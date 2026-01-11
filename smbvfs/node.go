package smbvfs

import (
	"context"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

// rootNode is the FUSE root node.
// It provides access to the .s directory which contains session-specific directories.
type rootNode struct {
	fs.Inode
	backend *Backend
}

var _ = (fs.NodeLookuper)((*rootNode)(nil))
var _ = (fs.NodeReaddirer)((*rootNode)(nil))

func (n *rootNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if name == ".s" {
		child := &sessionDirNode{backend: n.backend}
		// Use restrictive permissions (root only)
		out.Mode = syscall.S_IFDIR | 0700
		return n.NewInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR}), 0
	}
	return nil, syscall.ENOENT
}

func (n *rootNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries := []fuse.DirEntry{
		{Name: ".s", Mode: syscall.S_IFDIR},
	}
	return fs.NewListDirStream(entries), 0
}

// sessionDirNode lists session handles (/.s/)
type sessionDirNode struct {
	fs.Inode
	backend *Backend
}

var _ = (fs.NodeLookuper)((*sessionDirNode)(nil))
var _ = (fs.NodeReaddirer)((*sessionDirNode)(nil))

func (n *sessionDirNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	handle, err := strconv.ParseUint(name, 10, 32)
	if err != nil {
		return nil, syscall.ENOENT
	}

	user := n.backend.usernameForHandle(uint32(handle))
	if user == "" {
		// Security: Reject unknown session handles.
		// Previously we allowed "_unknown" as a fallback, but this could
		// allow unauthorized access if someone guesses a handle.
		// ksmbd should always send LOGIN_REQUEST before SHARE_CONFIG_REQUEST,
		// so the session should be registered by the time we need it.
		return nil, syscall.ENOENT
	}

	child := &userRootNode{
		backend: n.backend,
		handle:  uint32(handle),
		user:    user,
		share:   n.backend.shareName,
		path:    "",
	}
	// Use restrictive permissions (root only) for session directories
	out.Mode = syscall.S_IFDIR | 0700
	return n.NewInode(ctx, child, fs.StableAttr{Mode: syscall.S_IFDIR}), 0
}

func (n *sessionDirNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	// Security: Don't enumerate session handles.
	// Revealing active session handles could aid in session hijacking attempts.
	// The .s directory appears empty when listed, but direct access to
	// known session paths still works.
	return fs.NewListDirStream([]fuse.DirEntry{}), 0
}

// userRootNode is a node within a user's session directory.
// It routes operations to the FSHandler with the user context.
type userRootNode struct {
	fs.Inode
	backend *Backend
	handle  uint32
	user    string
	share   string // share name
	path    string // relative path from user root
}

// session creates a Session for handler calls.
func (n *userRootNode) session() Session {
	return Session{
		User:   n.user,
		Share:  n.share,
		Handle: n.handle,
	}
}

// toErrno converts FSHandler errors to syscall.Errno.
func toErrno(err error) syscall.Errno {
	if err == nil {
		return 0
	}
	switch err {
	case ErrReadOnly:
		return syscall.EROFS
	case ErrNotFound:
		return syscall.ENOENT
	case ErrExists:
		return syscall.EEXIST
	case ErrNotEmpty:
		return syscall.ENOTEMPTY
	case ErrIsDir:
		return syscall.EISDIR
	case ErrNotDir:
		return syscall.ENOTDIR
	case ErrPermission:
		return syscall.EACCES
	case ErrInvalidArg:
		return syscall.EINVAL
	default:
		return syscall.EIO
	}
}

var _ = (fs.NodeLookuper)((*userRootNode)(nil))
var _ = (fs.NodeReaddirer)((*userRootNode)(nil))
var _ = (fs.NodeGetattrer)((*userRootNode)(nil))
var _ = (fs.NodeOpener)((*userRootNode)(nil))
var _ = (fs.NodeCreater)((*userRootNode)(nil))
var _ = (fs.NodeMkdirer)((*userRootNode)(nil))
var _ = (fs.NodeUnlinker)((*userRootNode)(nil))
var _ = (fs.NodeRmdirer)((*userRootNode)(nil))
var _ = (fs.NodeRenamer)((*userRootNode)(nil))
var _ = (fs.NodeSetattrer)((*userRootNode)(nil))

func (n *userRootNode) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	attr, err := n.backend.handler.Getattr(ctx, n.session(), n.path)
	if err != nil {
		return toErrno(err)
	}
	fillAttrOut(attr, &out.Attr)
	return 0
}

func (n *userRootNode) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	childPath := filepath.Join(n.path, name)

	attr, err := n.backend.handler.Lookup(ctx, n.session(), childPath)
	if err != nil {
		return nil, toErrno(err)
	}

	child := &userRootNode{
		backend: n.backend,
		handle:  n.handle,
		user:    n.user,
		share:   n.share,
		path:    childPath,
	}

	fillEntryOut(attr, out)
	return n.NewInode(ctx, child, fs.StableAttr{Mode: attr.Mode}), 0
}

func (n *userRootNode) Readdir(ctx context.Context) (fs.DirStream, syscall.Errno) {
	entries, err := n.backend.handler.ReadDir(ctx, n.session(), n.path)
	if err != nil {
		return nil, toErrno(err)
	}

	var result []fuse.DirEntry
	for _, e := range entries {
		result = append(result, fuse.DirEntry{
			Name: e.Name,
			Mode: e.Mode,
		})
	}
	return fs.NewListDirStream(result), 0
}

func (n *userRootNode) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	// Return a file handle that will be used for Read/Write
	fh := &fileHandle{
		node: n,
	}
	return fh, 0, 0
}

func (n *userRootNode) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (node *fs.Inode, fh fs.FileHandle, fuseFlags uint32, errno syscall.Errno) {
	childPath := filepath.Join(n.path, name)

	if err := n.backend.handler.Create(ctx, n.session(), childPath, mode); err != nil {
		return nil, nil, 0, toErrno(err)
	}

	// Get attributes of newly created file
	attr, err := n.backend.handler.Lookup(ctx, n.session(), childPath)
	if err != nil {
		return nil, nil, 0, toErrno(err)
	}

	child := &userRootNode{
		backend: n.backend,
		handle:  n.handle,
		user:    n.user,
		share:   n.share,
		path:    childPath,
	}

	fillEntryOut(attr, out)
	inode := n.NewInode(ctx, child, fs.StableAttr{Mode: attr.Mode})
	return inode, &fileHandle{node: child}, 0, 0
}

func (n *userRootNode) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	childPath := filepath.Join(n.path, name)

	if err := n.backend.handler.Mkdir(ctx, n.session(), childPath, mode); err != nil {
		return nil, toErrno(err)
	}

	// Get attributes of newly created directory
	attr, err := n.backend.handler.Lookup(ctx, n.session(), childPath)
	if err != nil {
		return nil, toErrno(err)
	}

	child := &userRootNode{
		backend: n.backend,
		handle:  n.handle,
		user:    n.user,
		share:   n.share,
		path:    childPath,
	}

	fillEntryOut(attr, out)
	return n.NewInode(ctx, child, fs.StableAttr{Mode: attr.Mode}), 0
}

func (n *userRootNode) Unlink(ctx context.Context, name string) syscall.Errno {
	childPath := filepath.Join(n.path, name)
	if err := n.backend.handler.Remove(ctx, n.session(), childPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (n *userRootNode) Rmdir(ctx context.Context, name string) syscall.Errno {
	childPath := filepath.Join(n.path, name)
	if err := n.backend.handler.Remove(ctx, n.session(), childPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (n *userRootNode) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	oldPath := filepath.Join(n.path, name)

	// Get the new parent's path
	newParentPath := ""
	if np, ok := newParent.(*userRootNode); ok {
		newParentPath = np.path
	}
	newPath := filepath.Join(newParentPath, newName)

	if err := n.backend.handler.Rename(ctx, n.session(), oldPath, newPath); err != nil {
		return toErrno(err)
	}
	return 0
}

func (n *userRootNode) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	attr := &Attr{}

	if sz, ok := in.GetSize(); ok {
		if err := n.backend.handler.Truncate(ctx, n.session(), n.path, sz); err != nil {
			return toErrno(err)
		}
		attr.Size = sz
	}

	if mode, ok := in.GetMode(); ok {
		attr.Mode = mode
	}

	if mtime, ok := in.GetMTime(); ok {
		attr.Mtime = mtime.Unix()
	}

	if atime, ok := in.GetATime(); ok {
		attr.Atime = atime.Unix()
	}

	// Set other attributes if provided
	if err := n.backend.handler.SetAttr(ctx, n.session(), n.path, attr); err != nil {
		if err == ErrReadOnly {
			return syscall.EROFS
		}
		// Ignore errors for SetAttr - many handlers don't implement it
	}

	// Refresh attributes
	newAttr, err := n.backend.handler.Getattr(ctx, n.session(), n.path)
	if err == nil {
		fillAttrOut(newAttr, &out.Attr)
	}
	return 0
}

// fileHandle implements file operations
type fileHandle struct {
	node *userRootNode
}

var _ = (fs.FileReader)((*fileHandle)(nil))
var _ = (fs.FileWriter)((*fileHandle)(nil))

func (f *fileHandle) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	nread, err := f.node.backend.handler.Read(ctx, f.node.session(), f.node.path, dest, off)
	if err != nil {
		return nil, toErrno(err)
	}
	return fuse.ReadResultData(dest[:nread]), 0
}

func (f *fileHandle) Write(ctx context.Context, data []byte, off int64) (uint32, syscall.Errno) {
	nwritten, err := f.node.backend.handler.Write(ctx, f.node.session(), f.node.path, data, off)
	if err != nil {
		return 0, toErrno(err)
	}
	return uint32(nwritten), 0
}

// Helper functions

func fillAttrOut(attr *Attr, out *fuse.Attr) {
	out.Size = attr.Size
	out.Mode = attr.Mode
	out.Mtime = uint64(attr.Mtime)
	out.Atime = uint64(attr.Atime)
	out.Ctime = uint64(attr.Ctime)
	out.Uid = attr.Uid
	out.Gid = attr.Gid
	out.Nlink = attr.Nlink
	if out.Nlink == 0 {
		out.Nlink = 1
	}
}

func fillEntryOut(attr *Attr, out *fuse.EntryOut) {
	fillAttrOut(attr, &out.Attr)
}
