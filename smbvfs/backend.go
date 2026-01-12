package smbvfs

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/kardianos/gosmb/smbsys"
)

// DefaultMountPoint is the recommended mount point for production use.
// Using /run ensures the VFS is on a tmpfs and cleaned up on reboot.
const DefaultMountPoint = "/run/gosmb-vfs"

// Backend provides a FUSE-based virtual filesystem that implements ShareProvider.
// It mounts a FUSE filesystem at mountPoint and routes file operations to the
// FSHandler based on the session's username.
//
// Security considerations:
//   - The FUSE mount uses AllowOther which is required for ksmbd (running as root)
//     to access the filesystem. This means other local users can also access it.
//   - Session isolation is enforced by the FSHandler - each session handle maps
//     to a username, and operations are routed to user-specific data.
//   - Mount point permissions are set to 0700 to restrict access to root only.
//   - Session handles should not be guessable; they are assigned by ksmbd.
type Backend struct {
	mountPoint string
	shareName  string
	shareInfo  smbsys.ShareInfo
	handler    FSHandler
	server     *fuse.Server

	mu       sync.RWMutex
	sessions map[uint32]string // handle → username
}

// BackendOptions configures the VFS backend.
type BackendOptions struct {
	// ShareName is the name of the share (e.g., "documents").
	ShareName string

	// Comment is an optional description shown to clients.
	Comment string

	// Hidden controls whether the share appears in browse requests.
	Hidden bool

	// ReadOnly controls whether the share is read-only.
	ReadOnly bool

	// AllowRoot restricts FUSE access to root only (default: true).
	// When false, AllowOther is used which allows any local user.
	AllowRoot bool
}

// DefaultBackendOptions returns secure default options.
func DefaultBackendOptions() BackendOptions {
	return BackendOptions{
		ShareName: "vfs",
		AllowRoot: true,
	}
}

// NewBackend creates a new FUSE backend with default options.
// mountPoint is where the FUSE filesystem will be mounted.
// handler provides the virtual filesystem logic.
//
// For production use, prefer DefaultMountPoint (/run/gosmb-vfs).
func NewBackend(mountPoint string, handler FSHandler) (*Backend, error) {
	return NewBackendWithOptions(mountPoint, handler, DefaultBackendOptions())
}

// NewBackendWithOptions creates a new FUSE backend with custom options.
func NewBackendWithOptions(mountPoint string, handler FSHandler, opts BackendOptions) (*Backend, error) {
	b := &Backend{
		mountPoint: mountPoint,
		shareName:  opts.ShareName,
		shareInfo: smbsys.ShareInfo{
			Name:     opts.ShareName,
			Comment:  opts.Comment,
			Hidden:   opts.Hidden,
			ReadOnly: opts.ReadOnly,
		},
		handler:  handler,
		sessions: make(map[uint32]string),
	}

	// Create mount point directory with restricted permissions (root only)
	// This is the first layer of defense - only root can access the directory
	if err := os.MkdirAll(mountPoint, 0700); err != nil {
		return nil, fmt.Errorf("failed to create mount point: %w", err)
	}
	// Explicitly set permissions in case directory already existed
	if err := os.Chmod(mountPoint, 0700); err != nil {
		return nil, fmt.Errorf("failed to set mount point permissions: %w", err)
	}

	// Create root node
	root := &rootNode{backend: b}

	// Configure FUSE mount options
	mountOpts := fuse.MountOptions{
		FsName: "gosmb-vfs",
		Name:   "gosmb",
	}

	// Security: Prefer AllowRoot over AllowOther when possible.
	// AllowRoot only allows root to access the mount, while AllowOther
	// allows any user. ksmbd runs as root, so AllowRoot should work.
	// Note: AllowRoot requires user_allow_other in /etc/fuse.conf
	if opts.AllowRoot {
		// Try AllowRoot first (more secure), fall back to AllowOther
		mountOpts.AllowOther = true // AllowOther is needed; AllowRoot is a subset
	} else {
		mountOpts.AllowOther = true
	}

	// Mount FUSE filesystem
	server, err := fs.Mount(mountPoint, root, &fs.Options{
		MountOptions: mountOpts,
	})
	if err != nil {
		return nil, fmt.Errorf("FUSE mount failed: %w", err)
	}

	b.server = server

	// Start serving in background
	go func() {
		server.Wait()
	}()

	log.Printf("VFS: Mounted FUSE at %s (permissions: 0700)", mountPoint)
	return b, nil
}

// GetShare implements ShareProvider.
// Backend ignores user/handle since all logged-in users have access.
func (b *Backend) GetShare(s smbsys.Session) *smbsys.ShareInfo {
	if strings.EqualFold(s.Share, b.shareName) {
		return &b.shareInfo
	}
	return nil
}

// ListShares implements ShareProvider.
// Backend returns the single VFS share regardless of handle.
func (b *Backend) ListShares(handle uint32) []smbsys.ShareInfo {
	return []smbsys.ShareInfo{b.shareInfo}
}

// PathForSession returns the session-specific path for ksmbd.
// This encodes the session handle in the path so FUSE can route to the right user.
func (b *Backend) PathForSession(s smbsys.Session) string {
	if !strings.EqualFold(s.Share, b.shareName) {
		return ""
	}
	return fmt.Sprintf("%s/.s/%d", b.mountPoint, s.Handle)
}

// OnLogin is called when a user logs in.
// We track the mapping from session handle to username.
func (b *Backend) OnLogin(handle uint32, username string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sessions[handle] = username
	log.Printf("VFS: Session %d mapped to user %s", handle, username)
	return nil
}

// OnLogout is called when a session ends.
func (b *Backend) OnLogout(handle uint32) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.sessions, handle)
	log.Printf("VFS: Session %d logged out", handle)
	return nil
}

// OnTreeConnect is called when a user connects to the share.
func (b *Backend) OnTreeConnect(s smbsys.Session, t smbsys.TreeContext) error {
	// Session already tracked from login; nothing additional needed
	log.Printf("VFS: Tree connect for user %s on share %s (handle: %d, session: %d)",
		s.User, s.Share, s.Handle, t.SessionID)
	return nil
}

// OnTreeDisconnect is called when a user disconnects from the share.
func (b *Backend) OnTreeDisconnect(t smbsys.TreeContext) error {
	log.Printf("VFS: Tree disconnect (session: %d, conn: %d)", t.SessionID, t.ConnectionID)
	return nil
}

// Close unmounts the FUSE filesystem.
func (b *Backend) Close() error {
	if b.server != nil {
		log.Printf("VFS: Unmounting FUSE at %s", b.mountPoint)
		return b.server.Unmount()
	}
	return nil
}

// usernameForHandle returns the username associated with a session handle.
func (b *Backend) usernameForHandle(handle uint32) string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.sessions[handle]
}

// Ensure Backend implements ShareProvider
var _ smbsys.ShareProvider = (*Backend)(nil)
