package smbvfs

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MemoryFSHandler is an in-memory filesystem handler.
// It stores files per-user, so each user has their own isolated view.
type MemoryFSHandler struct {
	mu    sync.RWMutex
	users map[string]*userFS // username → user's filesystem
}

type userFS struct {
	files map[string]*memFile
}

type memFile struct {
	data  []byte
	mode  uint32
	isDir bool
	mtime int64
	atime int64
	ctime int64
}

// NewMemoryFSHandler creates a new in-memory filesystem handler.
func NewMemoryFSHandler() *MemoryFSHandler {
	return &MemoryFSHandler{
		users: make(map[string]*userFS),
	}
}

// InitUser initializes a user's filesystem with some default files.
func (h *MemoryFSHandler) InitUser(user string, files map[string][]byte) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getOrCreateUserFS(user)
	now := time.Now().Unix()

	// Ensure root directory exists
	ufs.files[""] = &memFile{
		isDir: true,
		mode:  ModeDirectory | 0755,
		mtime: now,
		atime: now,
		ctime: now,
	}

	for path, content := range files {
		// Ensure parent directories exist
		dir := filepath.Dir(path)
		if dir != "" && dir != "." {
			h.ensureDir(ufs, dir, now)
		}

		ufs.files[path] = &memFile{
			data:  content,
			mode:  ModeRegular | 0644,
			isDir: false,
			mtime: now,
			atime: now,
			ctime: now,
		}
	}
}

func (h *MemoryFSHandler) ensureDir(ufs *userFS, path string, now int64) {
	parts := strings.Split(path, string(filepath.Separator))
	current := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		if current == "" {
			current = part
		} else {
			current = filepath.Join(current, part)
		}
		if _, ok := ufs.files[current]; !ok {
			ufs.files[current] = &memFile{
				isDir: true,
				mode:  ModeDirectory | 0755,
				mtime: now,
				atime: now,
				ctime: now,
			}
		}
	}
}

func (h *MemoryFSHandler) getOrCreateUserFS(user string) *userFS {
	ufs, ok := h.users[user]
	if !ok {
		ufs = &userFS{
			files: make(map[string]*memFile),
		}
		h.users[user] = ufs
	}
	return ufs
}

func (h *MemoryFSHandler) getUserFS(user string) *userFS {
	return h.users[user]
}

func (h *MemoryFSHandler) Getattr(ctx context.Context, s Session, path string) (*Attr, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ufs := h.getUserFS(s.User)
	if ufs == nil {
		return nil, ErrNotFound
	}

	// Normalize path
	path = normalizePath(path)

	file, ok := ufs.files[path]
	if !ok {
		return nil, ErrNotFound
	}

	return &Attr{
		Size:  uint64(len(file.data)),
		Mode:  file.mode,
		Mtime: file.mtime,
		Atime: file.atime,
		Ctime: file.ctime,
		Nlink: 1,
	}, nil
}

func (h *MemoryFSHandler) Lookup(ctx context.Context, s Session, path string) (*Attr, error) {
	return h.Getattr(ctx, s, path)
}

func (h *MemoryFSHandler) ReadDir(ctx context.Context, s Session, path string) ([]DirEntry, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ufs := h.getUserFS(s.User)
	if ufs == nil {
		return nil, ErrNotFound
	}

	path = normalizePath(path)

	// Check if directory exists
	if path != "" {
		file, ok := ufs.files[path]
		if !ok || !file.isDir {
			return nil, ErrNotFound
		}
	}

	// Find all direct children
	var entries []DirEntry
	prefix := path
	if prefix != "" {
		prefix += string(filepath.Separator)
	}

	seen := make(map[string]bool)
	for p, f := range ufs.files {
		if p == path {
			continue
		}
		if !strings.HasPrefix(p, prefix) && path != "" {
			continue
		}

		// Get relative path
		rel := p
		if path != "" {
			rel = strings.TrimPrefix(p, prefix)
		}

		// Get first component (direct child)
		parts := strings.SplitN(rel, string(filepath.Separator), 2)
		child := parts[0]
		if child == "" {
			continue
		}

		// Only add direct children once
		if seen[child] {
			continue
		}
		seen[child] = true

		mode := f.mode
		// If this is not the exact path, it's a parent directory
		if len(parts) > 1 {
			mode = ModeDirectory | 0755
		}

		entries = append(entries, DirEntry{
			Name: child,
			Mode: mode,
		})
	}

	return entries, nil
}

func (h *MemoryFSHandler) Read(ctx context.Context, s Session, path string, dest []byte, offset int64) (int, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	ufs := h.getUserFS(s.User)
	if ufs == nil {
		return 0, ErrNotFound
	}

	path = normalizePath(path)
	file, ok := ufs.files[path]
	if !ok {
		return 0, ErrNotFound
	}
	if file.isDir {
		return 0, ErrIsDir
	}

	if offset >= int64(len(file.data)) {
		return 0, nil
	}

	n := copy(dest, file.data[offset:])
	return n, nil
}

func (h *MemoryFSHandler) Write(ctx context.Context, s Session, path string, data []byte, offset int64) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getOrCreateUserFS(s.User)
	path = normalizePath(path)

	file, ok := ufs.files[path]
	if !ok {
		return 0, ErrNotFound
	}
	if file.isDir {
		return 0, ErrIsDir
	}

	// Extend file if necessary
	end := int(offset) + len(data)
	if end > len(file.data) {
		newData := make([]byte, end)
		copy(newData, file.data)
		file.data = newData
	}

	n := copy(file.data[offset:], data)
	file.mtime = time.Now().Unix()
	return n, nil
}

func (h *MemoryFSHandler) Create(ctx context.Context, s Session, path string, mode uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getOrCreateUserFS(s.User)
	path = normalizePath(path)

	// Check parent directory exists
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		parent, ok := ufs.files[dir]
		if !ok || !parent.isDir {
			return ErrNotFound
		}
	}

	now := time.Now().Unix()
	ufs.files[path] = &memFile{
		data:  []byte{},
		mode:  ModeRegular | (mode & 0777),
		isDir: false,
		mtime: now,
		atime: now,
		ctime: now,
	}
	return nil
}

func (h *MemoryFSHandler) Mkdir(ctx context.Context, s Session, path string, mode uint32) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getOrCreateUserFS(s.User)
	path = normalizePath(path)

	// Check if already exists
	if _, ok := ufs.files[path]; ok {
		return ErrExists
	}

	// Check parent directory exists
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		parent, ok := ufs.files[dir]
		if !ok || !parent.isDir {
			return ErrNotFound
		}
	}

	now := time.Now().Unix()
	ufs.files[path] = &memFile{
		isDir: true,
		mode:  ModeDirectory | (mode & 0777),
		mtime: now,
		atime: now,
		ctime: now,
	}
	return nil
}

func (h *MemoryFSHandler) Remove(ctx context.Context, s Session, path string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getUserFS(s.User)
	if ufs == nil {
		return ErrNotFound
	}

	path = normalizePath(path)
	file, ok := ufs.files[path]
	if !ok {
		return ErrNotFound
	}

	// If directory, check if empty
	if file.isDir {
		prefix := path + string(filepath.Separator)
		for p := range ufs.files {
			if strings.HasPrefix(p, prefix) {
				return ErrNotEmpty
			}
		}
	}

	delete(ufs.files, path)
	return nil
}

func (h *MemoryFSHandler) Rename(ctx context.Context, s Session, oldPath, newPath string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getUserFS(s.User)
	if ufs == nil {
		return ErrNotFound
	}

	oldPath = normalizePath(oldPath)
	newPath = normalizePath(newPath)

	file, ok := ufs.files[oldPath]
	if !ok {
		return ErrNotFound
	}

	// Check new parent exists
	newDir := filepath.Dir(newPath)
	if newDir != "" && newDir != "." {
		parent, ok := ufs.files[newDir]
		if !ok || !parent.isDir {
			return ErrNotFound
		}
	}

	// If it's a directory, move all children too
	if file.isDir {
		oldPrefix := oldPath + string(filepath.Separator)
		toMove := make(map[string]*memFile)
		for p, f := range ufs.files {
			if strings.HasPrefix(p, oldPrefix) {
				newP := newPath + strings.TrimPrefix(p, oldPath)
				toMove[newP] = f
				delete(ufs.files, p)
			}
		}
		for p, f := range toMove {
			ufs.files[p] = f
		}
	}

	delete(ufs.files, oldPath)
	ufs.files[newPath] = file
	return nil
}

func (h *MemoryFSHandler) Truncate(ctx context.Context, s Session, path string, size uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getUserFS(s.User)
	if ufs == nil {
		return ErrNotFound
	}

	path = normalizePath(path)
	file, ok := ufs.files[path]
	if !ok {
		return ErrNotFound
	}
	if file.isDir {
		return ErrIsDir
	}

	if size < uint64(len(file.data)) {
		file.data = file.data[:size]
	} else if size > uint64(len(file.data)) {
		newData := make([]byte, size)
		copy(newData, file.data)
		file.data = newData
	}
	file.mtime = time.Now().Unix()
	return nil
}

func (h *MemoryFSHandler) SetAttr(ctx context.Context, s Session, path string, attr *Attr) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	ufs := h.getUserFS(s.User)
	if ufs == nil {
		return ErrNotFound
	}

	path = normalizePath(path)
	file, ok := ufs.files[path]
	if !ok {
		return ErrNotFound
	}

	if attr.Mtime != 0 {
		file.mtime = attr.Mtime
	}
	if attr.Atime != 0 {
		file.atime = attr.Atime
	}
	if attr.Mode != 0 {
		// Preserve file type, update permissions
		file.mode = (file.mode & ModeTypeMask) | (attr.Mode & 0777)
	}
	return nil
}

// normalizePath cleans up and normalizes a path
func normalizePath(path string) string {
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, ".")
	path = strings.TrimPrefix(path, "/")
	return path
}

// Ensure MemoryFSHandler implements FSHandler
var _ FSHandler = (*MemoryFSHandler)(nil)
