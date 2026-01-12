package smbvfs

import (
	"context"
	"errors"

	"github.com/kardianos/gosmb/smbsys"
)

// Common errors that FSHandler implementations should return.
// These are translated to appropriate FUSE/SMB error codes.
var (
	// ErrReadOnly indicates a write operation on a read-only filesystem.
	ErrReadOnly = errors.New("read-only filesystem")

	// ErrNotFound indicates the requested file or directory doesn't exist.
	ErrNotFound = errors.New("file not found")

	// ErrExists indicates the file or directory already exists.
	ErrExists = errors.New("file exists")

	// ErrNotEmpty indicates the directory is not empty.
	ErrNotEmpty = errors.New("directory not empty")

	// ErrIsDir indicates an operation expected a file but got a directory.
	ErrIsDir = errors.New("is a directory")

	// ErrNotDir indicates an operation expected a directory but got a file.
	ErrNotDir = errors.New("not a directory")

	// ErrPermission indicates a permission error.
	ErrPermission = errors.New("permission denied")

	// ErrInvalidArg indicates an invalid argument.
	ErrInvalidArg = errors.New("invalid argument")
)

// File type constants for Attr.Mode and DirEntry.Mode.
// These match POSIX file type bits and can be ORed with permission bits.
const (
	ModeRegular   = 0100000 // S_IFREG - regular file
	ModeDirectory = 0040000 // S_IFDIR - directory
	ModeSymlink   = 0120000 // S_IFLNK - symbolic link
	ModeSocket    = 0140000 // S_IFSOCK - socket
	ModeFIFO      = 0010000 // S_IFIFO - FIFO/pipe
	ModeBlock     = 0060000 // S_IFBLK - block device
	ModeChar      = 0020000 // S_IFCHR - character device

	// ModeTypeMask extracts the file type from mode.
	ModeTypeMask = 0170000 // S_IFMT
)

// Session is an alias for smbsys.Session for convenience.
// It identifies the user and share for a filesystem operation.
type Session = smbsys.Session

// FSHandler is implemented by users to provide virtual filesystem logic.
// All paths are relative to the share root (e.g., "subdir/file.txt").
// The session parameter identifies the user and share being accessed.
type FSHandler interface {
	// Getattr returns file attributes for the given path.
	Getattr(ctx context.Context, s Session, path string) (*Attr, error)

	// Lookup checks if a path exists and returns its attributes.
	// This is called when traversing directories.
	Lookup(ctx context.Context, s Session, path string) (*Attr, error)

	// ReadDir returns directory entries for the given path.
	// Use path "" for the root directory.
	ReadDir(ctx context.Context, s Session, path string) ([]DirEntry, error)

	// Read reads file content into dest starting at offset bytes from
	// the beginning of the file. Returns the number of bytes read.
	Read(ctx context.Context, s Session, path string, dest []byte, offset int64) (int, error)

	// Write writes data to the file at offset bytes from the beginning
	// of the file. Returns the number of bytes written.
	// Return ErrReadOnly if the filesystem is read-only.
	Write(ctx context.Context, s Session, path string, data []byte, offset int64) (int, error)

	// Create creates a new file with the given mode.
	// Return ErrReadOnly if the filesystem is read-only.
	Create(ctx context.Context, s Session, path string, mode uint32) error

	// Mkdir creates a directory with the given mode.
	// Return ErrReadOnly if the filesystem is read-only.
	Mkdir(ctx context.Context, s Session, path string, mode uint32) error

	// Remove deletes a file or empty directory.
	// Return ErrReadOnly if the filesystem is read-only.
	// Return ErrNotEmpty if the directory is not empty.
	Remove(ctx context.Context, s Session, path string) error

	// Rename renames/moves a file or directory.
	// Return ErrReadOnly if the filesystem is read-only.
	Rename(ctx context.Context, s Session, oldPath, newPath string) error

	// Truncate sets the file size in bytes.
	// Return ErrReadOnly if the filesystem is read-only.
	Truncate(ctx context.Context, s Session, path string, size uint64) error

	// SetAttr sets file attributes (times, mode, etc).
	// Return ErrReadOnly if the filesystem is read-only.
	SetAttr(ctx context.Context, s Session, path string, attr *Attr) error
}

// Attr represents file attributes.
type Attr struct {
	Size  uint64 // File size in bytes
	Mode  uint32 // File type (ModeRegular, ModeDirectory, etc.) ORed with permissions (0644)
	Mtime int64  // Modification time (Unix timestamp, seconds)
	Atime int64  // Access time (Unix timestamp, seconds)
	Ctime int64  // Change time (Unix timestamp, seconds)
	Uid   uint32 // Owner user ID
	Gid   uint32 // Owner group ID
	Nlink uint32 // Number of hard links
}

// IsDir returns true if the attributes indicate a directory.
func (a *Attr) IsDir() bool {
	return a.Mode&ModeTypeMask == ModeDirectory
}

// IsRegular returns true if the attributes indicate a regular file.
func (a *Attr) IsRegular() bool {
	return a.Mode&ModeTypeMask == ModeRegular
}

// DirEntry represents a directory entry.
type DirEntry struct {
	Name string // Entry name (not full path)
	Mode uint32 // File type (ModeDirectory, ModeRegular, etc.)
}

// IsDir returns true if the entry is a directory.
func (e DirEntry) IsDir() bool {
	return e.Mode&ModeTypeMask == ModeDirectory
}

// IsRegular returns true if the entry is a regular file.
func (e DirEntry) IsRegular() bool {
	return e.Mode&ModeTypeMask == ModeRegular
}

// ReadOnlyHandler can be embedded in handlers to provide default
// read-only implementations for write operations.
type ReadOnlyHandler struct{}

func (ReadOnlyHandler) Write(ctx context.Context, s Session, path string, data []byte, offset int64) (int, error) {
	return 0, ErrReadOnly
}

func (ReadOnlyHandler) Create(ctx context.Context, s Session, path string, mode uint32) error {
	return ErrReadOnly
}

func (ReadOnlyHandler) Mkdir(ctx context.Context, s Session, path string, mode uint32) error {
	return ErrReadOnly
}

func (ReadOnlyHandler) Remove(ctx context.Context, s Session, path string) error {
	return ErrReadOnly
}

func (ReadOnlyHandler) Rename(ctx context.Context, s Session, oldPath, newPath string) error {
	return ErrReadOnly
}

func (ReadOnlyHandler) Truncate(ctx context.Context, s Session, path string, size uint64) error {
	return ErrReadOnly
}

func (ReadOnlyHandler) SetAttr(ctx context.Context, s Session, path string, attr *Attr) error {
	return ErrReadOnly
}
