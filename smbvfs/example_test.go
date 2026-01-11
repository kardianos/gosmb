package smbvfs_test

import (
	"context"
	"fmt"

	"github.com/kardianos/gosmb/smbvfs"
)

// Example_memoryHandler demonstrates using the built-in MemoryFSHandler.
func Example_memoryHandler() {
	// Create an in-memory filesystem handler
	handler := smbvfs.NewMemoryFSHandler()

	// Initialize files for different users
	// Each user has their own isolated filesystem view
	handler.InitUser("alice", map[string][]byte{
		"hello.txt":       []byte("Hello, Alice!\n"),
		"docs/readme.txt": []byte("Alice's documents\n"),
		"docs/notes.txt":  []byte("Alice's notes\n"),
	})
	handler.InitUser("bob", map[string][]byte{
		"hello.txt":       []byte("Hello, Bob!\n"),
		"work/report.txt": []byte("Bob's report\n"),
	})

	// Users see only their own files
	sess := smbvfs.Session{User: "alice", Share: "vfs", Handle: 1}
	entries, _ := handler.ReadDir(context.Background(), sess, "")
	fmt.Printf("Alice's root directory has %d entries\n", len(entries))

	// Output:
	// Alice's root directory has 2 entries
}

// Example_readOnlyHandler demonstrates creating a read-only handler.
func Example_readOnlyHandler() {
	// Embed ReadOnlyHandler to get default implementations for write operations
	type MyReadOnlyHandler struct {
		smbvfs.ReadOnlyHandler
		files map[string][]byte
	}

	handler := &MyReadOnlyHandler{
		files: map[string][]byte{
			"readme.txt": []byte("Read-only content"),
		},
	}

	// Write operations return ErrReadOnly automatically
	sess := smbvfs.Session{User: "test"}
	_, err := handler.Write(context.Background(), sess, "readme.txt", []byte("new"), 0)
	fmt.Printf("Write error: %v\n", err)

	// Output:
	// Write error: read-only filesystem
}

// StaticHandler implements a simple read-only filesystem.
type StaticHandler struct {
	smbvfs.ReadOnlyHandler
	files map[string]*smbvfs.Attr
	data  map[string][]byte
}

// Getattr implements smbvfs.FSHandler.
func (h *StaticHandler) Getattr(ctx context.Context, s smbvfs.Session, path string) (*smbvfs.Attr, error) {
	if attr, ok := h.files[path]; ok {
		return attr, nil
	}
	return nil, smbvfs.ErrNotFound
}

// Lookup implements smbvfs.FSHandler.
func (h *StaticHandler) Lookup(ctx context.Context, s smbvfs.Session, path string) (*smbvfs.Attr, error) {
	return h.Getattr(ctx, s, path)
}

// ReadDir implements smbvfs.FSHandler.
func (h *StaticHandler) ReadDir(ctx context.Context, s smbvfs.Session, path string) ([]smbvfs.DirEntry, error) {
	if path != "" {
		return nil, smbvfs.ErrNotFound
	}
	var entries []smbvfs.DirEntry
	for name, attr := range h.files {
		entries = append(entries, smbvfs.DirEntry{
			Name: name,
			Mode: attr.Mode,
		})
	}
	return entries, nil
}

// Read implements smbvfs.FSHandler.
func (h *StaticHandler) Read(ctx context.Context, s smbvfs.Session, path string, dest []byte, offset int64) (int, error) {
	data, ok := h.data[path]
	if !ok {
		return 0, smbvfs.ErrNotFound
	}
	if offset >= int64(len(data)) {
		return 0, nil
	}
	n := copy(dest, data[offset:])
	return n, nil
}

// Verify interface implementation
var _ smbvfs.FSHandler = (*StaticHandler)(nil)

// Example_customHandler demonstrates implementing a custom FSHandler.
func Example_customHandler() {
	handler := &StaticHandler{
		files: map[string]*smbvfs.Attr{
			"config.json": {
				Size: 42,
				Mode: smbvfs.ModeRegular | 0644,
			},
		},
		data: map[string][]byte{
			"config.json": []byte(`{"setting": "value"}`),
		},
	}

	sess := smbvfs.Session{User: "admin", Share: "config", Handle: 1}
	attr, err := handler.Getattr(context.Background(), sess, "config.json")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("File mode: %o\n", attr.Mode&0777)

	// Output:
	// File mode: 644
}

// ExampleSession demonstrates the Session type.
func ExampleSession() {
	// Session identifies the user, share, and connection
	sess := smbvfs.Session{
		User:   "alice",        // Authenticated username
		Share:  "documents",    // Share being accessed
		Handle: 42,             // ksmbd session handle
	}

	fmt.Printf("User: %s, Share: %s\n", sess.User, sess.Share)

	// Output:
	// User: alice, Share: documents
}

// ExampleAttr demonstrates file attributes.
func ExampleAttr() {
	// Attr represents file metadata
	attr := smbvfs.Attr{
		Size:  1024,
		Mode:  smbvfs.ModeRegular | 0644, // Regular file, rw-r--r--
		Mtime: 1704067200,                // Unix timestamp
		Nlink: 1,
	}

	fmt.Printf("Is directory: %v\n", attr.IsDir())
	fmt.Printf("Is regular file: %v\n", attr.IsRegular())

	// Output:
	// Is directory: false
	// Is regular file: true
}

// ExampleDirEntry demonstrates directory entries.
func ExampleDirEntry() {
	entries := []smbvfs.DirEntry{
		{Name: "file.txt", Mode: smbvfs.ModeRegular | 0644},
		{Name: "subdir", Mode: smbvfs.ModeDirectory | 0755},
	}

	for _, e := range entries {
		if e.IsDir() {
			fmt.Printf("[DIR]  %s\n", e.Name)
		} else {
			fmt.Printf("[FILE] %s\n", e.Name)
		}
	}

	// Output:
	// [FILE] file.txt
	// [DIR]  subdir
}
