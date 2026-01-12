package smbvfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kardianos/gosmb/smbsys"
)

func TestVFSBackend(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("VFS test requires root for FUSE mount with AllowOther")
	}

	// Create a temporary mount point
	mountPoint, err := os.MkdirTemp("", "gosmb-vfs-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	// Create handler with test files for two users
	handler := NewMemoryFSHandler()
	handler.InitUser("alice", map[string][]byte{
		"hello.txt":           []byte("Hello from Alice!\n"),
		"secret.txt":          []byte("Alice's secret data\n"),
		"docs/readme.md":      []byte("# Alice's Docs\n"),
		"docs/notes/todo.txt": []byte("Alice's TODO list\n"),
	})
	handler.InitUser("bob", map[string][]byte{
		"hello.txt":      []byte("Hello from Bob!\n"),
		"work/report.md": []byte("# Bob's Report\n"),
	})

	// Create and mount the VFS backend
	backend, err := NewBackend(mountPoint, handler)
	if err != nil {
		t.Fatalf("Failed to create VFS backend: %v", err)
	}
	defer backend.Close()

	// Wait for FUSE to be ready
	time.Sleep(100 * time.Millisecond)

	// Simulate login for two users
	if err := backend.OnLogin(42, "alice"); err != nil {
		t.Fatalf("OnLogin failed for alice: %v", err)
	}
	if err := backend.OnLogin(43, "bob"); err != nil {
		t.Fatalf("OnLogin failed for bob: %v", err)
	}

	t.Run("PathForSession", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		bobPath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 43})

		if alicePath == bobPath {
			t.Error("Alice and Bob should have different paths")
		}
		if alicePath != filepath.Join(mountPoint, ".s", "42") {
			t.Errorf("Unexpected alice path: %s", alicePath)
		}
		if bobPath != filepath.Join(mountPoint, ".s", "43") {
			t.Errorf("Unexpected bob path: %s", bobPath)
		}
	})

	t.Run("ReadAliceFile", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		content, err := os.ReadFile(filepath.Join(alicePath, "hello.txt"))
		if err != nil {
			t.Fatalf("Failed to read alice's hello.txt: %v", err)
		}
		if string(content) != "Hello from Alice!\n" {
			t.Errorf("Unexpected content: %q", string(content))
		}
	})

	t.Run("ReadBobFile", func(t *testing.T) {
		bobPath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 43})
		content, err := os.ReadFile(filepath.Join(bobPath, "hello.txt"))
		if err != nil {
			t.Fatalf("Failed to read bob's hello.txt: %v", err)
		}
		if string(content) != "Hello from Bob!\n" {
			t.Errorf("Unexpected content: %q", string(content))
		}
	})

	t.Run("UserIsolation", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		bobPath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 43})

		// Alice should have secret.txt
		if _, err := os.Stat(filepath.Join(alicePath, "secret.txt")); err != nil {
			t.Error("Alice should have secret.txt")
		}

		// Bob should NOT have secret.txt
		if _, err := os.Stat(filepath.Join(bobPath, "secret.txt")); err == nil {
			t.Error("Bob should NOT have secret.txt")
		}

		// Bob should have work directory
		if _, err := os.Stat(filepath.Join(bobPath, "work")); err != nil {
			t.Error("Bob should have work directory")
		}

		// Alice should NOT have work directory
		if _, err := os.Stat(filepath.Join(alicePath, "work")); err == nil {
			t.Error("Alice should NOT have work directory")
		}
	})

	t.Run("ReadNestedFile", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		content, err := os.ReadFile(filepath.Join(alicePath, "docs", "readme.md"))
		if err != nil {
			t.Fatalf("Failed to read nested file: %v", err)
		}
		if string(content) != "# Alice's Docs\n" {
			t.Errorf("Unexpected content: %q", string(content))
		}
	})

	t.Run("ListDirectory", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		entries, err := os.ReadDir(alicePath)
		if err != nil {
			t.Fatalf("Failed to list directory: %v", err)
		}

		names := make(map[string]bool)
		for _, e := range entries {
			names[e.Name()] = true
		}

		expected := []string{"hello.txt", "secret.txt", "docs"}
		for _, name := range expected {
			if !names[name] {
				t.Errorf("Expected %q in directory listing", name)
			}
		}
	})

	t.Run("WriteFile", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		testFile := filepath.Join(alicePath, "hello.txt")

		// Write new content
		newContent := []byte("Updated content!\n")
		if err := os.WriteFile(testFile, newContent, 0644); err != nil {
			t.Fatalf("Failed to write file: %v", err)
		}

		// Read it back
		content, err := os.ReadFile(testFile)
		if err != nil {
			t.Fatalf("Failed to read updated file: %v", err)
		}
		if string(content) != string(newContent) {
			t.Errorf("Content mismatch: got %q, want %q", string(content), string(newContent))
		}
	})

	t.Run("CreateFile", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		testFile := filepath.Join(alicePath, "newfile.txt")

		content := []byte("Brand new file!\n")
		if err := os.WriteFile(testFile, content, 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		// Verify it exists
		readContent, err := os.ReadFile(testFile)
		if err != nil {
			t.Fatalf("Failed to read new file: %v", err)
		}
		if string(readContent) != string(content) {
			t.Errorf("Content mismatch: got %q, want %q", string(readContent), string(content))
		}
	})

	t.Run("CreateDirectory", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})
		testDir := filepath.Join(alicePath, "newdir")

		if err := os.Mkdir(testDir, 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}

		// Verify it exists and is a directory
		info, err := os.Stat(testDir)
		if err != nil {
			t.Fatalf("Failed to stat new directory: %v", err)
		}
		if !info.IsDir() {
			t.Error("Expected a directory")
		}
	})

	t.Run("RemoveFile", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})

		// Create a file to remove
		testFile := filepath.Join(alicePath, "todelete.txt")
		if err := os.WriteFile(testFile, []byte("delete me"), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		// Remove it
		if err := os.Remove(testFile); err != nil {
			t.Fatalf("Failed to remove file: %v", err)
		}

		// Verify it's gone
		if _, err := os.Stat(testFile); err == nil {
			t.Error("File should not exist after removal")
		}
	})

	t.Run("Rename", func(t *testing.T) {
		alicePath := backend.PathForSession(smbsys.Session{Share: "vfs", Handle: 42})

		// Create a file to rename
		oldPath := filepath.Join(alicePath, "oldname.txt")
		newPath := filepath.Join(alicePath, "newname.txt")
		content := []byte("rename me")

		if err := os.WriteFile(oldPath, content, 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}

		// Rename it
		if err := os.Rename(oldPath, newPath); err != nil {
			t.Fatalf("Failed to rename file: %v", err)
		}

		// Verify old path is gone
		if _, err := os.Stat(oldPath); err == nil {
			t.Error("Old path should not exist")
		}

		// Verify new path exists with correct content
		readContent, err := os.ReadFile(newPath)
		if err != nil {
			t.Fatalf("Failed to read renamed file: %v", err)
		}
		if string(readContent) != string(content) {
			t.Errorf("Content mismatch after rename")
		}
	})
}

func TestMemoryFSHandler(t *testing.T) {
	handler := NewMemoryFSHandler()

	// Initialize with test files
	handler.InitUser("testuser", map[string][]byte{
		"file1.txt":      []byte("content1"),
		"dir1/file2.txt": []byte("content2"),
	})

	// Helper to create a session for testuser
	sess := Session{User: "testuser", Share: "test", Handle: 1}

	t.Run("Getattr", func(t *testing.T) {
		attr, err := handler.Getattr(nil, sess, "file1.txt")
		if err != nil {
			t.Fatalf("Getattr failed: %v", err)
		}
		if attr.Size != 8 {
			t.Errorf("Expected size 8, got %d", attr.Size)
		}
	})

	t.Run("GettattrNotFound", func(t *testing.T) {
		_, err := handler.Getattr(nil, sess, "nonexistent.txt")
		if err == nil {
			t.Error("Expected error for nonexistent file")
		}
	})

	t.Run("ReadDir", func(t *testing.T) {
		entries, err := handler.ReadDir(nil, sess, "")
		if err != nil {
			t.Fatalf("ReadDir failed: %v", err)
		}

		names := make(map[string]bool)
		for _, e := range entries {
			names[e.Name] = true
		}

		if !names["file1.txt"] {
			t.Error("Expected file1.txt in listing")
		}
		if !names["dir1"] {
			t.Error("Expected dir1 in listing")
		}
	})

	t.Run("Read", func(t *testing.T) {
		buf := make([]byte, 100)
		n, err := handler.Read(nil, sess, "file1.txt", buf, 0)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if string(buf[:n]) != "content1" {
			t.Errorf("Expected 'content1', got %q", string(buf[:n]))
		}
	})

	t.Run("ReadWithOffset", func(t *testing.T) {
		buf := make([]byte, 100)
		n, err := handler.Read(nil, sess, "file1.txt", buf, 3)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if string(buf[:n]) != "tent1" {
			t.Errorf("Expected 'tent1', got %q", string(buf[:n]))
		}
	})

	t.Run("Write", func(t *testing.T) {
		n, err := handler.Write(nil, sess, "file1.txt", []byte("NEW"), 0)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		if n != 3 {
			t.Errorf("Expected 3 bytes written, got %d", n)
		}

		buf := make([]byte, 100)
		n, _ = handler.Read(nil, sess, "file1.txt", buf, 0)
		if string(buf[:n]) != "NEWtent1" {
			t.Errorf("Expected 'NEWtent1', got %q", string(buf[:n]))
		}
	})

	t.Run("Create", func(t *testing.T) {
		err := handler.Create(nil, sess, "newfile.txt", 0644)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		attr, err := handler.Lookup(nil, sess, "newfile.txt")
		if err != nil {
			t.Fatalf("Lookup after create failed: %v", err)
		}
		if attr.Size != 0 {
			t.Errorf("New file should be empty, got size %d", attr.Size)
		}
	})

	t.Run("Mkdir", func(t *testing.T) {
		err := handler.Mkdir(nil, sess, "newdir", 0755)
		if err != nil {
			t.Fatalf("Mkdir failed: %v", err)
		}

		attr, err := handler.Lookup(nil, sess, "newdir")
		if err != nil {
			t.Fatalf("Lookup after mkdir failed: %v", err)
		}
		if !attr.IsDir() {
			t.Error("Expected directory")
		}
	})

	t.Run("Remove", func(t *testing.T) {
		// Create then remove
		handler.Create(nil, sess, "toremove.txt", 0644)
		err := handler.Remove(nil, sess, "toremove.txt")
		if err != nil {
			t.Fatalf("Remove failed: %v", err)
		}

		_, err = handler.Lookup(nil, sess, "toremove.txt")
		if err == nil {
			t.Error("File should not exist after removal")
		}
	})

	t.Run("Rename", func(t *testing.T) {
		handler.Create(nil, sess, "oldname.txt", 0644)
		handler.Write(nil, sess, "oldname.txt", []byte("data"), 0)

		err := handler.Rename(nil, sess, "oldname.txt", "renamed.txt")
		if err != nil {
			t.Fatalf("Rename failed: %v", err)
		}

		// Old path should not exist
		if _, err := handler.Lookup(nil, sess, "oldname.txt"); err == nil {
			t.Error("Old path should not exist")
		}

		// New path should exist
		if _, err := handler.Lookup(nil, sess, "renamed.txt"); err != nil {
			t.Error("New path should exist")
		}
	})

	t.Run("Truncate", func(t *testing.T) {
		handler.Create(nil, sess, "truncate.txt", 0644)
		handler.Write(nil, sess, "truncate.txt", []byte("long content here"), 0)

		err := handler.Truncate(nil, sess, "truncate.txt", 4)
		if err != nil {
			t.Fatalf("Truncate failed: %v", err)
		}

		attr, _ := handler.Getattr(nil, sess, "truncate.txt")
		if attr.Size != 4 {
			t.Errorf("Expected size 4 after truncate, got %d", attr.Size)
		}

		buf := make([]byte, 100)
		n, _ := handler.Read(nil, sess, "truncate.txt", buf, 0)
		if string(buf[:n]) != "long" {
			t.Errorf("Expected 'long', got %q", string(buf[:n]))
		}
	})

	t.Run("UserIsolation", func(t *testing.T) {
		handler.InitUser("user1", map[string][]byte{"private.txt": []byte("user1 data")})
		handler.InitUser("user2", map[string][]byte{"private.txt": []byte("user2 data")})

		sess1 := Session{User: "user1", Share: "test", Handle: 2}
		sess2 := Session{User: "user2", Share: "test", Handle: 3}

		buf := make([]byte, 100)

		n, _ := handler.Read(nil, sess1, "private.txt", buf, 0)
		if string(buf[:n]) != "user1 data" {
			t.Errorf("user1 should see 'user1 data', got %q", string(buf[:n]))
		}

		n, _ = handler.Read(nil, sess2, "private.txt", buf, 0)
		if string(buf[:n]) != "user2 data" {
			t.Errorf("user2 should see 'user2 data', got %q", string(buf[:n]))
		}
	})
}
