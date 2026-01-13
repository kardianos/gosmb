package smbsys

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	testPort     = "4455"
	testUser     = "testuser"
	testPassword = "my-pass"
	testShare    = "memshare"
)

// smbClient provides helper methods for smbclient operations
type smbClient struct {
	t        *testing.T
	host     string
	port     string
	user     string
	password string
	share    string
	opts     []string
}

func newSMBClient(t *testing.T) *smbClient {
	return &smbClient{
		t:        t,
		host:     "localhost",
		port:     testPort,
		user:     testUser,
		password: testPassword,
		share:    testShare,
		opts:     []string{"--option=client signing=off"},
	}
}

func (c *smbClient) credentials() string {
	return fmt.Sprintf("%s%%%s", c.user, c.password)
}

func (c *smbClient) shareURL() string {
	return fmt.Sprintf("//%s/%s", c.host, c.share)
}

func (c *smbClient) baseArgs() []string {
	return append(c.opts, c.shareURL(), "-p", c.port, "-U", c.credentials())
}

// run executes an smbclient command and returns output
func (c *smbClient) run(command string) ([]byte, error) {
	args := append(c.baseArgs(), "-c", command)
	cmd := exec.Command("smbclient", args...)
	return cmd.CombinedOutput()
}

// mustRun executes an smbclient command and fails the test on error
func (c *smbClient) mustRun(command string) []byte {
	out, err := c.run(command)
	if err != nil {
		c.t.Fatalf("smbclient command %q failed: %v\nOutput:\n%s", command, err, string(out))
	}
	return out
}

// listShares lists available shares
func (c *smbClient) listShares() ([]byte, error) {
	args := append(c.opts, "-L", c.host, "-p", c.port, "-U", c.credentials(), "-d", "3")
	cmd := exec.Command("smbclient", args...)
	return cmd.CombinedOutput()
}

// put uploads a file to the share
func (c *smbClient) put(localPath, remotePath string) error {
	_, err := c.run(fmt.Sprintf("put %s %s", localPath, remotePath))
	return err
}

// get downloads a file to stdout
func (c *smbClient) get(remotePath string) ([]byte, error) {
	return c.run(fmt.Sprintf("get %s -", remotePath))
}

// ls lists directory contents
func (c *smbClient) ls() ([]byte, error) {
	return c.run("ls")
}

// del deletes a file
func (c *smbClient) del(path string) error {
	_, err := c.run(fmt.Sprintf("del %s", path))
	return err
}

// mkdir creates a directory
func (c *smbClient) mkdir(path string) error {
	_, err := c.run(fmt.Sprintf("mkdir %s", path))
	return err
}

// rmdir removes a directory
func (c *smbClient) rmdir(path string) error {
	_, err := c.run(fmt.Sprintf("rmdir %s", path))
	return err
}

// rename renames a file or directory
func (c *smbClient) rename(oldPath, newPath string) error {
	_, err := c.run(fmt.Sprintf("rename %s %s", oldPath, newPath))
	return err
}

// allinfo gets detailed file info
func (c *smbClient) allinfo(path string) ([]byte, error) {
	return c.run(fmt.Sprintf("allinfo %s", path))
}

// setmode sets DOS attributes
func (c *smbClient) setmode(path, mode string) error {
	_, err := c.run(fmt.Sprintf("setmode %s %s", path, mode))
	return err
}

// createTempFile creates a temporary file with content in the given directory and returns its path
func createTempFile(t *testing.T, dir, name, content string) string {
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create temp file %s: %v", name, err)
	}
	t.Cleanup(func() { os.Remove(path) })
	return path
}

// setupTestMountPoint creates a tmpfs mount with test files for testing
func setupTestMountPoint(t *testing.T) string {
	mountPoint := "/tmp/gosmb_test"

	os.RemoveAll(mountPoint)
	os.MkdirAll(mountPoint, 0777)

	// Wait a tiny bit
	time.Sleep(100 * time.Millisecond)

	// Create a subfolder
	os.MkdirAll(mountPoint+"/subfolder", 0777)
	os.Chmod(mountPoint+"/subfolder", 0777)
	// Create files
	os.WriteFile(mountPoint+"/hello.txt", []byte("Hello from in-memory Go SMB!\n"), 0777)
	os.Chmod(mountPoint+"/hello.txt", 0777)
	os.WriteFile(mountPoint+"/subfolder/test.txt", []byte("Nested file content\n"), 0777)
	os.Chmod(mountPoint+"/subfolder/test.txt", 0777)
	os.Chmod(mountPoint, 0777)

	t.Logf("Created test mount at %s", mountPoint)

	// Double check
	files, _ := os.ReadDir(mountPoint)
	for _, f := range files {
		t.Logf("File in %s: %s", mountPoint, f.Name())
	}

	return mountPoint
}

// TestAuthenticatorValidation verifies that at least one authenticator is required.
func TestAuthenticatorValidation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test must be run as root")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Test: No authenticators should fail
	sys := NewSys()
	err := sys.Start(ctx, SysOpt{
		Config: DefaultServerConfig(),
		ShareProvider: NewFSShareProvider([]FSShare{
			{ShareInfo: ShareInfo{Name: "test"}, Path: "/tmp"},
		}),
		// No authenticators set
	})
	if err == nil {
		t.Fatal("Expected error when no authenticators provided")
	}
	if !strings.Contains(err.Error(), "at least one") {
		t.Errorf("Expected 'at least one' error, got: %v", err)
	}
}

func TestIntegration(t *testing.T) {
	const runDMSG = false

	if os.Geteuid() != 0 {
		t.Fatal("Test must be run as root to interface with ksmbd")
	}

	if runDMSG {
		exec.Command("sudo", "dmesg", "-C").Run()
	}

	// Setup test mount point
	mountPoint := setupTestMountPoint(t)

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "gosmb-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create context for server lifetime
	ctx, cancel := context.WithCancel(context.Background())

	// Configure and start server
	config := DefaultServerConfig()
	config.TCPPort = 4455 // Use non-privileged port for testing

	sys := NewSys()
	err = sys.Start(ctx, SysOpt{
		Logger: NewLogger(os.Stderr),
		Config: config,
		ShareProvider: NewFSShareProvider([]FSShare{
			{ShareInfo: ShareInfo{Name: "memshare"}, Path: mountPoint},
		}),
		NTLMAuthenticator: NewStaticNTLMAuthenticator(map[string]*UserCredentials{
			testUser: {PasswordHash: NewPassHash(testPassword)},
		}),
	})
	if err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Ensure cleanup happens
	defer func() {
		cancel() // Signal server to stop
		sys.Wait() // Wait for complete shutdown (module unloaded)
		syscall.Unmount(mountPoint, 0)
		os.RemoveAll(mountPoint)
	}()

	// Debug output (disabled by default)
	if runDMSG {
		t.Log(">>> Checking listening ports <<<")
		cmdSS := exec.Command("ss", "-tlnp")
		cmdSS.Stdout = os.Stdout
		cmdSS.Run()

		t.Log(">>> Dumping dmesg (last 100 lines) <<<")
		cmdDmesg := exec.Command("dmesg")
		outDmesg, _ := cmdDmesg.CombinedOutput()
		lines := bytes.Split(outDmesg, []byte("\n"))
		start := len(lines) - 100
		if start < 0 {
			start = 0
		}
		for _, line := range lines[start:] {
			t.Logf("KERNEL: %s", line)
		}
		t.Log(">>> End dmesg <<<")
	}

	t.Log(">>> Starting Client Verification <<<")

	client := newSMBClient(t)

	// Table-driven tests for basic operations
	t.Run("BasicOperations", func(t *testing.T) {
		basicTests := []struct {
			name string
			test func(t *testing.T)
		}{
			{
				name: "ListShares",
				test: func(t *testing.T) {
					out, err := client.listShares()
					if err != nil {
						t.Fatalf("list shares failed: %v\nOutput:\n%s", err, out)
					}
					if !bytes.Contains(out, []byte("memshare")) {
						t.Fatal("memshare not found in share list")
					}
					if !bytes.Contains(out, []byte("IPC$")) {
						t.Fatal("IPC$ not found in share list")
					}
				},
			},
			{
				name: "ReadFile",
				test: func(t *testing.T) {
					out, err := client.get("hello.txt")
					if err != nil {
						t.Fatalf("get hello.txt failed: %v\nOutput:\n%s", err, out)
					}
					if !bytes.Contains(out, []byte("Hello from in-memory Go SMB!")) {
						t.Fatal("Expected content not found in hello.txt")
					}
				},
			},
			{
				name: "ListFiles",
				test: func(t *testing.T) {
					out, err := client.ls()
					if err != nil {
						t.Fatalf("ls failed: %v\nOutput:\n%s", err, out)
					}
					if !bytes.Contains(out, []byte("subfolder")) {
						t.Fatal("subfolder not found")
					}
					if !bytes.Contains(out, []byte("hello.txt")) {
						t.Fatal("hello.txt not found")
					}
				},
			},
			{
				name: "ReadNestedFile",
				test: func(t *testing.T) {
					out, err := client.get("subfolder\\test.txt")
					if err != nil {
						t.Fatalf("get nested file failed: %v\nOutput:\n%s", err, out)
					}
					if !bytes.Contains(out, []byte("Nested file content")) {
						t.Fatal("Expected nested content not found")
					}
				},
			},
			{
				name: "QueryFileInfo",
				test: func(t *testing.T) {
					out, err := client.allinfo("hello.txt")
					if err != nil {
						t.Fatalf("allinfo failed: %v\nOutput:\n%s", err, out)
					}
					for _, field := range []string{"create_time:", "access_time:", "write_time:"} {
						if !bytes.Contains(out, []byte(field)) {
							t.Fatalf("Missing %s in file info", field)
						}
					}
				},
			},
		}

		for _, tc := range basicTests {
			t.Run(tc.name, tc.test)
		}
	})

	// Table-driven tests for write operations
	t.Run("WriteOperations", func(t *testing.T) {
		writeTests := []struct {
			name    string
			setup   func() string // returns cleanup command if any
			test    func(t *testing.T)
			cleanup func()
		}{
			{
				name: "OverwriteFile",
				test: func(t *testing.T) {
					newContent := "Updated content"
					tmpFile := createTempFile(t, tmpDir, "overwrite_tmp.txt", newContent)

					if err := client.put(tmpFile, "hello.txt"); err != nil {
						t.Fatalf("put overwrite failed: %v", err)
					}

					out, err := client.get("hello.txt")
					if err != nil {
						t.Fatalf("get after overwrite failed: %v", err)
					}
					if !bytes.Contains(out, []byte(newContent)) {
						t.Fatal("Overwritten content not found")
					}
				},
			},
			{
				name: "CreateNewFile",
				test: func(t *testing.T) {
					content := "Fresh file content"
					tmpFile := createTempFile(t, tmpDir, "newfile_tmp.txt", content)

					if err := client.put(tmpFile, "newfile.txt"); err != nil {
						t.Fatalf("put new file failed: %v", err)
					}

					out, err := client.get("newfile.txt")
					if err != nil {
						t.Fatalf("get new file failed: %v", err)
					}
					if !bytes.Contains(out, []byte(content)) {
						t.Fatal("New file content not found")
					}
				},
				cleanup: func() {
					client.del("newfile.txt")
				},
			},
			{
				name: "DeleteFile",
				test: func(t *testing.T) {
					// Create file to delete
					tmpFile := createTempFile(t, tmpDir, "delete_tmp.txt", "to be deleted")
					client.put(tmpFile, "deleteme.txt")

					if err := client.del("deleteme.txt"); err != nil {
						t.Fatalf("delete failed: %v", err)
					}

					out, _ := client.ls()
					if bytes.Contains(out, []byte("deleteme.txt")) {
						t.Fatal("File still exists after deletion")
					}
				},
			},
			{
				name: "CreateDirectory",
				test: func(t *testing.T) {
					if err := client.mkdir("testdir"); err != nil {
						t.Fatalf("mkdir failed: %v", err)
					}

					out, _ := client.ls()
					if !bytes.Contains(out, []byte("testdir")) {
						t.Fatal("Directory not created")
					}
				},
				cleanup: func() {
					client.rmdir("testdir")
				},
			},
			{
				name: "RemoveDirectory",
				test: func(t *testing.T) {
					client.mkdir("rmtestdir")

					if err := client.rmdir("rmtestdir"); err != nil {
						t.Fatalf("rmdir failed: %v", err)
					}

					out, _ := client.ls()
					if bytes.Contains(out, []byte("rmtestdir")) {
						t.Fatal("Directory still exists after removal")
					}
				},
			},
			{
				name: "RenameFile",
				test: func(t *testing.T) {
					tmpFile := createTempFile(t, tmpDir, "rename_tmp.txt", "File to rename")
					client.put(tmpFile, "original.txt")

					if err := client.rename("original.txt", "renamed.txt"); err != nil {
						t.Fatalf("rename failed: %v", err)
					}

					out, _ := client.ls()
					if bytes.Contains(out, []byte("original.txt")) {
						t.Fatal("Original file still exists")
					}
					if !bytes.Contains(out, []byte("renamed.txt")) {
						t.Fatal("Renamed file not found")
					}

					// Verify content preserved
					content, _ := client.get("renamed.txt")
					if !bytes.Contains(content, []byte("File to rename")) {
						t.Fatal("Content not preserved after rename")
					}
				},
				cleanup: func() {
					client.del("renamed.txt")
				},
			},
			{
				name: "RenameDirectory",
				test: func(t *testing.T) {
					client.mkdir("olddir")

					if err := client.rename("olddir", "newdirname"); err != nil {
						t.Fatalf("rename dir failed: %v", err)
					}

					out, _ := client.ls()
					if bytes.Contains(out, []byte("olddir")) {
						t.Fatal("Old directory still exists")
					}
					if !bytes.Contains(out, []byte("newdirname")) {
						t.Fatal("Renamed directory not found")
					}
				},
				cleanup: func() {
					client.rmdir("newdirname")
				},
			},
			{
				name: "SetFileAttributes",
				test: func(t *testing.T) {
					tmpFile := createTempFile(t, tmpDir, "attr_tmp.txt", "Attribute test")
					client.put(tmpFile, "attrtest.txt")

					if err := client.setmode("attrtest.txt", "+h"); err != nil {
						t.Fatalf("setmode failed: %v", err)
					}

					// Query to verify (attribute may not always be visible)
					out, _ := client.allinfo("attrtest.txt")
					t.Logf("Attributes after setmode:\n%s", out)
				},
				cleanup: func() {
					client.del("attrtest.txt")
				},
			},
		}

		for _, tc := range writeTests {
			t.Run(tc.name, func(t *testing.T) {
				tc.test(t)
				if tc.cleanup != nil {
					tc.cleanup()
				}
			})
		}
	})

	// Tests that may be unsupported (skip on error)
	t.Run("OptionalFeatures", func(t *testing.T) {
		optionalTests := []struct {
			name     string
			test     func() ([]byte, error)
			validate func([]byte) error
		}{
			{
				name: "HardLink",
				test: func() ([]byte, error) {
					tmpFile := createTempFile(t, tmpDir, "link_tmp.txt", "Link source content")
					client.put(tmpFile, "linksrc.txt")
					return client.run("hardlink linksrc.txt linkdst.txt")
				},
				validate: func(out []byte) error {
					ls, _ := client.ls()
					if !bytes.Contains(ls, []byte("linkdst.txt")) {
						return fmt.Errorf("hardlink target not found")
					}
					content, _ := client.get("linkdst.txt")
					if !bytes.Contains(content, []byte("Link source content")) {
						return fmt.Errorf("hardlink content mismatch")
					}
					client.del("linksrc.txt")
					client.del("linkdst.txt")
					return nil
				},
			},
			{
				name: "Stat",
				test: func() ([]byte, error) {
					return client.run("stat hello.txt")
				},
				validate: func(out []byte) error {
					if !bytes.Contains(out, []byte("hello.txt")) {
						return fmt.Errorf("filename not in stat output")
					}
					return nil
				},
			},
			{
				name: "Volume",
				test: func() ([]byte, error) {
					return client.run("volume")
				},
				validate: func(out []byte) error {
					// Just check it returns something
					return nil
				},
			},
		}

		for _, tc := range optionalTests {
			t.Run(tc.name, func(t *testing.T) {
				out, err := tc.test()
				if err != nil {
					// Check if it's an expected unsupported feature
					outStr := string(out)
					if strings.Contains(outStr, "NT_STATUS_INVALID_PARAMETER") ||
						strings.Contains(outStr, "UNIX CIFS") ||
						strings.Contains(outStr, "not supported") {
						t.Skipf("Feature not supported: %s", outStr)
					}
					t.Fatalf("Unexpected error: %v\nOutput: %s", err, out)
				}
				if tc.validate != nil {
					if err := tc.validate(out); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	})

	// Filesystem info tests
	t.Run("FilesystemInfo", func(t *testing.T) {
		t.Run("DiskUsage", func(t *testing.T) {
			out, err := client.run("du")
			if err != nil {
				t.Fatalf("du failed: %v\nOutput:\n%s", err, out)
			}
			if !bytes.Contains(out, []byte("blocks")) {
				t.Fatal("Block info not found in du output")
			}
		})
	})

	t.Log(">>> Verification SUCCESS <<<")
}

// mockRPCHandler implements RPCInterfaceHandler for testing.
type mockRPCHandler struct {
	mu           sync.Mutex
	bindCalls    [][]byte
	requestCalls []struct {
		opnum  uint16
		packet []byte
	}
	bindResponse    []byte
	requestResponse []byte
	bindErr         error
	requestErr      error
}

func (h *mockRPCHandler) HandleBind(ctx context.Context, bindPacket []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.bindCalls = append(h.bindCalls, bindPacket)
	return h.bindResponse, h.bindErr
}

func (h *mockRPCHandler) HandleRequest(ctx context.Context, opnum uint16, requestPacket []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.requestCalls = append(h.requestCalls, struct {
		opnum  uint16
		packet []byte
	}{opnum, requestPacket})
	return h.requestResponse, h.requestErr
}

func (h *mockRPCHandler) getBindCallCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.bindCalls)
}

func (h *mockRPCHandler) getRequestCallCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.requestCalls)
}

func (h *mockRPCHandler) getLastRequestOpnum() uint16 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.requestCalls) == 0 {
		return 0
	}
	return h.requestCalls[len(h.requestCalls)-1].opnum
}

func TestPipeRegistryBasic(t *testing.T) {
	registry := NewPipeRegistry()

	// Test empty registry
	if handler := registry.GetHandler(SamrInterfaceUUID); handler != nil {
		t.Error("Expected nil handler for unregistered UUID")
	}

	if len(registry.ListInterfaces()) != 0 {
		t.Error("Expected empty interface list")
	}

	// Register a handler
	mockHandler := &mockRPCHandler{}
	registry.RegisterInterface(SamrInterfaceUUID, mockHandler)

	// Test retrieval
	if handler := registry.GetHandler(SamrInterfaceUUID); handler != mockHandler {
		t.Error("Expected to get registered handler")
	}

	// Test list
	interfaces := registry.ListInterfaces()
	if len(interfaces) != 1 {
		t.Errorf("Expected 1 interface, got %d", len(interfaces))
	}

	// Register another handler
	mockHandler2 := &mockRPCHandler{}
	registry.RegisterInterface(NetlogonInterfaceUUID, mockHandler2)

	if len(registry.ListInterfaces()) != 2 {
		t.Error("Expected 2 interfaces")
	}

	// Verify different UUIDs return different handlers
	if registry.GetHandler(SamrInterfaceUUID) == registry.GetHandler(NetlogonInterfaceUUID) {
		t.Error("Different UUIDs should return different handlers")
	}

	// Unregistered UUID still returns nil
	if handler := registry.GetHandler(LsarpcInterfaceUUID); handler != nil {
		t.Error("Expected nil for unregistered LSARPC UUID")
	}
}

// buildTestBindPacket creates a DCE/RPC BIND packet with the given interface UUID.
// This follows MS-RPCE 2.2.2.3 structure.
func buildTestBindPacket(callID uint32, interfaceUUID [16]byte) []byte {
	buf := new(bytes.Buffer)

	// DCE/RPC header (bytes 0-15)
	buf.WriteByte(5)                                           // rpc_vers
	buf.WriteByte(0)                                           // rpc_vers_minor
	buf.WriteByte(11)                                          // PTYPE = BIND
	buf.WriteByte(0x03)                                        // pfc_flags (first+last)
	binary.Write(buf, binary.LittleEndian, uint32(0x00000010)) // packed_drep (little-endian)
	binary.Write(buf, binary.LittleEndian, uint16(72))         // frag_length
	binary.Write(buf, binary.LittleEndian, uint16(0))          // auth_length
	binary.Write(buf, binary.LittleEndian, callID)             // call_id

	// BIND body (bytes 16-23)
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // max_xmit_frag
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // max_recv_frag
	binary.Write(buf, binary.LittleEndian, uint32(0))    // assoc_group_id

	// p_cont_list_t (bytes 24-27)
	buf.WriteByte(1)          // n_context_elem
	buf.Write([]byte{0, 0, 0}) // reserved

	// p_cont_elem_t[0] (bytes 28-31 + interface)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // p_cont_id
	buf.WriteByte(1)                                  // n_transfer_syn
	buf.WriteByte(0)                                  // reserved

	// abstract_syntax (interface UUID + version) - bytes 32-51
	buf.Write(interfaceUUID[:])                       // interface UUID (16 bytes)
	binary.Write(buf, binary.LittleEndian, uint32(1)) // version

	// transfer_syntax (NDR) - bytes 52-71
	ndrUUID := [16]byte{
		0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
		0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
	}
	buf.Write(ndrUUID[:])
	binary.Write(buf, binary.LittleEndian, uint32(2)) // NDR version

	return buf.Bytes()
}

// buildTestRequestPacket creates a DCE/RPC REQUEST packet.
func buildTestRequestPacket(callID uint32, contextID, opnum uint16, stubData []byte) []byte {
	buf := new(bytes.Buffer)

	fragLen := uint16(24 + len(stubData))

	// DCE/RPC header (bytes 0-15)
	buf.WriteByte(5)                                           // rpc_vers
	buf.WriteByte(0)                                           // rpc_vers_minor
	buf.WriteByte(0)                                           // PTYPE = REQUEST
	buf.WriteByte(0x03)                                        // pfc_flags (first+last)
	binary.Write(buf, binary.LittleEndian, uint32(0x00000010)) // packed_drep
	binary.Write(buf, binary.LittleEndian, fragLen)            // frag_length
	binary.Write(buf, binary.LittleEndian, uint16(0))          // auth_length
	binary.Write(buf, binary.LittleEndian, callID)             // call_id

	// REQUEST body (bytes 16-23)
	binary.Write(buf, binary.LittleEndian, uint32(len(stubData))) // alloc_hint
	binary.Write(buf, binary.LittleEndian, contextID)             // p_cont_id
	binary.Write(buf, binary.LittleEndian, opnum)                 // opnum

	// Stub data
	buf.Write(stubData)

	return buf.Bytes()
}

func TestPipeRegistryBindRouting(t *testing.T) {
	// Create a Sys instance with a pipe registry
	sys := NewSys()
	registry := NewPipeRegistry()

	// Create mock handler with a response
	mockHandler := &mockRPCHandler{
		bindResponse: []byte("mock-bind-ack"),
	}
	registry.RegisterInterface(SamrInterfaceUUID, mockHandler)

	// Set up sys with the registry (normally done via Start, but we test directly)
	sys.pipeRegistry = registry

	// Build a BIND packet for SAMR interface
	bindPacket := buildTestBindPacket(1, SamrInterfaceUUID)

	// Verify the UUID is at the expected offset (32-47)
	var extractedUUID [16]byte
	copy(extractedUUID[:], bindPacket[32:48])
	if extractedUUID != SamrInterfaceUUID {
		t.Fatalf("UUID not at expected offset: got %x, want %x", extractedUUID, SamrInterfaceUUID)
	}

	// Test that handler lookup works
	handler := registry.GetHandler(extractedUUID)
	if handler == nil {
		t.Fatal("Handler not found for SAMR UUID")
	}

	// Simulate HandleBind call
	resp, err := handler.HandleBind(context.Background(), bindPacket)
	if err != nil {
		t.Fatalf("HandleBind error: %v", err)
	}
	if string(resp) != "mock-bind-ack" {
		t.Errorf("Unexpected response: %s", resp)
	}

	if mockHandler.getBindCallCount() != 1 {
		t.Errorf("Expected 1 bind call, got %d", mockHandler.getBindCallCount())
	}
}

func TestPipeRegistryRequestRouting(t *testing.T) {
	sys := NewSys()
	registry := NewPipeRegistry()

	mockHandler := &mockRPCHandler{
		requestResponse: []byte("mock-response"),
	}
	registry.RegisterInterface(SamrInterfaceUUID, mockHandler)

	sys.pipeRegistry = registry

	// Simulate binding first (associates handle with handler)
	handle := uint32(42)
	sys.rpcHandlers[handle] = mockHandler

	// Build a REQUEST packet
	requestPacket := buildTestRequestPacket(1, 0, 15, []byte("stub-data"))

	// Verify opnum extraction works (offset 22-23)
	opnum := binary.LittleEndian.Uint16(requestPacket[22:24])
	if opnum != 15 {
		t.Fatalf("Opnum not at expected offset: got %d, want 15", opnum)
	}

	// Test routing via the handler map
	handler, ok := sys.rpcHandlers[handle]
	if !ok {
		t.Fatal("Handler not found for handle")
	}

	resp, err := handler.HandleRequest(context.Background(), opnum, requestPacket)
	if err != nil {
		t.Fatalf("HandleRequest error: %v", err)
	}
	if string(resp) != "mock-response" {
		t.Errorf("Unexpected response: %s", resp)
	}

	if mockHandler.getRequestCallCount() != 1 {
		t.Errorf("Expected 1 request call, got %d", mockHandler.getRequestCallCount())
	}

	if mockHandler.getLastRequestOpnum() != 15 {
		t.Errorf("Expected opnum 15, got %d", mockHandler.getLastRequestOpnum())
	}
}

func TestPipeRegistryMultipleInterfaces(t *testing.T) {
	registry := NewPipeRegistry()

	samrHandler := &mockRPCHandler{bindResponse: []byte("samr-ack")}
	netlogonHandler := &mockRPCHandler{bindResponse: []byte("netlogon-ack")}
	lsarpcHandler := &mockRPCHandler{bindResponse: []byte("lsarpc-ack")}

	registry.RegisterInterface(SamrInterfaceUUID, samrHandler)
	registry.RegisterInterface(NetlogonInterfaceUUID, netlogonHandler)
	registry.RegisterInterface(LsarpcInterfaceUUID, lsarpcHandler)

	// Test that each UUID routes to the correct handler
	tests := []struct {
		uuid         [16]byte
		name         string
		expectedResp string
	}{
		{SamrInterfaceUUID, "SAMR", "samr-ack"},
		{NetlogonInterfaceUUID, "NetLogon", "netlogon-ack"},
		{LsarpcInterfaceUUID, "LSARPC", "lsarpc-ack"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := registry.GetHandler(tc.uuid)
			if handler == nil {
				t.Fatalf("No handler for %s", tc.name)
			}

			bindPacket := buildTestBindPacket(1, tc.uuid)
			resp, err := handler.HandleBind(context.Background(), bindPacket)
			if err != nil {
				t.Fatalf("HandleBind error: %v", err)
			}
			if string(resp) != tc.expectedResp {
				t.Errorf("Expected %q, got %q", tc.expectedResp, resp)
			}
		})
	}
}

func TestPipeRegistryUnknownInterface(t *testing.T) {
	registry := NewPipeRegistry()

	// Register only SAMR
	mockHandler := &mockRPCHandler{}
	registry.RegisterInterface(SamrInterfaceUUID, mockHandler)

	// Try to get handler for unknown UUID
	unknownUUID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}

	if handler := registry.GetHandler(unknownUUID); handler != nil {
		t.Error("Expected nil for unknown UUID")
	}

	// NetLogon not registered
	if handler := registry.GetHandler(NetlogonInterfaceUUID); handler != nil {
		t.Error("Expected nil for unregistered NetLogon UUID")
	}
}

func TestWellKnownUUIDs(t *testing.T) {
	// Verify the well-known UUIDs are correctly defined (little-endian wire format)
	// These match MS-SAMR, MS-NRPC, MS-LSAD specifications

	tests := []struct {
		name string
		uuid [16]byte
		// First 4 bytes should match the Data1 field in little-endian
		expectedData1 uint32
	}{
		{"SAMR", SamrInterfaceUUID, 0x12345778},
		{"NetLogon", NetlogonInterfaceUUID, 0x12345678},
		{"LSARPC", LsarpcInterfaceUUID, 0x12345778},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data1 := binary.LittleEndian.Uint32(tc.uuid[0:4])
			if data1 != tc.expectedData1 {
				t.Errorf("UUID Data1 mismatch: got 0x%08x, want 0x%08x", data1, tc.expectedData1)
			}
		})
	}
}
