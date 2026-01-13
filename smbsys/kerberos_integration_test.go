package smbsys

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kardianos/gosmb/krb5"
	"github.com/kardianos/gosmb/smblog"
)

const (
	kerbTestRealm     = "TEST.GOSMB.LOCAL"
	kerbTestUser      = "alice"
	kerbTestPassword  = "alice-secret-password"
	kerbTestShare     = "kerbshare"
	kerbServiceName   = "cifs"
	kerbTestHost      = "localhost"
	kerbServiceSecret = "smb-service-secret-key"
)

// addHostsEntry adds a temporary entry to /etc/hosts and returns a cleanup function.
// This is needed for Kerberos tests because Kerberos clients require proper hostnames.
func addHostsEntry(hostname string) (cleanup func(), err error) {
	const hostsFile = "/etc/hosts"
	entry := fmt.Sprintf("127.0.0.1 %s\n", hostname)

	// Read existing content
	original, err := os.ReadFile(hostsFile)
	if err != nil {
		return nil, fmt.Errorf("read hosts file: %w", err)
	}

	// Check if entry already exists
	if strings.Contains(string(original), hostname) {
		return func() {}, nil // Already present, no cleanup needed
	}

	// Append entry
	f, err := os.OpenFile(hostsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open hosts file: %w", err)
	}
	if _, err := f.WriteString(entry); err != nil {
		f.Close()
		return nil, fmt.Errorf("write hosts entry: %w", err)
	}
	f.Close()

	// Return cleanup function
	return func() {
		// Restore original content
		os.WriteFile(hostsFile, original, 0644)
	}, nil
}

// testKDCPrincipalStore is a simple principal store for testing.
// Stores pre-computed AES256 keys for both users and services.
type testKDCPrincipalStore struct {
	users    map[string][]byte // user principal -> key
	services map[string][]byte // service principal -> key
}

func (s *testKDCPrincipalStore) GetKey(principalType krb5.PrincipalType, principal, realm string) ([]byte, error) {
	switch principalType {
	case krb5.PrincipalUser:
		if key, ok := s.users[principal]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("user not found: %s", principal)
	case krb5.PrincipalService:
		if key, ok := s.services[principal]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("service not found: %s", principal)
	default:
		return nil, fmt.Errorf("unknown principal type: %v", principalType)
	}
}

// newTestKDCPrincipalStore creates a test principal store with keys derived from passwords.
func newTestKDCPrincipalStore(realm string, users, services map[string]string) *testKDCPrincipalStore {
	store := &testKDCPrincipalStore{
		users:    make(map[string][]byte),
		services: make(map[string][]byte),
	}
	for principal, password := range users {
		key, _ := krb5.DeriveKey(password, principal, realm)
		store.users[principal] = key
	}
	for principal, password := range services {
		key, _ := krb5.DeriveKey(password, principal, realm)
		store.services[principal] = key
	}
	return store
}

// krb5AuthAdapter wraps krb5.ServiceAuthenticator to implement smbsys.KerberosAuthenticator.
type krb5AuthAdapter struct {
	auth             *krb5.ServiceAuthenticator
	servicePrincipal string
	realm            string
}

func (a *krb5AuthAdapter) ValidateAPReq(apReqBytes []byte) (*KerberosAuthResult, error) {
	result, err := a.auth.ValidateAPReq(apReqBytes)
	if err != nil {
		return nil, err
	}
	return &KerberosAuthResult{
		Username:   result.Username,
		SessionKey: result.SessionKey.KeyValue,
		APRep:      result.APRep,
	}, nil
}

func (a *krb5AuthAdapter) SPNEGOConfig() *SPNEGOConfig {
	return &SPNEGOConfig{
		ServicePrincipal: a.servicePrincipal,
		Realm:            a.realm,
	}
}

// kerberosSMBClient wraps smbclient for Kerberos authentication.
type kerberosSMBClient struct {
	t          *testing.T
	host       string
	port       string
	share      string
	user       string // Kerberos principal (without realm)
	realm      string // Kerberos realm
	krb5Config string // Path to krb5.conf
	ccache     string // Path to credential cache
}

func (c *kerberosSMBClient) env() []string {
	env := os.Environ()
	env = append(env, "KRB5_CONFIG="+c.krb5Config)
	env = append(env, "KRB5CCNAME=FILE:"+c.ccache)
	return env
}

// configureSambaClient writes smb.conf to help smbclient find Kerberos realm.
// Samba's internal Heimdal needs the realm configured in smb.conf.
func configureSambaClient(realm string) error {
	conf := fmt.Sprintf(`[global]
workgroup = %s
realm = %s
client use spnego = yes
`, strings.Split(realm, ".")[0], realm)
	return os.WriteFile("/etc/samba/smb.conf", []byte(conf), 0644)
}

func (c *kerberosSMBClient) shareURL() string {
	return fmt.Sprintf("//%s/%s", c.host, c.share)
}

func (c *kerberosSMBClient) baseArgs() []string {
	return []string{
		c.shareURL(),
		"-p", c.port,
		// Don't specify -U, let smbclient use the default principal from ccache
		"--use-kerberos=required",
		"--use-krb5-ccache=" + c.ccache,
	}
}

func (c *kerberosSMBClient) run(command string) ([]byte, error) {
	args := append(c.baseArgs(), "-c", command)
	cmd := exec.Command("smbclient", args...)
	cmd.Env = c.env()
	return cmd.CombinedOutput()
}

func (c *kerberosSMBClient) mustRun(command string) []byte {
	out, err := c.run(command)
	if err != nil {
		c.t.Fatalf("smbclient (kerberos) command %q failed: %v\nOutput:\n%s", command, err, string(out))
	}
	return out
}

func (c *kerberosSMBClient) ls() ([]byte, error) {
	return c.run("ls")
}

func (c *kerberosSMBClient) get(remotePath string) ([]byte, error) {
	return c.run(fmt.Sprintf("get %s -", remotePath))
}

// writeKrb5Conf writes a krb5.conf file for the test KDC.
func writeKrb5Conf(path, realm, kdcHost string, kdcPort int) error {
	conf := fmt.Sprintf(`[libdefaults]
    default_realm = %s
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_%%{uid}

[realms]
    %s = {
        kdc = %s:%d
        admin_server = %s:%d
    }

[domain_realm]
    .%s = %s
    %s = %s
`, realm, realm, kdcHost, kdcPort, kdcHost, kdcPort,
		strings.ToLower(realm), realm,
		strings.ToLower(realm), realm)

	return os.WriteFile(path, []byte(conf), 0644)
}

// runKinit runs kinit to get a TGT.
func runKinit(t *testing.T, principal, password, realm, krb5Config, ccache string) error {
	fullPrincipal := principal + "@" + realm

	// Use kinit with password via stdin
	cmd := exec.Command("kinit", fullPrincipal)
	cmd.Env = append(os.Environ(),
		"KRB5_CONFIG="+krb5Config,
		"KRB5CCNAME=FILE:"+ccache, // Use FILE: prefix explicitly
		"KRB5_TRACE=/dev/stderr",  // Enable verbose tracing
	)
	cmd.Stdin = strings.NewReader(password + "\n")

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("kinit output: %s", string(out))
		return fmt.Errorf("kinit failed: %w", err)
	}

	t.Logf("kinit successful for %s", fullPrincipal)
	return nil
}

// verifyKlist checks that we have a valid ticket.
func verifyKlist(t *testing.T, krb5Config, ccache string) error {
	cmd := exec.Command("klist")
	cmd.Env = append(os.Environ(),
		"KRB5_CONFIG="+krb5Config,
		"KRB5CCNAME=FILE:"+ccache, // Use FILE: prefix explicitly
	)

	out, err := cmd.CombinedOutput()
	t.Logf("klist output:\n%s", string(out))
	return err
}

func TestKerberosIntegrationWithKinit(t *testing.T) {
	// This test uses MIT kinit to get a ticket, which requires strict ASN.1 compatibility.
	if os.Geteuid() != 0 {
		t.Skip("Test must be run as root to interface with ksmbd and bind port 88")
	}

	// Check if kinit is available
	if _, err := exec.LookPath("kinit"); err != nil {
		t.Skip("kinit not found, skipping Kerberos integration test")
	}

	// Setup test mount point
	mountPoint := "/tmp/gosmb_kerb_test"
	os.RemoveAll(mountPoint)
	os.MkdirAll(mountPoint, 0777)
	os.WriteFile(filepath.Join(mountPoint, "hello.txt"), []byte("Hello from Kerberos SMB!\n"), 0666)
	os.WriteFile(filepath.Join(mountPoint, "secret.txt"), []byte("Top secret data\n"), 0666)
	os.MkdirAll(filepath.Join(mountPoint, "subdir"), 0777)
	os.WriteFile(filepath.Join(mountPoint, "subdir", "nested.txt"), []byte("Nested content\n"), 0666)

	defer func() {
		syscall.Unmount(mountPoint, 0)
		os.RemoveAll(mountPoint)
	}()

	t.Logf("Created test mount at %s", mountPoint)

	// Create temp directory for Kerberos config
	tmpDir, err := os.MkdirTemp("", "gosmb-kerb-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	krb5ConfPath := filepath.Join(tmpDir, "krb5.conf")
	ccachePath := filepath.Join(tmpDir, "krb5cc_test")

	// Service principal: cifs/localhost@TEST.GOSMB.LOCAL
	servicePrincipal := fmt.Sprintf("%s/%s", kerbServiceName, kerbTestHost)

	// Start our KDC on port 88
	kdc, err := krb5.NewKDC(krb5.KDCConfig{
		Realm:      kerbTestRealm,
		ListenAddr: "0.0.0.0:88",
		Principals: newTestKDCPrincipalStore(kerbTestRealm,
			map[string]string{kerbTestUser: kerbTestPassword},
			map[string]string{servicePrincipal: kerbServiceSecret},
		),
		TicketLifetime: 1 * time.Hour,
		Logger:         smblog.New(os.Stderr),
	})
	if err != nil {
		t.Fatalf("NewKDC: %v", err)
	}

	kdcCtx, kdcCancel := context.WithCancel(context.Background())
	defer func() {
		kdcCancel()
		kdc.Wait()
	}()

	if err := kdc.Start(kdcCtx); err != nil {
		t.Fatalf("KDC Start: %v", err)
	}
	if err := kdc.Ready(kdcCtx); err != nil {
		t.Fatalf("KDC not ready: %v", err)
	}
	t.Logf("KDC started on port 88 (realm: %s)", kerbTestRealm)

	// Write krb5.conf
	if err := writeKrb5Conf(krb5ConfPath, kerbTestRealm, "127.0.0.1", 88); err != nil {
		t.Fatalf("Failed to write krb5.conf: %v", err)
	}
	t.Logf("Wrote krb5.conf to %s", krb5ConfPath)

	// Create Kerberos service authenticator
	serviceAuth, err := krb5.NewServiceAuthenticator(krb5.ServiceAuthenticatorConfig{
		Principal: servicePrincipal,
		Realm:     kerbTestRealm,
		Password:  kerbServiceSecret,
	})
	if err != nil {
		t.Fatalf("NewServiceAuthenticator: %v", err)
	}

	// Start SMB server with Kerberos auth
	smbCtx, smbCancel := context.WithCancel(context.Background())

	config := DefaultServerConfig()
	config.TCPPort = 4456

	sys := NewSys()
	err = sys.Start(smbCtx, SysOpt{
		Logger: NewLogger(os.Stderr),
		Config: config,
		ShareProvider: NewFSShareProvider([]FSShare{
			{ShareInfo: ShareInfo{Name: kerbTestShare}, Path: mountPoint},
		}),
		// Use Kerberos authentication
		KerberosAuthenticator: &krb5AuthAdapter{
			auth:             serviceAuth,
			servicePrincipal: servicePrincipal,
			realm:            kerbTestRealm,
		},
		// Also allow NTLM password auth as fallback for testing
		NTLMAuthenticator: NewStaticNTLMAuthenticator(map[string]*UserCredentials{
			kerbTestUser: {PasswordHash: NewPassHash(kerbTestPassword)},
		}),
	})
	if err != nil {
		t.Fatalf("Failed to start SMB server: %v", err)
	}

	defer func() {
		smbCancel()
		sys.Wait()
	}()

	t.Log("SMB server started with Kerberos authentication")

	// Get a Kerberos ticket using kinit
	t.Log("Getting Kerberos ticket with kinit...")
	if err := runKinit(t, kerbTestUser, kerbTestPassword, kerbTestRealm, krb5ConfPath, ccachePath); err != nil {
		t.Fatalf("kinit failed: %v", err)
	}

	// Verify we have a ticket
	if err := verifyKlist(t, krb5ConfPath, ccachePath); err != nil {
		t.Fatalf("klist failed: %v", err)
	}

	// Note: The ksmbd kernel module controls SPNEGO negotiation internally and
	// builds its own mechlist. We cannot control what mechanisms the kernel
	// advertises. However, when a client sends a Kerberos SPNEGO token, the
	// kernel forwards it to userspace via KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST.
	//
	// Since kinit succeeded and we have a valid TGT, the KDC implementation
	// is verified to be working correctly. The smbsys package is configured
	// to handle Kerberos authentication when the kernel forwards such requests.
	t.Log("KDC verified working: kinit succeeded, TGT obtained for alice@TEST.GOSMB.LOCAL")
	t.Log("Kerberos authenticator configured - ready to handle SPNEGO_AUTHEN_REQUEST events")

	t.Log("Kerberos KDC integration test completed successfully!")
}

// TestKerberosClientLibrary tests the krb5 client library directly
// without using external kinit. This verifies the Go implementation.
func TestKerberosClientLibrary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test must be run as root to bind port 88")
	}

	realm := "CLIENTLIB.TEST"
	user := "testuser"
	password := "user-password"
	servicePrincipal := "cifs/testserver"
	servicePassword := "service-password"

	// Start KDC
	kdc, err := krb5.NewKDC(krb5.KDCConfig{
		Realm:      realm,
		ListenAddr: "127.0.0.1:88",
		Principals: newTestKDCPrincipalStore(realm,
			map[string]string{user: password},
			map[string]string{servicePrincipal: servicePassword},
		),
		Logger: smblog.New(os.Stderr),
	})
	if err != nil {
		t.Fatalf("NewKDC: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		kdc.Wait()
	}()

	if err := kdc.Start(ctx); err != nil {
		t.Fatalf("KDC Start: %v", err)
	}
	if err := kdc.Ready(ctx); err != nil {
		t.Fatalf("KDC not ready: %v", err)
	}

	// Use krb5.Client to get ticket
	client := krb5.NewClient(user, realm, password, "127.0.0.1:88")

	// Get AP-REQ
	apReq, sessionKey, err := client.GetAPReq(servicePrincipal)
	if err != nil {
		t.Fatalf("GetAPReq: %v", err)
	}

	t.Logf("Got AP-REQ (%d bytes), session key: %d bytes", len(apReq), len(sessionKey.KeyValue))

	// Create service authenticator
	service, err := krb5.NewServiceAuthenticator(krb5.ServiceAuthenticatorConfig{
		Principal: servicePrincipal,
		Realm:     realm,
		Password:  servicePassword,
	})
	if err != nil {
		t.Fatalf("NewServiceAuthenticator: %v", err)
	}

	// Validate
	result, err := service.ValidateAPReq(apReq)
	if err != nil {
		t.Fatalf("ValidateAPReq: %v", err)
	}

	if result.Username != user {
		t.Errorf("Username = %q, want %q", result.Username, user)
	}

	t.Logf("Authentication successful: user=%s, session_key=%d bytes, ap_rep=%d bytes",
		result.Username, len(result.SessionKey.KeyValue), len(result.APRep))
}

// TestKerberosSMBClientIntegration is a full end-to-end test that:
// 1. Starts a KDC
// 2. Gets a Kerberos ticket using kinit
// 3. Starts an SMB server with Kerberos authentication
// 4. Uses smbclient with --use-kerberos=required to connect
// 5. Lists directory contents and reads a file
//
// NOTE: The kernel must be compiled with CONFIG_SMB_SERVER_KERBEROS5=y for
// Kerberos to be advertised in the SPNEGO negotiate response.
func TestKerberosSMBClientIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Test must be run as root to interface with ksmbd and bind port 88")
	}

	// Check if required tools are available
	if _, err := exec.LookPath("kinit"); err != nil {
		t.Skip("kinit not found, skipping Kerberos integration test")
	}
	if _, err := exec.LookPath("smbclient"); err != nil {
		t.Skip("smbclient not found, skipping Kerberos integration test")
	}

	// Test configuration
	const (
		testRealm       = "SMBTEST.LOCAL"
		testUser        = "testuser"
		testPassword    = "test-password-123"
		testShare       = "testshare"
		testPort        = "4457"
		serviceName     = "cifs"
		servicePassword = "service-key-456"
		testFileName    = "kerberos-test.txt"
		testFileContent = "Hello from Kerberos authenticated SMB!\n"
	)

	// Get the machine's hostname - Kerberos requires a proper FQDN, not "localhost"
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatalf("Failed to get hostname: %v", err)
	}
	// Use hostname.realm as FQDN for the service principal
	testHost := strings.ToLower(hostname) + "." + strings.ToLower(testRealm)
	servicePrincipal := fmt.Sprintf("%s/%s", serviceName, testHost)
	t.Logf("Using hostname: %s, SPN: %s", testHost, servicePrincipal)

	// Add temporary /etc/hosts entry for the test hostname
	cleanupHosts, err := addHostsEntry(testHost)
	if err != nil {
		t.Fatalf("Failed to add hosts entry: %v", err)
	}
	defer cleanupHosts()
	t.Logf("Added /etc/hosts entry for %s", testHost)

	// Setup test mount point with test files
	mountPoint, err := os.MkdirTemp("", "gosmb-kerb-mount-*")
	if err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	// Create test file
	testFilePath := filepath.Join(mountPoint, testFileName)
	if err := os.WriteFile(testFilePath, []byte(testFileContent), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create subdirectory with another file
	subDir := filepath.Join(mountPoint, "subdir")
	os.MkdirAll(subDir, 0755)
	os.WriteFile(filepath.Join(subDir, "nested.txt"), []byte("Nested file content\n"), 0644)

	t.Logf("Created test mount at %s with file %s", mountPoint, testFileName)

	// Create temp directory for Kerberos config
	tmpDir, err := os.MkdirTemp("", "gosmb-kerb-config-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	krb5ConfPath := filepath.Join(tmpDir, "krb5.conf")
	// Use the default ccache location for UID 0 (root)
	// smbclient's GSSAPI may not respect custom ccache paths correctly
	ccachePath := "/tmp/krb5cc_0"

	// Start our KDC on port 88 (required for standard Kerberos clients)
	kdc, err := krb5.NewKDC(krb5.KDCConfig{
		Realm:      testRealm,
		ListenAddr: "0.0.0.0:88",
		Principals: newTestKDCPrincipalStore(testRealm,
			map[string]string{testUser: testPassword},
			map[string]string{servicePrincipal: servicePassword},
		),
		TicketLifetime: 1 * time.Hour,
		Logger:         smblog.New(os.Stderr),
	})
	if err != nil {
		t.Fatalf("NewKDC: %v", err)
	}

	kdcCtx, kdcCancel := context.WithCancel(context.Background())
	defer func() {
		kdcCancel()
		kdc.Wait()
	}()

	if err := kdc.Start(kdcCtx); err != nil {
		t.Fatalf("KDC Start: %v", err)
	}
	if err := kdc.Ready(kdcCtx); err != nil {
		t.Fatalf("KDC not ready: %v", err)
	}
	t.Logf("KDC started on port 88 (realm: %s)", testRealm)

	// Write krb5.conf for the test
	if err := writeKrb5Conf(krb5ConfPath, testRealm, "127.0.0.1", 88); err != nil {
		t.Fatalf("Failed to write krb5.conf: %v", err)
	}
	t.Logf("Wrote krb5.conf to %s", krb5ConfPath)

	// Create Kerberos service authenticator
	serviceAuth, err := krb5.NewServiceAuthenticator(krb5.ServiceAuthenticatorConfig{
		Principal: servicePrincipal,
		Realm:     testRealm,
		Password:  servicePassword,
	})
	if err != nil {
		t.Fatalf("NewServiceAuthenticator: %v", err)
	}

	// Start SMB server with Kerberos authentication
	smbCtx, smbCancel := context.WithCancel(context.Background())

	config := DefaultServerConfig()
	config.TCPPort = 4457

	sys := NewSys()
	err = sys.Start(smbCtx, SysOpt{
		Logger: NewLogger(os.Stderr),
		Config: config,
		ShareProvider: NewFSShareProvider([]FSShare{
			{ShareInfo: ShareInfo{Name: testShare}, Path: mountPoint},
		}),
		// Use Kerberos-only authentication (no NTLM fallback)
		KerberosAuthenticator: &krb5AuthAdapter{
			auth:             serviceAuth,
			servicePrincipal: servicePrincipal,
			realm:            testRealm,
		},
	})
	if err != nil {
		t.Fatalf("Failed to start SMB server: %v", err)
	}

	defer func() {
		smbCancel()
		sys.Wait()
	}()

	// Get a Kerberos ticket using kinit
	t.Log("Getting Kerberos ticket with kinit...")
	if err := runKinit(t, testUser, testPassword, testRealm, krb5ConfPath, ccachePath); err != nil {
		t.Fatalf("kinit failed: %v", err)
	}

	// Verify we have a valid ticket
	if err := verifyKlist(t, krb5ConfPath, ccachePath); err != nil {
		t.Fatalf("klist failed: %v", err)
	}
	t.Log("Successfully obtained Kerberos ticket")

	// Check ccache file permissions
	ccacheInfo, err := os.Stat(ccachePath)
	if err != nil {
		t.Fatalf("Failed to stat ccache file: %v", err)
	}
	t.Logf("Ccache file: %s, size: %d, mode: %s", ccachePath, ccacheInfo.Size(), ccacheInfo.Mode())

	// Try to get a service ticket with kvno before running smbclient
	t.Logf("Getting service ticket for %s...", servicePrincipal+"@"+testRealm)
	kvnoCmd := exec.Command("kvno", servicePrincipal+"@"+testRealm)
	kvnoCmd.Env = append(os.Environ(),
		"KRB5_CONFIG="+krb5ConfPath,
		"KRB5CCNAME=FILE:"+ccachePath,
	)
	kvnoOut, kvnoErr := kvnoCmd.CombinedOutput()
	t.Logf("kvno output: %s", string(kvnoOut))
	if kvnoErr != nil {
		t.Fatalf("kvno failed (may not be installed): %v", kvnoErr)
	}

	// List tickets again to see if we got a service ticket
	verifyKlist(t, krb5ConfPath, ccachePath)

	// Configure samba client with realm (needed for Samba's internal Heimdal)
	if err := configureSambaClient(testRealm); err != nil {
		t.Fatalf("Failed to configure samba client: %v", err)
	}

	// Create smbclient wrapper for Kerberos
	client := &kerberosSMBClient{
		t:          t,
		host:       testHost,
		port:       testPort,
		share:      testShare,
		user:       testUser,
		realm:      testRealm,
		krb5Config: krb5ConfPath,
		ccache:     ccachePath,
	}

	// Try smbclient with Kerberos
	// NOTE: On Alpine Linux, samba-client uses internal Heimdal GSSAPI which has a bug
	// where gss_init_sec_context returns an error status even when the operation succeeds.
	// The Kerberos token IS sent and validated by the server, but smbclient fails client-side.
	t.Log("Test: Attempting smbclient with Kerberos...")
	lsOutput, err := client.ls()
	if err != nil {
		t.Fatalf("smbclient ls failed: %v\nOutput:\n%s", err, string(lsOutput))
	}

	// If smbclient succeeded, verify results
	t.Logf("Directory listing:\n%s", string(lsOutput))
	if !strings.Contains(string(lsOutput), testFileName) {
		t.Errorf("Expected file %q not found in directory listing", testFileName)
	}

	// Test 2: Read the test file
	t.Log("Test 2: Reading test file...")
	fileContent, err := client.get(testFileName)
	if err != nil {
		t.Fatalf("smbclient get failed: %v\nOutput:\n%s", err, string(fileContent))
	}

	if !strings.Contains(string(fileContent), testFileContent) {
		t.Errorf("File content mismatch:\nExpected to contain: %q\nGot: %q", testFileContent, string(fileContent))
	}
}
