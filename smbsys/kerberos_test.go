package smbsys_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kardianos/gosmb/krb5"
	"github.com/kardianos/gosmb/smblog"
	"github.com/kardianos/gosmb/smbsys"
)

// krb5Adapter wraps krb5.ServiceAuthenticator to implement smbsys.KerberosAuthenticator.
type krb5Adapter struct {
	auth             *krb5.ServiceAuthenticator
	servicePrincipal string
	realm            string
}

func (a *krb5Adapter) ValidateAPReq(apReqBytes []byte) (*smbsys.KerberosAuthResult, error) {
	result, err := a.auth.ValidateAPReq(apReqBytes)
	if err != nil {
		return nil, err
	}
	return &smbsys.KerberosAuthResult{
		Username:   result.Username,
		SessionKey: result.SessionKey.KeyValue,
		APRep:      result.APRep,
	}, nil
}

func (a *krb5Adapter) SPNEGOConfig() *smbsys.SPNEGOConfig {
	return &smbsys.SPNEGOConfig{
		ServicePrincipal: a.servicePrincipal,
		Realm:            a.realm,
	}
}

// testPrincipalStore is a simple principal store for testing.
// Stores pre-computed AES256 keys for both users and services.
type testPrincipalStore struct {
	users    map[string][]byte // user principal -> key
	services map[string][]byte // service principal -> key
}

func (s *testPrincipalStore) GetKey(principalType krb5.PrincipalType, principal, realm string) ([]byte, error) {
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

// newTestPrincipalStore creates a test principal store with keys derived from passwords.
func newTestPrincipalStore(realm string, users, services map[string]string) *testPrincipalStore {
	store := &testPrincipalStore{
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

func TestKerberosAuthFlow(t *testing.T) {
	// Test configuration
	realm := "TEST.EXAMPLE.COM"
	clientPrincipal := "testuser"
	clientPassword := "user-password-123"
	servicePrincipal := "cifs/smbserver.test.example.com"
	servicePassword := "service-secret-456"

	// Start our KDC
	kdc, err := krb5.NewKDC(krb5.KDCConfig{
		Realm:      realm,
		ListenAddr: "127.0.0.1:0", // Random port
		Principals: newTestPrincipalStore(realm,
			map[string]string{clientPrincipal: clientPassword},
			map[string]string{servicePrincipal: servicePassword},
		),
		TicketLifetime: 1 * time.Hour,
		Logger:         smblog.New(os.Stderr),
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
	t.Logf("KDC started on %s", kdc.Addr())

	// Create Kerberos client
	client := krb5.NewClient(clientPrincipal, realm, clientPassword, kdc.Addr())

	// Get AP-REQ (this would normally be wrapped in SPNEGO for SMB)
	apReq, _, err := client.GetAPReq(servicePrincipal)
	if err != nil {
		t.Fatalf("GetAPReq: %v", err)
	}
	t.Logf("Got AP-REQ (%d bytes)", len(apReq))

	// Create service authenticator using our krb5 package
	serviceAuth, err := krb5.NewServiceAuthenticator(krb5.ServiceAuthenticatorConfig{
		Principal: servicePrincipal,
		Realm:     realm,
		Password:  servicePassword,
	})
	if err != nil {
		t.Fatalf("NewServiceAuthenticator: %v", err)
	}

	// Wrap in adapter for smbsys interface
	smbAuth := &krb5Adapter{
		auth:             serviceAuth,
		servicePrincipal: servicePrincipal,
		realm:            realm,
	}

	// Validate AP-REQ (simulating what smbsys would do)
	result, err := smbAuth.ValidateAPReq(apReq)
	if err != nil {
		t.Fatalf("ValidateAPReq: %v", err)
	}

	// Verify results
	t.Logf("Authentication successful!")
	t.Logf("  Username: %s", result.Username)
	t.Logf("  Session key length: %d bytes", len(result.SessionKey))
	t.Logf("  AP-REP length: %d bytes", len(result.APRep))

	if result.Username != clientPrincipal {
		t.Errorf("Username = %q, want %q", result.Username, clientPrincipal)
	}
	if len(result.SessionKey) == 0 {
		t.Error("SessionKey is empty")
	}
	if len(result.APRep) == 0 {
		t.Error("AP-REP is empty")
	}
}

func TestKerberosWithSMBSysConfig(t *testing.T) {
	// This test verifies that our krb5 package works with the same
	// configuration format as smbsys.KerberosConfig

	realm := "CORP.LOCAL"
	servicePrincipal := "cifs/fileserver.corp.local"
	servicePassword := "file-server-secret"

	// Create authenticator using krb5 package with same config style
	serviceAuth, err := krb5.NewServiceAuthenticator(krb5.ServiceAuthenticatorConfig{
		Principal: servicePrincipal,
		Realm:     realm,
		Password:  servicePassword,
	})
	if err != nil {
		t.Fatalf("NewServiceAuthenticator: %v", err)
	}

	// Verify it's not nil
	if serviceAuth == nil {
		t.Fatal("serviceAuth is nil")
	}

	t.Log("Service authenticator created successfully")

	// Also verify the smbsys.KerberosConfig and NewKerberosAuthenticator work
	smbKerbAuth, err := smbsys.NewKerberosAuthenticator(smbsys.KerberosConfig{
		ServicePrincipal: servicePrincipal,
		Realm:            realm,
		Password:         servicePassword,
	})
	if err != nil {
		t.Fatalf("smbsys.NewKerberosAuthenticator: %v", err)
	}

	if smbKerbAuth == nil {
		t.Fatal("smbKerbAuth is nil")
	}

	t.Log("SMBSys Kerberos authenticator created successfully")
}
