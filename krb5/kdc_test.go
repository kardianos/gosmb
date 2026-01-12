package krb5

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"
)

// testClientAuth is a simple client authenticator for testing.
type testClientAuth struct {
	users map[string]string // principal -> password
}

func (a *testClientAuth) Authenticate(principal, realm string) (string, error) {
	if pw, ok := a.users[principal]; ok {
		return pw, nil
	}
	return "", fmt.Errorf("user not found: %s", principal)
}

func TestKDCBasic(t *testing.T) {
	// Create KDC
	kdc, err := NewKDC(KDCConfig{
		Realm:      "TEST.LOCAL",
		ListenAddr: "127.0.0.1:0", // Random port
		ClientAuth: &testClientAuth{
			users: map[string]string{
				"testuser": "testpassword",
			},
		},
		Services: map[string]string{
			"cifs/server.test.local": "service-password",
		},
		Logger: log.New(os.Stderr, "", log.LstdFlags),
	})
	if err != nil {
		t.Fatalf("NewKDC: %v", err)
	}

	// Start KDC
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		kdc.Wait()
	}()
	if err := kdc.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := kdc.Ready(ctx); err != nil {
		t.Fatalf("KDC not ready: %v", err)
	}

	t.Logf("KDC listening on %s", kdc.Addr())

	// Create client
	client := NewClient("testuser", "TEST.LOCAL", "testpassword", kdc.Addr())

	// Get service ticket
	ticket, sessionKey, err := client.GetServiceTicket("cifs/server.test.local")
	if err != nil {
		t.Fatalf("GetServiceTicket: %v", err)
	}

	t.Logf("Got service ticket, session key type: %d, length: %d",
		sessionKey.KeyType, len(sessionKey.KeyValue))

	if ticket == nil {
		t.Fatal("ticket is empty")
	}
	if len(sessionKey.KeyValue) == 0 {
		t.Fatal("session key is empty")
	}
}

func TestKDCFullFlow(t *testing.T) {
	// This tests the complete flow:
	// 1. Client gets TGT from KDC
	// 2. Client gets service ticket from KDC
	// 3. Client creates AP-REQ
	// 4. Service validates AP-REQ

	realm := "EXAMPLE.COM"
	clientPrincipal := "alice"
	clientPassword := "alice-password"
	servicePrincipal := "cifs/fileserver.example.com"
	servicePassword := "service-secret"

	// Start KDC
	kdc, err := NewKDC(KDCConfig{
		Realm:      realm,
		ListenAddr: "127.0.0.1:0",
		ClientAuth: &testClientAuth{
			users: map[string]string{
				clientPrincipal: clientPassword,
			},
		},
		Services: map[string]string{
			servicePrincipal: servicePassword,
		},
		TicketLifetime: 1 * time.Hour,
		Logger:         log.New(os.Stderr, "", log.LstdFlags),
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
		t.Fatalf("Start: %v", err)
	}
	if err := kdc.Ready(ctx); err != nil {
		t.Fatalf("KDC not ready: %v", err)
	}

	t.Logf("KDC started on %s", kdc.Addr())

	// Create client
	client := NewClient(clientPrincipal, realm, clientPassword, kdc.Addr())

	// Get AP-REQ
	apReq, clientSessionKey, err := client.GetAPReq(servicePrincipal)
	if err != nil {
		t.Fatalf("GetAPReq: %v", err)
	}

	t.Logf("Got AP-REQ (%d bytes), client session key type: %d",
		len(apReq), clientSessionKey.KeyType)

	// Create service authenticator
	service, err := NewServiceAuthenticator(ServiceAuthenticatorConfig{
		Principal: servicePrincipal,
		Realm:     realm,
		Password:  servicePassword,
	})
	if err != nil {
		t.Fatalf("NewServiceAuthenticator: %v", err)
	}

	// Validate AP-REQ
	result, err := service.ValidateAPReq(apReq)
	if err != nil {
		t.Fatalf("ValidateAPReq: %v", err)
	}

	t.Logf("Authentication successful!")
	t.Logf("  Username: %s", result.Username)
	t.Logf("  Realm: %s", result.Realm)
	t.Logf("  Session key type: %d", result.SessionKey.KeyType)
	t.Logf("  AP-REP length: %d", len(result.APRep))

	// Verify results
	if result.Username != clientPrincipal {
		t.Errorf("Username = %q, want %q", result.Username, clientPrincipal)
	}
	if result.Realm != realm {
		t.Errorf("Realm = %q, want %q", result.Realm, realm)
	}
	if len(result.SessionKey.KeyValue) == 0 {
		t.Error("SessionKey is empty")
	}
	if len(result.APRep) == 0 {
		t.Error("AP-REP is empty (should have mutual auth)")
	}
}

func TestKDCInvalidUser(t *testing.T) {
	kdc, err := NewKDC(KDCConfig{
		Realm:      "TEST.LOCAL",
		ListenAddr: "127.0.0.1:0",
		ClientAuth: &testClientAuth{
			users: map[string]string{
				"validuser": "password",
			},
		},
		Services: map[string]string{},
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
		t.Fatalf("Start: %v", err)
	}
	if err := kdc.Ready(ctx); err != nil {
		t.Fatalf("KDC not ready: %v", err)
	}

	// Try to authenticate with invalid user
	client := NewClient("invaliduser", "TEST.LOCAL", "wrongpassword", kdc.Addr())

	_, _, err = client.GetServiceTicket("some/service")
	if err == nil {
		t.Fatal("expected error for invalid user")
	}

	t.Logf("Got expected error: %v", err)
}

func TestKDCInvalidPassword(t *testing.T) {
	kdc, err := NewKDC(KDCConfig{
		Realm:      "TEST.LOCAL",
		ListenAddr: "127.0.0.1:0",
		ClientAuth: &testClientAuth{
			users: map[string]string{
				"testuser": "correctpassword",
			},
		},
		Services: map[string]string{
			"test/service": "svc-password",
		},
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
		t.Fatalf("Start: %v", err)
	}
	if err := kdc.Ready(ctx); err != nil {
		t.Fatalf("KDC not ready: %v", err)
	}

	// Try to authenticate with wrong password
	client := NewClient("testuser", "TEST.LOCAL", "wrongpassword", kdc.Addr())

	_, _, err = client.GetServiceTicket("test/service")
	if err == nil {
		t.Fatal("expected error for wrong password")
	}

	t.Logf("Got expected error: %v", err)
}

func TestCryptoRoundtrip(t *testing.T) {
	// Test encryption/decryption roundtrip
	key, err := GenerateSessionKey(ETypeAES256SHA1)
	if err != nil {
		t.Fatalf("GenerateSessionKey: %v", err)
	}

	plaintext := []byte("Hello, Kerberos! This is a test message.")

	encrypted, err := Encrypt(key, 1, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	decrypted, err := Decrypt(key, 1, encrypted)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestKeyDerivation(t *testing.T) {
	// Test that key derivation is deterministic
	key1, err := DeriveKey(ETypeAES256SHA1, "password", "user", "REALM")
	if err != nil {
		t.Fatalf("DeriveKey 1: %v", err)
	}

	key2, err := DeriveKey(ETypeAES256SHA1, "password", "user", "REALM")
	if err != nil {
		t.Fatalf("DeriveKey 2: %v", err)
	}

	if string(key1) != string(key2) {
		t.Error("Key derivation is not deterministic")
	}

	// Different inputs should produce different keys
	key3, _ := DeriveKey(ETypeAES256SHA1, "different", "user", "REALM")
	if string(key1) == string(key3) {
		t.Error("Different passwords produced same key")
	}
}

func TestServiceAuthenticatorConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ServiceAuthenticatorConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: ServiceAuthenticatorConfig{
				Principal: "cifs/server",
				Realm:     "EXAMPLE.COM",
				Password:  "secret",
			},
			wantErr: false,
		},
		{
			name: "missing principal",
			cfg: ServiceAuthenticatorConfig{
				Realm:    "EXAMPLE.COM",
				Password: "secret",
			},
			wantErr: true,
		},
		{
			name: "missing realm",
			cfg: ServiceAuthenticatorConfig{
				Principal: "cifs/server",
				Password:  "secret",
			},
			wantErr: true,
		},
		{
			name: "missing password",
			cfg: ServiceAuthenticatorConfig{
				Principal: "cifs/server",
				Realm:     "EXAMPLE.COM",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewServiceAuthenticator(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewServiceAuthenticator() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
