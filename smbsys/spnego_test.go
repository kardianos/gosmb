package smbsys

import (
	"bytes"
	"encoding/asn1"
	"testing"
)

func TestSPNEGOTokenRoundtrip(t *testing.T) {
	// Build a synthetic SPNEGO negTokenInit with Kerberos
	// This tests our encoding/decoding logic without needing real Kerberos

	// Fake AP-REQ data (just some bytes for testing)
	fakeAPReq := []byte{0x6e, 0x82, 0x01, 0x00} // APPLICATION 14 (AP-REQ) header + some bytes

	// Wrap in GSSAPI Kerberos framing
	mechToken := wrapKerberosToken(oidKerberos5, 0x01, 0x00, fakeAPReq)

	// Build negTokenInit
	negToken := negTokenInit{
		MechTypes: []asn1.ObjectIdentifier{oidKerberos5},
		MechToken: mechToken,
	}

	negTokenBytes, err := asn1.Marshal(negToken)
	if err != nil {
		t.Fatalf("marshal negTokenInit: %v", err)
	}

	// Wrap in context tag [0]
	innerWrapped := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      negTokenBytes,
	}

	innerBytes, err := asn1.Marshal(innerWrapped)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}

	// Build GSSAPI wrapper
	oidBytes, _ := asn1.Marshal(oidSPNEGO)
	gssInner := append(oidBytes, innerBytes...)

	gssToken := asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        0,
		IsCompound: true,
		Bytes:      gssInner,
	}

	spnegoBlob, err := asn1.Marshal(gssToken)
	if err != nil {
		t.Fatalf("marshal GSSAPI: %v", err)
	}

	// Now decode it back
	mechOID, apReq, err := decodeNegTokenInit(spnegoBlob)
	if err != nil {
		t.Fatalf("decodeNegTokenInit: %v", err)
	}

	if !mechOID.Equal(oidKerberos5) {
		t.Errorf("expected Kerberos OID, got %v", mechOID)
	}

	if !bytes.Equal(apReq, fakeAPReq) {
		t.Errorf("AP-REQ mismatch: got %x, want %x", apReq, fakeAPReq)
	}
}

func TestSPNEGONegTokenResp(t *testing.T) {
	fakeAPRep := []byte{0x6f, 0x82, 0x00, 0x50} // APPLICATION 15 (AP-REP) header

	respBlob, err := encodeNegTokenResp(spnegoAcceptCompleted, oidKerberos5, fakeAPRep)
	if err != nil {
		t.Fatalf("encodeNegTokenResp: %v", err)
	}

	// Verify it's valid ASN.1 and has the right structure
	var rawResp asn1.RawValue
	rest, err := asn1.Unmarshal(respBlob, &rawResp)
	if err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(rest) > 0 {
		t.Errorf("trailing data: %x", rest)
	}

	// Should be context tag [1] for negTokenResp
	if rawResp.Class != asn1.ClassContextSpecific || rawResp.Tag != 1 {
		t.Errorf("expected context tag 1, got class=%d tag=%d", rawResp.Class, rawResp.Tag)
	}

	// Decode the inner negTokenResp
	var resp negTokenResp
	_, err = asn1.Unmarshal(rawResp.Bytes, &resp)
	if err != nil {
		t.Fatalf("unmarshal negTokenResp: %v", err)
	}

	if resp.NegState != spnegoAcceptCompleted {
		t.Errorf("expected state %d, got %d", spnegoAcceptCompleted, resp.NegState)
	}

	if !resp.SupportedMech.Equal(oidKerberos5) {
		t.Errorf("expected Kerberos OID, got %v", resp.SupportedMech)
	}

	// The response token should contain our wrapped AP-REP
	if len(resp.ResponseToken) == 0 {
		t.Error("expected non-empty response token")
	}
}

func TestUnwrapKerberosToken(t *testing.T) {
	testData := []byte{0xde, 0xad, 0xbe, 0xef}

	// Wrap with AP-REQ token ID
	wrapped := wrapKerberosToken(oidKerberos5, 0x01, 0x00, testData)

	unwrapped, err := unwrapKerberosToken(wrapped)
	if err != nil {
		t.Fatalf("unwrapKerberosToken: %v", err)
	}

	if !bytes.Equal(unwrapped, testData) {
		t.Errorf("data mismatch: got %x, want %x", unwrapped, testData)
	}
}

func TestSPNEGOUnsupportedMech(t *testing.T) {
	// Build a negTokenInit with only NTLM (which we don't support)
	ntlmOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

	negToken := negTokenInit{
		MechTypes: []asn1.ObjectIdentifier{ntlmOID},
		MechToken: []byte{0x01, 0x02, 0x03},
	}

	negTokenBytes, _ := asn1.Marshal(negToken)

	innerWrapped := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      negTokenBytes,
	}
	innerBytes, _ := asn1.Marshal(innerWrapped)

	oidBytes, _ := asn1.Marshal(oidSPNEGO)
	gssInner := append(oidBytes, innerBytes...)

	gssToken := asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        0,
		IsCompound: true,
		Bytes:      gssInner,
	}

	spnegoBlob, _ := asn1.Marshal(gssToken)

	_, _, err := decodeNegTokenInit(spnegoBlob)
	if err != ErrUnsupportedMech {
		t.Errorf("expected ErrUnsupportedMech, got %v", err)
	}
}

func TestKerberosConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     KerberosConfig
		wantErr string
	}{
		{
			name:    "missing service principal",
			cfg:     KerberosConfig{Realm: "EXAMPLE.COM", Password: "test"},
			wantErr: "ServicePrincipal is required",
		},
		{
			name:    "missing realm",
			cfg:     KerberosConfig{ServicePrincipal: "cifs/server", Password: "test"},
			wantErr: "Realm is required",
		},
		{
			name:    "missing password",
			cfg:     KerberosConfig{ServicePrincipal: "cifs/server", Realm: "EXAMPLE.COM"},
			wantErr: "Password is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewKerberosAuthenticator(tt.cfg)
			if err == nil {
				t.Fatal("expected error")
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestKerberosConfigWithPassword(t *testing.T) {
	// Test that we can create an authenticator from a password
	cfg := KerberosConfig{
		ServicePrincipal: "cifs/server.example.com",
		Realm:            "EXAMPLE.COM",
		Password:         "test-password",
	}

	auth, err := NewKerberosAuthenticator(cfg)
	if err != nil {
		t.Fatalf("NewKerberosAuthenticator: %v", err)
	}

	if auth == nil {
		t.Fatal("authenticator is nil")
	}
}
