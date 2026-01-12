package krb5

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// ServiceAuthenticator validates Kerberos AP-REQs for a service.
// This implements the interface needed by smbsys for Kerberos authentication.
type ServiceAuthenticator struct {
	principal string
	realm     string
	key       []byte
	etype     int32
}

// ServiceAuthenticatorConfig configures a service authenticator.
type ServiceAuthenticatorConfig struct {
	// Principal is the service principal name (e.g., "cifs/server.example.com").
	Principal string

	// Realm is the Kerberos realm.
	Realm string

	// Password is the service password (used to derive keys).
	Password string
}

// NewServiceAuthenticator creates a new service authenticator.
func NewServiceAuthenticator(cfg ServiceAuthenticatorConfig) (*ServiceAuthenticator, error) {
	if cfg.Principal == "" {
		return nil, fmt.Errorf("principal is required")
	}
	if cfg.Realm == "" {
		return nil, fmt.Errorf("realm is required")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("password is required")
	}

	// Derive key from password
	key, err := DeriveKey(ETypeAES256SHA1, cfg.Password, cfg.Principal, cfg.Realm)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	return &ServiceAuthenticator{
		principal: cfg.Principal,
		realm:     cfg.Realm,
		key:       key,
		etype:     ETypeAES256SHA1,
	}, nil
}

// ServiceAuthResult contains the result of service authentication.
type ServiceAuthResult struct {
	// Username is the authenticated client's principal name.
	Username string

	// Realm is the client's realm.
	Realm string

	// SessionKey is the session key for the connection.
	SessionKey EncryptionKey

	// APRep is the AP-REP to send back to the client.
	APRep []byte
}

// ValidateAPReq validates an AP-REQ and returns the authentication result.
// This is the method that smbsys calls to authenticate Kerberos clients.
func (s *ServiceAuthenticator) ValidateAPReq(apReqBytes []byte) (*ServiceAuthResult, error) {
	// Parse AP-REQ
	apReq, err := unmarshalAPReq(apReqBytes)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AP-REQ: %w", err)
	}

	// Extract Ticket from RawValue
	ticket, err := unmarshalTicket(apReq.TicketBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ticket from AP-REQ: %w", err)
	}

	// Decrypt ticket
	serviceKey := EncryptionKey{
		KeyType:  s.etype,
		KeyValue: s.key,
	}

	ticketData, err := Decrypt(serviceKey, keyUsageTicket, ticket.EncPart)
	if err != nil {
		return nil, fmt.Errorf("decrypt ticket: %w", err)
	}

	// Unmarshal EncTicketPart
	inner, _, err := unwrapAppTag(ticketData)
	if err != nil {
		return nil, fmt.Errorf("unwrap EncTicketPart: %w", err)
	}

	var encTicket EncTicketPart
	if _, err := asn1.Unmarshal(inner, &encTicket); err != nil {
		return nil, fmt.Errorf("unmarshal EncTicketPart: %w", err)
	}

	// Check ticket expiry
	if time.Now().After(encTicket.EndTime) {
		return nil, fmt.Errorf("ticket expired")
	}

	// Get session key from ticket
	sessionKey := encTicket.Key

	// Decrypt authenticator
	authData, err := Decrypt(sessionKey, keyUsageAPReqAuth, apReq.Auth)
	if err != nil {
		return nil, fmt.Errorf("decrypt authenticator: %w", err)
	}

	// Unmarshal authenticator
	authInner, _, err := unwrapAppTag(authData)
	if err != nil {
		return nil, fmt.Errorf("unwrap authenticator: %w", err)
	}

	var auth Authenticator
	if _, err := asn1.Unmarshal(authInner, &auth); err != nil {
		return nil, fmt.Errorf("unmarshal authenticator: %w", err)
	}

	// Verify authenticator matches ticket
	if auth.CRealm != encTicket.CRealm {
		return nil, fmt.Errorf("realm mismatch in authenticator")
	}
	if auth.CName.String() != encTicket.CName.String() {
		return nil, fmt.Errorf("client name mismatch in authenticator")
	}

	// Check authenticator timestamp (within 5 minutes)
	diff := time.Since(auth.CTime)
	if diff < 0 {
		diff = -diff
	}
	if diff > 5*time.Minute {
		return nil, fmt.Errorf("authenticator timestamp out of range")
	}

	// Build AP-REP if mutual authentication requested
	var apRepBytes []byte
	// MUTUAL-REQUIRED is bit 1 in AP-OPTIONS
	mutualRequired := len(apReq.APOptions.Bytes) > 0 && (apReq.APOptions.Bytes[0]&0x20) != 0
	if mutualRequired {
		apRepBytes, err = s.buildAPRep(auth, sessionKey)
		if err != nil {
			return nil, fmt.Errorf("build AP-REP: %w", err)
		}
	}

	// Determine the session key for SMB signing (per RFC 4121):
	// - If the authenticator contains a subkey, use it
	// - Otherwise, use the ticket's session key
	smbSessionKey := sessionKey
	if auth.SubKey.KeyType != 0 && len(auth.SubKey.KeyValue) > 0 {
		smbSessionKey = auth.SubKey
	}

	return &ServiceAuthResult{
		Username:   encTicket.CName.String(),
		Realm:      encTicket.CRealm,
		SessionKey: smbSessionKey,
		APRep:      apRepBytes,
	}, nil
}

func (s *ServiceAuthenticator) buildAPRep(auth Authenticator, sessionKey EncryptionKey) ([]byte, error) {
	// Build EncAPRepPart
	encPart := EncAPRepPart{
		CTime: auth.CTime,
		CUSec: auth.CUSec,
	}

	// Include subkey if client sent one
	if auth.SubKey.KeyType != 0 {
		encPart.SubKey = auth.SubKey
	}

	encPartBytes, err := marshalEncAPRepPart(encPart)
	if err != nil {
		return nil, fmt.Errorf("marshal EncAPRepPart: %w", err)
	}

	// Encrypt with session key
	encData, err := Encrypt(sessionKey, keyUsageAPRepEncPart, encPartBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt AP-REP: %w", err)
	}

	// Build AP-REP
	apRep := APRep{
		PVNO:    5,
		MsgType: msgTypeAPRep,
		EncPart: encData,
	}

	return marshalAPRep(apRep)
}

// KerberosAuthResult is an alias for ServiceAuthResult for compatibility with smbsys.
// This allows ServiceAuthenticator to be used directly with smbsys.KerberosAuthenticator.
type KerberosAuthResult = ServiceAuthResult

// SMBKerberosAuthenticator wraps ServiceAuthenticator to implement
// the smbsys.KerberosAuthenticator interface.
//
// Usage with smbsys:
//
//	auth := krb5.NewSMBKerberosAuthenticator(krb5.ServiceAuthenticatorConfig{
//	    Principal: "cifs/server.example.com",
//	    Realm:     "EXAMPLE.COM",
//	    Password:  "service-password",
//	})
//	sys, _ := smbsys.New(smbsys.SysOpt{
//	    KerberosAuthenticator: auth,
//	    // ... other options
//	})
type SMBKerberosAuthenticator struct {
	service   *ServiceAuthenticator
	principal string
	realm     string
}

// SMBSPNEGOConfig contains SPNEGO configuration for SMB servers.
type SMBSPNEGOConfig struct {
	ServicePrincipal string
	Realm            string
}

// SMBKerberosAuthResult matches the smbsys.KerberosAuthResult interface.
// This is returned by ValidateAPReq.
type SMBKerberosAuthResult struct {
	Username   string
	SessionKey []byte
	APRep      []byte
}

// NewSMBKerberosAuthenticator creates a Kerberos authenticator for use with smbsys.
func NewSMBKerberosAuthenticator(cfg ServiceAuthenticatorConfig) (*SMBKerberosAuthenticator, error) {
	svc, err := NewServiceAuthenticator(cfg)
	if err != nil {
		return nil, err
	}
	return &SMBKerberosAuthenticator{
		service:   svc,
		principal: cfg.Principal,
		realm:     cfg.Realm,
	}, nil
}

// ValidateAPReq implements the smbsys.KerberosAuthenticator interface.
// Note: The return type is interface-compatible with smbsys.KerberosAuthResult.
func (a *SMBKerberosAuthenticator) ValidateAPReq(apReqBytes []byte) (*SMBKerberosAuthResult, error) {
	result, err := a.service.ValidateAPReq(apReqBytes)
	if err != nil {
		return nil, err
	}

	return &SMBKerberosAuthResult{
		Username:   result.Username,
		SessionKey: result.SessionKey.KeyValue,
		APRep:      result.APRep,
	}, nil
}

// SPNEGOConfig returns the SPNEGO configuration for this authenticator.
func (a *SMBKerberosAuthenticator) SPNEGOConfig() *SMBSPNEGOConfig {
	return &SMBSPNEGOConfig{
		ServicePrincipal: a.principal,
		Realm:            a.realm,
	}
}
