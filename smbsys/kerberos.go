package smbsys

import (
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/service"
	"github.com/jcmturner/gokrb5/v8/types"
)

// KerberosConfig configures Kerberos authentication for the SMB server.
//
// For Kerberos to work, you need:
//   - A KDC (Key Distribution Center) - Active Directory or MIT Kerberos
//   - A service principal for your SMB server (e.g., cifs/server.example.com@REALM)
//   - The service principal's password or keytab
//
// Example configuration:
//
//	cfg := KerberosConfig{
//	    ServicePrincipal: "cifs/fileserver.example.com",
//	    Realm:            "EXAMPLE.COM",
//	    Password:         "service-account-password",
//	}
type KerberosConfig struct {
	// ServicePrincipal is the Kerberos principal name for this SMB service.
	// Format: "cifs/hostname" (without the realm suffix).
	// Example: "cifs/fileserver.example.com"
	ServicePrincipal string

	// Realm is the Kerberos realm (typically uppercase domain name).
	// Example: "EXAMPLE.COM"
	Realm string

	// Password is the service principal's password.
	// Either Password or KeytabBytes must be set.
	Password string

	// KeytabBytes contains a keytab file's contents.
	// Use this instead of Password if you have an existing keytab.
	// Either Password or KeytabBytes must be set.
	KeytabBytes []byte
}

// NewKerberosAuthenticator creates a KerberosAuthenticator from configuration.
// This creates all necessary cryptographic keys in memory.
func NewKerberosAuthenticator(cfg KerberosConfig) (KerberosAuthenticator, error) {
	if cfg.ServicePrincipal == "" {
		return nil, fmt.Errorf("ServicePrincipal is required")
	}
	if cfg.Realm == "" {
		return nil, fmt.Errorf("Realm is required")
	}

	var kt *keytab.Keytab

	if len(cfg.KeytabBytes) > 0 {
		// Load from provided keytab bytes
		kt = keytab.New()
		if err := kt.Unmarshal(cfg.KeytabBytes); err != nil {
			return nil, fmt.Errorf("parse keytab: %w", err)
		}
	} else if cfg.Password != "" {
		// Create keytab from password
		kt = keytab.New()

		// Add entries for common encryption types (strongest first)
		// Windows and modern clients prefer AES256
		etypes := []int32{
			etypeID.AES256_CTS_HMAC_SHA1_96,
			etypeID.AES128_CTS_HMAC_SHA1_96,
			etypeID.RC4_HMAC, // For older Windows clients
		}

		for _, etype := range etypes {
			err := kt.AddEntry(cfg.ServicePrincipal, cfg.Realm, cfg.Password, time.Now(), 1, etype)
			if err != nil {
				return nil, fmt.Errorf("add keytab entry for etype %d: %w", etype, err)
			}
		}
	} else {
		return nil, fmt.Errorf("either Password or KeytabBytes must be provided")
	}

	settings := service.NewSettings(kt, service.Logger(nil))

	return &keytabAuthenticator{
		keytab:           kt,
		settings:         settings,
		servicePrincipal: cfg.ServicePrincipal,
		realm:            cfg.Realm,
	}, nil
}

// keytabAuthenticator implements KerberosAuthenticator using a keytab.
type keytabAuthenticator struct {
	keytab           *keytab.Keytab
	settings         *service.Settings
	servicePrincipal string
	realm            string
}

// ValidateAPReq validates a Kerberos AP-REQ and returns the authentication result.
func (a *keytabAuthenticator) ValidateAPReq(apReqBytes []byte) (*KerberosAuthResult, error) {
	// Decode AP-REQ
	var apReq messages.APReq
	if err := apReq.Unmarshal(apReqBytes); err != nil {
		return nil, fmt.Errorf("unmarshal AP-REQ: %w", err)
	}

	// Verify the AP-REQ (this decrypts the ticket and authenticator)
	ok, creds, err := service.VerifyAPREQ(&apReq, a.settings)
	if err != nil {
		return nil, fmt.Errorf("verify AP-REQ: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("AP-REQ verification failed")
	}

	// Extract username (without realm)
	username := creds.UserName()

	// Get session key from the decrypted ticket
	ticketSessionKey := apReq.Ticket.DecryptedEncPart.Key

	// Build AP-REP using the ticket session key (for encrypting the reply)
	apRepBytes, err := buildAPRep(&apReq, ticketSessionKey)
	if err != nil {
		return nil, fmt.Errorf("build AP-REP: %w", err)
	}

	// Determine the session key for SMB signing:
	// - If the authenticator contains a subkey, use it (per RFC 4121)
	// - Otherwise, use the ticket's session key
	smbSessionKey := ticketSessionKey.KeyValue
	if apReq.Authenticator.SubKey.KeyType != 0 {
		smbSessionKey = apReq.Authenticator.SubKey.KeyValue
	}

	return &KerberosAuthResult{
		Username:   username,
		SessionKey: smbSessionKey,
		APRep:      apRepBytes,
	}, nil
}

// SPNEGOConfig returns the SPNEGO configuration for this authenticator.
func (a *keytabAuthenticator) SPNEGOConfig() *SPNEGOConfig {
	return &SPNEGOConfig{
		ServicePrincipal: a.servicePrincipal,
		Realm:            a.realm,
	}
}

// Ensure keytabAuthenticator implements KerberosAuthenticator
var _ KerberosAuthenticator = (*keytabAuthenticator)(nil)

// ASN.1 marshaling helpers for AP-REP construction

// encAPRepPartASN1 is the ASN.1 structure for marshaling EncAPRepPart.
type encAPRepPartASN1 struct {
	CTime          asn1.RawValue `asn1:"explicit,tag:0"`
	Cusec          int           `asn1:"explicit,tag:1"`
	Subkey         asn1.RawValue `asn1:"optional,explicit,tag:2"`
	SequenceNumber int64         `asn1:"optional,explicit,tag:3"`
}

// apRepASN1 is the ASN.1 structure for marshaling APRep.
type apRepASN1 struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	EncPart asn1.RawValue `asn1:"explicit,tag:2"`
}

// buildAPRep creates an AP-REP message.
func buildAPRep(apReq *messages.APReq, sessionKey types.EncryptionKey) ([]byte, error) {
	encPart := messages.EncAPRepPart{
		CTime: apReq.Authenticator.CTime,
		Cusec: apReq.Authenticator.Cusec,
	}

	if apReq.Authenticator.SubKey.KeyType != 0 {
		encPart.Subkey = apReq.Authenticator.SubKey
	}
	if apReq.Authenticator.SeqNumber != 0 {
		encPart.SequenceNumber = apReq.Authenticator.SeqNumber
	}

	encPartBytes, err := marshalEncAPRepPart(encPart)
	if err != nil {
		return nil, fmt.Errorf("marshal EncAPRepPart: %w", err)
	}

	encryptedData, err := crypto.GetEncryptedData(encPartBytes, sessionKey, uint32(keyusage.AP_REP_ENCPART), 0)
	if err != nil {
		return nil, fmt.Errorf("encrypt AP-REP: %w", err)
	}

	return marshalAPRep(encryptedData)
}

func marshalEncAPRepPart(e messages.EncAPRepPart) ([]byte, error) {
	ctime, err := asn1.MarshalWithParams(e.CTime, "generalized")
	if err != nil {
		return nil, err
	}

	asn1Part := encAPRepPartASN1{
		CTime: asn1.RawValue{FullBytes: ctime},
		Cusec: e.Cusec,
	}

	if e.Subkey.KeyType != 0 {
		subkeyBytes, err := marshalEncryptionKey(e.Subkey)
		if err != nil {
			return nil, err
		}
		asn1Part.Subkey = asn1.RawValue{FullBytes: subkeyBytes}
	}

	if e.SequenceNumber != 0 {
		asn1Part.SequenceNumber = e.SequenceNumber
	}

	inner, err := asn1.Marshal(asn1Part)
	if err != nil {
		return nil, err
	}

	// Wrap in APPLICATION 27 tag (EncAPRepPart)
	wrapped := asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        27,
		IsCompound: true,
		Bytes:      inner,
	}
	return asn1.Marshal(wrapped)
}

func marshalEncryptionKey(key types.EncryptionKey) ([]byte, error) {
	type encryptionKeyASN1 struct {
		KeyType  int32  `asn1:"explicit,tag:0"`
		KeyValue []byte `asn1:"explicit,tag:1"`
	}
	return asn1.Marshal(encryptionKeyASN1{
		KeyType:  key.KeyType,
		KeyValue: key.KeyValue,
	})
}

func marshalEncryptedData(e types.EncryptedData) ([]byte, error) {
	type encryptedDataASN1 struct {
		EType  int32  `asn1:"explicit,tag:0"`
		KVNO   int    `asn1:"optional,explicit,tag:1"`
		Cipher []byte `asn1:"explicit,tag:2"`
	}
	return asn1.Marshal(encryptedDataASN1{
		EType:  e.EType,
		KVNO:   e.KVNO,
		Cipher: e.Cipher,
	})
}

func marshalAPRep(encPart types.EncryptedData) ([]byte, error) {
	encPartBytes, err := marshalEncryptedData(encPart)
	if err != nil {
		return nil, err
	}

	rep := apRepASN1{
		PVNO:    5,
		MsgType: msgtype.KRB_AP_REP,
		EncPart: asn1.RawValue{FullBytes: encPartBytes},
	}

	inner, err := asn1.Marshal(rep)
	if err != nil {
		return nil, err
	}

	// Wrap in APPLICATION 15 tag (AP-REP)
	wrapped := asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        15,
		IsCompound: true,
		Bytes:      inner,
	}
	return asn1.Marshal(wrapped)
}
