package smbsys

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// SPNEGO and Kerberos OIDs
var (
	// SPNEGO OID: 1.3.6.1.5.5.2
	oidSPNEGO = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

	// Kerberos 5 OID: 1.2.840.113554.1.2.2
	oidKerberos5 = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}

	// MS-Kerberos OID: 1.2.840.48018.1.2.2
	oidMSKerberos5 = asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
)

// SPNEGO errors
var (
	ErrSPNEGODecode       = errors.New("failed to decode SPNEGO token")
	ErrUnsupportedMech    = errors.New("unsupported SPNEGO mechanism")
	ErrKerberosValidation = errors.New("Kerberos validation failed")
	ErrNoKerberos         = errors.New("Kerberos authenticator not configured")
)

// KerberosAuthenticator handles Kerberos authentication.
// Implement this interface to enable Kerberos/SPNEGO authentication.
type KerberosAuthenticator interface {
	// ValidateAPReq validates a Kerberos AP-REQ and returns authentication result.
	// Returns the client principal name, session key, AP-REP token, and any error.
	ValidateAPReq(apReq []byte) (*KerberosAuthResult, error)

	// SPNEGOConfig returns the SPNEGO configuration parameters needed for
	// the kernel to advertise Kerberos support during SMB negotiation.
	// Returns the service principal and realm.
	SPNEGOConfig() *SPNEGOConfig
}

// SPNEGOConfig contains the SPNEGO/Kerberos configuration for the SMB server.
// This is used to configure the kernel module to advertise Kerberos support.
type SPNEGOConfig struct {
	// ServicePrincipal is the Kerberos service principal name.
	// Example: "cifs/fileserver.example.com"
	ServicePrincipal string

	// Realm is the Kerberos realm (uppercase).
	// Example: "EXAMPLE.COM"
	Realm string
}

// KerberosAuthResult contains the result of Kerberos authentication.
type KerberosAuthResult struct {
	// Username is the client principal name (without realm).
	Username string

	// SessionKey is the session key for SMB encryption/signing.
	SessionKey []byte

	// APRep is the AP-REP token to send back to the client.
	APRep []byte
}

// SPNEGO ASN.1 structures

// negTokenInit is the initial SPNEGO token from the client.
// RFC 4178 Section 4.2.1
type negTokenInit struct {
	MechTypes    []asn1.ObjectIdentifier `asn1:"explicit,tag:0,optional"`
	ReqFlags     asn1.BitString          `asn1:"explicit,tag:1,optional"`
	MechToken    []byte                  `asn1:"explicit,tag:2,optional"`
	MechListMIC  []byte                  `asn1:"explicit,tag:3,optional"`
}

// negTokenResp is the response token sent back to the client.
// RFC 4178 Section 4.2.2
type negTokenResp struct {
	NegState      asn1.Enumerated         `asn1:"explicit,tag:0,optional"`
	SupportedMech asn1.ObjectIdentifier   `asn1:"explicit,tag:1,optional"`
	ResponseToken []byte                  `asn1:"explicit,tag:2,optional"`
	MechListMIC   []byte                  `asn1:"explicit,tag:3,optional"`
}

// SPNEGO negotiation states
const (
	spnegoAcceptCompleted  = 0
	spnegoAcceptIncomplete = 1
	spnegoReject           = 2
	spnegoRequestMIC       = 3
)

// gssAPIToken wraps the SPNEGO token in GSSAPI framing.
type gssAPIToken struct {
	OID   asn1.ObjectIdentifier
	Inner asn1.RawValue
}

// decodeNegTokenInit decodes a GSSAPI/SPNEGO negTokenInit from the client.
// Returns the mechanism type and the mechanism token (e.g., AP-REQ for Kerberos).
func decodeNegTokenInit(blob []byte) (mechOID asn1.ObjectIdentifier, mechToken []byte, err error) {
	// The blob is a GSSAPI token: [APPLICATION 0] { OID, negTokenInit }
	var gss gssAPIToken
	rest, err := asn1.UnmarshalWithParams(blob, &gss, "application,tag:0")
	if err != nil {
		return nil, nil, fmt.Errorf("decode GSSAPI wrapper: %w", err)
	}
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("trailing data after GSSAPI token")
	}

	// Verify SPNEGO OID
	if !gss.OID.Equal(oidSPNEGO) {
		return nil, nil, fmt.Errorf("expected SPNEGO OID, got %v", gss.OID)
	}

	// The inner value is [0] negTokenInit
	if gss.Inner.Tag != 0 || gss.Inner.Class != asn1.ClassContextSpecific {
		return nil, nil, fmt.Errorf("expected context tag 0 for negTokenInit")
	}

	var negToken negTokenInit
	_, err = asn1.Unmarshal(gss.Inner.Bytes, &negToken)
	if err != nil {
		return nil, nil, fmt.Errorf("decode negTokenInit: %w", err)
	}

	if len(negToken.MechTypes) == 0 {
		return nil, nil, fmt.Errorf("no mechanism types in negTokenInit")
	}

	// Find a supported mechanism (prefer Kerberos 5, accept MS-Kerberos)
	var selectedMech asn1.ObjectIdentifier
	for _, mech := range negToken.MechTypes {
		if mech.Equal(oidKerberos5) || mech.Equal(oidMSKerberos5) {
			selectedMech = mech
			break
		}
	}

	if selectedMech == nil {
		return nil, nil, ErrUnsupportedMech
	}

	// The mechToken contains the Kerberos AP-REQ wrapped in GSSAPI
	if len(negToken.MechToken) == 0 {
		return nil, nil, fmt.Errorf("no mechanism token in negTokenInit")
	}

	// Unwrap the Kerberos token from GSSAPI framing
	apReq, err := unwrapKerberosToken(negToken.MechToken)
	if err != nil {
		return nil, nil, fmt.Errorf("unwrap Kerberos token: %w", err)
	}

	return selectedMech, apReq, nil
}

// unwrapKerberosToken removes the GSSAPI wrapper from a Kerberos token.
// Input: [APPLICATION 0] { OID(Kerberos), token-id(0x01 0x00), AP-REQ }
//
// Note: The Kerberos token format isn't standard ASN.1 - the token-id and AP-REQ
// are raw bytes following the OID, not proper ASN.1 elements. We parse manually.
func unwrapKerberosToken(blob []byte) ([]byte, error) {
	// Parse APPLICATION 0 wrapper
	var wrapper asn1.RawValue
	rest, err := asn1.Unmarshal(blob, &wrapper)
	if err != nil {
		return nil, fmt.Errorf("decode GSSAPI wrapper: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("trailing data after Kerberos token")
	}
	if wrapper.Class != asn1.ClassApplication || wrapper.Tag != 0 {
		return nil, fmt.Errorf("expected APPLICATION 0, got class=%d tag=%d", wrapper.Class, wrapper.Tag)
	}

	// Parse OID from the content
	content := wrapper.Bytes
	var oid asn1.ObjectIdentifier
	rest, err = asn1.Unmarshal(content, &oid)
	if err != nil {
		return nil, fmt.Errorf("decode OID: %w", err)
	}

	// Verify Kerberos OID
	if !oid.Equal(oidKerberos5) && !oid.Equal(oidMSKerberos5) {
		return nil, fmt.Errorf("expected Kerberos OID, got %v", oid)
	}

	// The remaining bytes are: token-id (2 bytes) + AP-REQ
	if len(rest) < 2 {
		return nil, fmt.Errorf("Kerberos token too short")
	}
	if rest[0] != 0x01 || rest[1] != 0x00 {
		return nil, fmt.Errorf("unexpected Kerberos token ID: %02x %02x", rest[0], rest[1])
	}

	// The rest is the AP-REQ
	return rest[2:], nil
}

// encodeNegTokenResp creates a SPNEGO negTokenResp (response to client).
func encodeNegTokenResp(state int, mechOID asn1.ObjectIdentifier, apRep []byte) ([]byte, error) {
	// For GSSAPI-based SPNEGO with Kerberos, the responseToken contains the AP-REP
	// wrapped in GSSAPI framing. Always use the standard Kerberos 5 OID for the
	// response, regardless of whether the client used MS-Kerberos OID.
	var responseToken []byte
	if len(apRep) > 0 {
		responseToken = wrapKerberosToken(oidKerberos5, 0x02, 0x00, apRep)
	}

	resp := negTokenResp{
		NegState:      asn1.Enumerated(state),
		SupportedMech: mechOID,
		ResponseToken: responseToken,
	}

	respBytes, err := asn1.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal negTokenResp: %w", err)
	}

	// Wrap in context tag [1] for negTokenResp
	wrapped := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        1,
		IsCompound: true,
		Bytes:      respBytes,
	}

	return asn1.Marshal(wrapped)
}

// wrapKerberosToken wraps a Kerberos token in GSSAPI framing.
func wrapKerberosToken(oid asn1.ObjectIdentifier, tokenID1, tokenID2 byte, token []byte) []byte {
	// Encode OID
	oidBytes, _ := asn1.Marshal(oid)

	// Build inner content: OID + token-id + token
	inner := make([]byte, 0, len(oidBytes)+2+len(token))
	inner = append(inner, oidBytes...)
	inner = append(inner, tokenID1, tokenID2)
	inner = append(inner, token...)

	// Wrap in APPLICATION 0
	wrapped := asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        0,
		IsCompound: true,
		Bytes:      inner,
	}

	result, _ := asn1.Marshal(wrapped)
	return result
}
