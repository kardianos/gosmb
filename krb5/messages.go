// Package krb5 implements a minimal Kerberos 5 KDC for testing purposes.
//
// This package provides a Key Distribution Center (KDC) that can issue
// Ticket Granting Tickets (TGTs) and service tickets for Kerberos authentication.
// It is designed for testing SMB Kerberos authentication without requiring
// external infrastructure.
//
// The KDC listens on port 88 (UDP and TCP) and handles:
//   - AS-REQ/AS-REP: Initial authentication to get a TGT
//   - TGS-REQ/TGS-REP: Exchange TGT for service tickets
package krb5

import (
	"encoding/asn1"
	"fmt"
	"time"
)

// Kerberos protocol version (RFC 4120)
const kerberosVersion = 5

// Kerberos message types (RFC 4120 Section 7.5.7)
const (
	msgTypeASReq  = 10
	msgTypeASRep  = 11
	msgTypeTGSReq = 12
	msgTypeTGSRep = 13
	msgTypeAPReq  = 14
	msgTypeAPRep  = 15
	msgTypeError  = 30
)

// Kerberos APPLICATION tags (RFC 4120)
const (
	appTagTicket        = 1
	appTagAuthenticator = 2
	appTagEncTicketPart = 3
	appTagEncASRepPart  = 25
	appTagEncTGSRepPart = 26
	appTagEncAPRepPart  = 27
)

// Kerberos error codes (RFC 4120 Section 7.5.9)
const (
	errNone            = 0
	errClientNotFound  = 6  // KDC_ERR_C_PRINCIPAL_UNKNOWN
	errServiceNotFound = 7  // KDC_ERR_S_PRINCIPAL_UNKNOWN
	errPreAuthRequired = 25 // KDC_ERR_PREAUTH_REQUIRED
	errPreAuthFailed   = 24 // KDC_ERR_PREAUTH_FAILED
	errBadIntegrity    = 31 // KRB_AP_ERR_BAD_INTEGRITY
	errTicketExpired   = 32 // KRB_AP_ERR_TKT_EXPIRED
	errGeneric         = 60 // KRB_ERR_GENERIC
)

// Pre-authentication types
const (
	paTypeTGSReq       = 1  // PA-TGS-REQ
	paTypeEncTimestamp = 2  // PA-ENC-TIMESTAMP
	paTypeETypeInfo2   = 19 // PA-ETYPE-INFO2
)

// Name types (RFC 4120 Section 7.5.8)
const (
	nameTypePrincipal = 1 // KRB_NT_PRINCIPAL
	nameTypeSrvInst   = 2 // KRB_NT_SRV_INST (service/host)
)

// Key usage numbers (RFC 4120 Section 7.5.1)
const (
	keyUsageASReqTimestamp = 1
	keyUsageTicket         = 2
	keyUsageASRepEncPart   = 3
	keyUsageTGSReqAuth     = 7
	keyUsageTGSRepEncPart  = 8
	keyUsageAPReqAuthCksum = 10
	keyUsageAPReqAuth      = 11
	keyUsageAPRepEncPart   = 12
)

// KDC option flags (RFC 4120 Section 5.4.1)
// These are bit flags used in KDC-OPTIONS and ticket flags.
var (
	// kdcOptionFlags represents FORWARDABLE | RENEWABLE flags
	kdcOptionFlags = []byte{0x40, 0x80, 0x00, 0x00}
	// ticketFlagsInitialPreAuth represents INITIAL | PRE-AUTHENT flags
	ticketFlagsInitialPreAuth = []byte{0x40, 0x80, 0x00, 0x00}
)

// AP option flags (RFC 4120 Section 5.5.1)
var (
	// apOptionsMutualRequired represents the MUTUAL-REQUIRED flag
	apOptionsMutualRequired = []byte{0x20, 0x00, 0x00, 0x00}
	// apOptionsEmpty represents no flags set
	apOptionsEmpty = []byte{0x00, 0x00, 0x00, 0x00}
)

// principalName represents a Kerberos principal name.
type principalName struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `asn1:"general,explicit,tag:1"`
}

// String returns the principal name as a string.
func (p principalName) String() string {
	if len(p.NameString) == 0 {
		return ""
	}
	if len(p.NameString) == 1 {
		return p.NameString[0]
	}
	return p.NameString[0] + "/" + p.NameString[1]
}

// encryptedData holds encrypted content.
type encryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"optional,explicit,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

// EncryptionKey is a Kerberos encryption key.
type EncryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

// ticket is a Kerberos ticket.
type ticket struct {
	TktVNO  int           `asn1:"explicit,tag:0"`
	Realm   string        `asn1:"general,explicit,tag:1"`
	SName   principalName `asn1:"explicit,tag:2"`
	EncPart encryptedData `asn1:"explicit,tag:3"`
}

// encTicketPart is the encrypted part of a ticket.
type encTicketPart struct {
	Flags     asn1.BitString `asn1:"explicit,tag:0"`
	Key       EncryptionKey  `asn1:"explicit,tag:1"`
	CRealm    string         `asn1:"general,explicit,tag:2"`
	CName     principalName  `asn1:"explicit,tag:3"`
	Transited transitedEnc   `asn1:"explicit,tag:4"`
	AuthTime  time.Time      `asn1:"generalized,explicit,tag:5"`
	StartTime time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	EndTime   time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill time.Time      `asn1:"generalized,optional,explicit,tag:8"`
	CAddr     []hostAddress  `asn1:"optional,explicit,tag:9"`
	AuthData  []authDataElem `asn1:"optional,explicit,tag:10"`
}

// transitedEnc holds transited realm information.
type transitedEnc struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// hostAddress is a network address.
type hostAddress struct {
	AddrType int32  `asn1:"explicit,tag:0"`
	Address  []byte `asn1:"explicit,tag:1"`
}

// authDataElem is an authorization data element.
type authDataElem struct {
	ADType int32  `asn1:"explicit,tag:0"`
	ADData []byte `asn1:"explicit,tag:1"`
}

// kdcReqBody is the body of an AS-REQ or TGS-REQ.
type kdcReqBody struct {
	KDCOptions asn1.BitString `asn1:"explicit,tag:0"`
	CName      principalName  `asn1:"optional,explicit,tag:1"`
	Realm      string         `asn1:"general,explicit,tag:2"`
	SName      principalName  `asn1:"optional,explicit,tag:3"`
	From       time.Time      `asn1:"generalized,optional,explicit,tag:4"`
	Till       time.Time      `asn1:"generalized,explicit,tag:5"`
	RTime      time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	Nonce      int64          `asn1:"explicit,tag:7"`
	EType      []int32        `asn1:"explicit,tag:8"`
	Addresses  []hostAddress  `asn1:"optional,explicit,tag:9"`
	EncAuthz   encryptedData  `asn1:"optional,explicit,tag:10"`
	AddlTkts   []ticket       `asn1:"optional,explicit,tag:11"`
}

// paData is pre-authentication data.
type paData struct {
	PADataType  int32  `asn1:"explicit,tag:1"`
	PADataValue []byte `asn1:"explicit,tag:2"`
}

// asReq is an Authentication Service request.
type asReq struct {
	PVNO    int        `asn1:"explicit,tag:1"`
	MsgType int        `asn1:"explicit,tag:2"`
	PAData  []paData   `asn1:"optional,explicit,tag:3"`
	ReqBody kdcReqBody `asn1:"explicit,tag:4"`
}

// tgsReq is a Ticket Granting Service request.
type tgsReq struct {
	PVNO    int        `asn1:"explicit,tag:1"`
	MsgType int        `asn1:"explicit,tag:2"`
	PAData  []paData   `asn1:"optional,explicit,tag:3"`
	ReqBody kdcReqBody `asn1:"explicit,tag:4"`
}

// asRep is an Authentication Service reply.
// Note: TicketBytes holds the pre-marshaled ticket with APPLICATION 1 tag.
type asRep struct {
	PVNO        int           `asn1:"explicit,tag:0"`
	MsgType     int           `asn1:"explicit,tag:1"`
	PAData      []paData      `asn1:"optional,explicit,tag:2"`
	CRealm      string        `asn1:"general,explicit,tag:3"`
	CName       principalName `asn1:"explicit,tag:4"`
	TicketBytes []byte        `asn1:"-"` // Manually handled - not marshaled by asn1
	EncPart     encryptedData `asn1:"explicit,tag:6"`
}

// tgsRep is a Ticket Granting Service reply.
// Note: TicketBytes holds the pre-marshaled ticket with APPLICATION 1 tag.
type tgsRep struct {
	PVNO        int           `asn1:"explicit,tag:0"`
	MsgType     int           `asn1:"explicit,tag:1"`
	PAData      []paData      `asn1:"optional,explicit,tag:2"`
	CRealm      string        `asn1:"general,explicit,tag:3"`
	CName       principalName `asn1:"explicit,tag:4"`
	TicketBytes []byte        `asn1:"-"` // Manually handled - not marshaled by asn1
	EncPart     encryptedData `asn1:"explicit,tag:6"`
}

// encKDCRepPart is the encrypted part of AS-REP or TGS-REP.
type encKDCRepPart struct {
	Key       EncryptionKey  `asn1:"explicit,tag:0"`
	LastReq   []lastReqEntry `asn1:"explicit,tag:1"`
	Nonce     int64          `asn1:"explicit,tag:2"`
	KeyExp    time.Time      `asn1:"generalized,optional,explicit,tag:3"`
	Flags     asn1.BitString `asn1:"explicit,tag:4"`
	AuthTime  time.Time      `asn1:"generalized,explicit,tag:5"`
	StartTime time.Time      `asn1:"generalized,optional,explicit,tag:6"`
	EndTime   time.Time      `asn1:"generalized,explicit,tag:7"`
	RenewTill time.Time      `asn1:"generalized,optional,explicit,tag:8"`
	SRealm    string         `asn1:"general,explicit,tag:9"`
	SName     principalName  `asn1:"explicit,tag:10"`
	CAddr     []hostAddress  `asn1:"optional,explicit,tag:11"`
}

// lastReqEntry is a last request timestamp entry.
type lastReqEntry struct {
	LRType  int32     `asn1:"explicit,tag:0"`
	LRValue time.Time `asn1:"generalized,explicit,tag:1"`
}

// krbError is a Kerberos error message.
type krbError struct {
	PVNO      int           `asn1:"explicit,tag:0"`
	MsgType   int           `asn1:"explicit,tag:1"`
	CTime     time.Time     `asn1:"generalized,optional,explicit,tag:2"`
	CUSec     int           `asn1:"optional,explicit,tag:3"`
	STime     time.Time     `asn1:"generalized,explicit,tag:4"`
	SUSec     int           `asn1:"explicit,tag:5"`
	ErrorCode int32         `asn1:"explicit,tag:6"`
	CRealm    string        `asn1:"general,optional,explicit,tag:7"`
	CName     principalName `asn1:"optional,explicit,tag:8"`
	Realm     string        `asn1:"general,explicit,tag:9"`
	SName     principalName `asn1:"explicit,tag:10"`
	EText     string        `asn1:"general,optional,explicit,tag:11"`
	EData     []byte        `asn1:"optional,explicit,tag:12"`
}

// apReq is an Application Request (sent to services).
// Note: TicketBytes holds the pre-marshaled ticket with APPLICATION 1 tag.
type apReq struct {
	PVNO        int            `asn1:"explicit,tag:0"`
	MsgType     int            `asn1:"explicit,tag:1"`
	APOptions   asn1.BitString `asn1:"explicit,tag:2"`
	TicketBytes []byte         `asn1:"-"` // Manually handled - not marshaled by asn1
	Auth        encryptedData  `asn1:"explicit,tag:4"`
}

// authenticator is the encrypted authenticator in AP-REQ.
type authenticator struct {
	AuthVNO   int            `asn1:"explicit,tag:0"`
	CRealm    string         `asn1:"general,explicit,tag:1"`
	CName     principalName  `asn1:"explicit,tag:2"`
	Cksum     checksum       `asn1:"optional,explicit,tag:3"`
	CUSec     int            `asn1:"explicit,tag:4"`
	CTime     time.Time      `asn1:"generalized,explicit,tag:5"`
	SubKey    EncryptionKey  `asn1:"optional,explicit,tag:6"`
	SeqNumber int64          `asn1:"optional,explicit,tag:7"`
	AuthData  []authDataElem `asn1:"optional,explicit,tag:8"`
}

// checksum is a Kerberos checksum.
type checksum struct {
	CksumType int32  `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}

// apRep is an Application Reply.
type apRep struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	EncPart encryptedData `asn1:"explicit,tag:2"`
}

// encAPRepPart is the encrypted part of AP-REP.
type encAPRepPart struct {
	CTime     time.Time     `asn1:"generalized,explicit,tag:0"`
	CUSec     int           `asn1:"explicit,tag:1"`
	SubKey    EncryptionKey `asn1:"optional,explicit,tag:2"`
	SeqNumber int64         `asn1:"optional,explicit,tag:3"`
}

// paEncTimestamp is the encrypted timestamp for pre-authentication.
type paEncTimestamp struct {
	PATimestamp time.Time `asn1:"generalized,explicit,tag:0"`
	PAUSec      int       `asn1:"optional,explicit,tag:1"`
}

// eTypeInfo2Entry provides encryption type info for pre-auth.
type eTypeInfo2Entry struct {
	EType     int32  `asn1:"explicit,tag:0"`
	Salt      string `asn1:"general,optional,explicit,tag:1"`
	S2KParams []byte `asn1:"optional,explicit,tag:2"`
}

// marshalETypeInfo2 marshals ETYPE-INFO2 with GeneralString for salt.
func marshalETypeInfo2(entries []eTypeInfo2Entry) ([]byte, error) {
	var entriesBytes []byte
	for _, e := range entries {
		var parts []byte

		// Tag 0: etype
		etype, _ := asn1.Marshal(e.EType)
		parts = append(parts, wrapExplicit(0, etype)...)

		// Tag 1: salt (GeneralString, optional)
		if e.Salt != "" {
			parts = append(parts, wrapExplicit(1, marshalGeneralString(e.Salt))...)
		}

		// Tag 2: s2kparams (optional)
		if len(e.S2KParams) > 0 {
			s2k, _ := asn1.Marshal(e.S2KParams)
			parts = append(parts, wrapExplicit(2, s2k)...)
		}

		entriesBytes = append(entriesBytes, wrapSequence(parts)...)
	}
	return wrapSequence(entriesBytes), nil
}

// marshalPAData marshals pre-authentication data with proper encoding.
func marshalPAData(data []paData) ([]byte, error) {
	var entries []byte
	for _, pa := range data {
		var parts []byte

		// Tag 1: padata-type
		paType, _ := asn1.Marshal(pa.PADataType)
		parts = append(parts, wrapExplicit(1, paType)...)

		// Tag 2: padata-value (OCTET STRING)
		paValue, _ := asn1.Marshal(pa.PADataValue)
		parts = append(parts, wrapExplicit(2, paValue)...)

		entries = append(entries, wrapSequence(parts)...)
	}
	return wrapSequence(entries), nil
}

// marshalASReq marshals an AS-REQ with APPLICATION 10 tag.
func marshalASReq(req asReq) ([]byte, error) {
	return marshalWithAppTag(req, msgTypeASReq)
}

// marshalASRep marshals an AS-REP with APPLICATION 11 tag.
// This manually constructs the ASN.1 to properly include the ticket with APPLICATION 1 tag.
func marshalASRep(rep asRep) ([]byte, error) {
	// Build each field manually with explicit tags
	var parts []byte

	// Tag 0: PVNO
	pvno, err := asn1.Marshal(rep.PVNO)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(0, pvno)...)

	// Tag 1: msg-type
	msgType, err := asn1.Marshal(rep.MsgType)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(1, msgType)...)

	// Tag 2: padata (optional)
	if len(rep.PAData) > 0 {
		padata, err := asn1.Marshal(rep.PAData)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(2, padata)...)
	}

	// Tag 3: crealm (GeneralString)
	crealm := marshalGeneralString(rep.CRealm)
	parts = append(parts, wrapExplicit(3, crealm)...)

	// Tag 4: cname (uses GeneralString for name-string)
	cname, err := marshalPrincipalName(rep.CName)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(4, cname)...)

	// Tag 5: ticket (already has APPLICATION 1 tag, just wrap in CONTEXT 5)
	parts = append(parts, wrapExplicit(5, rep.TicketBytes)...)

	// Tag 6: enc-part
	encPart, err := asn1.Marshal(rep.EncPart)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(6, encPart)...)

	// Wrap in SEQUENCE
	seq := wrapSequence(parts)

	// Wrap in APPLICATION 11
	return wrapApplication(msgTypeASRep, seq), nil
}

// marshalTGSReq marshals a TGS-REQ with APPLICATION 12 tag.
func marshalTGSReq(req tgsReq) ([]byte, error) {
	return marshalWithAppTag(req, msgTypeTGSReq)
}

// marshalTGSRep marshals a TGS-REP with APPLICATION 13 tag.
// This manually constructs the ASN.1 to properly include the ticket with APPLICATION 1 tag.
func marshalTGSRep(rep tgsRep) ([]byte, error) {
	// Build each field manually with explicit tags
	var parts []byte

	// Tag 0: PVNO
	pvno, err := asn1.Marshal(rep.PVNO)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(0, pvno)...)

	// Tag 1: msg-type
	msgType, err := asn1.Marshal(rep.MsgType)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(1, msgType)...)

	// Tag 2: padata (optional)
	if len(rep.PAData) > 0 {
		padata, err := asn1.Marshal(rep.PAData)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(2, padata)...)
	}

	// Tag 3: crealm (GeneralString)
	crealm := marshalGeneralString(rep.CRealm)
	parts = append(parts, wrapExplicit(3, crealm)...)

	// Tag 4: cname (uses GeneralString for name-string)
	cname, err := marshalPrincipalName(rep.CName)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(4, cname)...)

	// Tag 5: ticket (already has APPLICATION 1 tag, just wrap in CONTEXT 5)
	parts = append(parts, wrapExplicit(5, rep.TicketBytes)...)

	// Tag 6: enc-part
	encPart, err := asn1.Marshal(rep.EncPart)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(6, encPart)...)

	// Wrap in SEQUENCE
	seq := wrapSequence(parts)

	// Wrap in APPLICATION 13
	return wrapApplication(msgTypeTGSRep, seq), nil
}

// marshalTicket marshals a Ticket with APPLICATION 1 tag.
// This manually constructs the ASN.1 to properly encode GeneralStrings.
func marshalTicket(t ticket) ([]byte, error) {
	var parts []byte

	// Tag 0: tkt-vno
	tktVno, err := asn1.Marshal(t.TktVNO)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(0, tktVno)...)

	// Tag 1: realm (GeneralString)
	realm := marshalGeneralString(t.Realm)
	parts = append(parts, wrapExplicit(1, realm)...)

	// Tag 2: sname (PrincipalName with GeneralString)
	sname, err := marshalPrincipalName(t.SName)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(2, sname)...)

	// Tag 3: enc-part
	encPart, err := asn1.Marshal(t.EncPart)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(3, encPart)...)

	// Wrap in SEQUENCE
	seq := wrapSequence(parts)

	// Wrap in APPLICATION tag for Ticket
	return wrapApplication(appTagTicket, seq), nil
}

// marshalAPReq marshals an AP-REQ with APPLICATION 14 tag.
// This manually constructs the ASN.1 to properly include the ticket with APPLICATION 1 tag.
func marshalAPReq(req apReq) ([]byte, error) {
	// Build each field manually with explicit tags
	var parts []byte

	// Tag 0: PVNO
	pvno, err := asn1.Marshal(req.PVNO)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(0, pvno)...)

	// Tag 1: msg-type
	msgType, err := asn1.Marshal(req.MsgType)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(1, msgType)...)

	// Tag 2: ap-options
	apOptions, err := asn1.Marshal(req.APOptions)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(2, apOptions)...)

	// Tag 3: ticket (already has APPLICATION 1 tag, just wrap in CONTEXT 3)
	parts = append(parts, wrapExplicit(3, req.TicketBytes)...)

	// Tag 4: authenticator
	auth, err := asn1.Marshal(req.Auth)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(4, auth)...)

	// Wrap in SEQUENCE
	seq := wrapSequence(parts)

	// Wrap in APPLICATION 14
	return wrapApplication(msgTypeAPReq, seq), nil
}

// marshalAPRep marshals an AP-REP with APPLICATION 15 tag.
func marshalAPRep(rep apRep) ([]byte, error) {
	return marshalWithAppTag(rep, msgTypeAPRep)
}

// marshalKRBError marshals a KRB-ERROR with APPLICATION 30 tag.
// This manually constructs the ASN.1 to ensure GeneralString encoding for string fields.
func marshalKRBError(e krbError) ([]byte, error) {
	var parts []byte

	// Tag 0: PVNO
	pvno, _ := asn1.Marshal(e.PVNO)
	parts = append(parts, wrapExplicit(0, pvno)...)

	// Tag 1: msg-type
	msgType, _ := asn1.Marshal(e.MsgType)
	parts = append(parts, wrapExplicit(1, msgType)...)

	// Tag 2: ctime (optional)
	if !e.CTime.IsZero() {
		ctime, _ := asn1.MarshalWithParams(e.CTime, "generalized")
		parts = append(parts, wrapExplicit(2, ctime)...)
	}

	// Tag 3: cusec (optional) - only if ctime is present
	if !e.CTime.IsZero() {
		cusec, _ := asn1.Marshal(e.CUSec)
		parts = append(parts, wrapExplicit(3, cusec)...)
	}

	// Tag 4: stime
	stime, _ := asn1.MarshalWithParams(e.STime, "generalized")
	parts = append(parts, wrapExplicit(4, stime)...)

	// Tag 5: susec
	susec, _ := asn1.Marshal(e.SUSec)
	parts = append(parts, wrapExplicit(5, susec)...)

	// Tag 6: error-code
	errCode, _ := asn1.Marshal(e.ErrorCode)
	parts = append(parts, wrapExplicit(6, errCode)...)

	// Tag 7: crealm (optional, GeneralString)
	if e.CRealm != "" {
		parts = append(parts, wrapExplicit(7, marshalGeneralString(e.CRealm))...)
	}

	// Tag 8: cname (optional)
	if len(e.CName.NameString) > 0 {
		cname, _ := marshalPrincipalName(e.CName)
		parts = append(parts, wrapExplicit(8, cname)...)
	}

	// Tag 9: realm (GeneralString)
	parts = append(parts, wrapExplicit(9, marshalGeneralString(e.Realm))...)

	// Tag 10: sname
	sname, _ := marshalPrincipalName(e.SName)
	parts = append(parts, wrapExplicit(10, sname)...)

	// Tag 11: e-text (optional, GeneralString)
	if e.EText != "" {
		parts = append(parts, wrapExplicit(11, marshalGeneralString(e.EText))...)
	}

	// Tag 12: e-data (optional)
	if len(e.EData) > 0 {
		edata, _ := asn1.Marshal(e.EData)
		parts = append(parts, wrapExplicit(12, edata)...)
	}

	seq := wrapSequence(parts)
	return wrapApplication(msgTypeError, seq), nil
}

// marshalEncTicketPart marshals EncTicketPart with APPLICATION 3 tag.
// This manually constructs the ASN.1 to properly encode GeneralStrings.
func marshalEncTicketPart(e encTicketPart) ([]byte, error) {
	var parts []byte

	// Tag 0: flags
	flags, err := asn1.Marshal(e.Flags)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(0, flags)...)

	// Tag 1: key
	key, err := asn1.Marshal(e.Key)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(1, key)...)

	// Tag 2: crealm (GeneralString)
	crealm := marshalGeneralString(e.CRealm)
	parts = append(parts, wrapExplicit(2, crealm)...)

	// Tag 3: cname (PrincipalName with GeneralString)
	cname, err := marshalPrincipalName(e.CName)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(3, cname)...)

	// Tag 4: transited
	transited, err := asn1.Marshal(e.Transited)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(4, transited)...)

	// Tag 5: authtime
	authTime, err := asn1.MarshalWithParams(e.AuthTime, "generalized")
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(5, authTime)...)

	// Tag 6: starttime (optional)
	if !e.StartTime.IsZero() {
		startTime, err := asn1.MarshalWithParams(e.StartTime, "generalized")
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(6, startTime)...)
	}

	// Tag 7: endtime
	endTime, err := asn1.MarshalWithParams(e.EndTime, "generalized")
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(7, endTime)...)

	// Tag 8: renew-till (optional)
	if !e.RenewTill.IsZero() {
		renewTill, err := asn1.MarshalWithParams(e.RenewTill, "generalized")
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(8, renewTill)...)
	}

	// Tag 9: caddr (optional)
	if len(e.CAddr) > 0 {
		caddr, err := asn1.Marshal(e.CAddr)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(9, caddr)...)
	}

	// Tag 10: authorization-data (optional)
	if len(e.AuthData) > 0 {
		authData, err := asn1.Marshal(e.AuthData)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(10, authData)...)
	}

	// Wrap in SEQUENCE
	seq := wrapSequence(parts)

	// Wrap in APPLICATION tag for EncTicketPart
	return wrapApplication(appTagEncTicketPart, seq), nil
}

// marshalEncASRepPart marshals EncKDCRepPart with APPLICATION tag for AS-REP.
func marshalEncASRepPart(e encKDCRepPart) ([]byte, error) {
	return marshalEncKDCRepPart(e, appTagEncASRepPart)
}

// marshalEncTGSRepPart marshals EncKDCRepPart with APPLICATION tag for TGS-REP.
func marshalEncTGSRepPart(e encKDCRepPart) ([]byte, error) {
	return marshalEncKDCRepPart(e, appTagEncTGSRepPart)
}

// marshalEncKDCRepPart marshals EncKDCRepPart with the specified APPLICATION tag.
// This manually constructs the ASN.1 to properly encode GeneralStrings.
func marshalEncKDCRepPart(e encKDCRepPart, appTag int) ([]byte, error) {
	var parts []byte

	// Tag 0: key
	key, err := asn1.Marshal(e.Key)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(0, key)...)

	// Tag 1: last-req
	lastReq, err := marshalLastReq(e.LastReq)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(1, lastReq)...)

	// Tag 2: nonce
	nonce, err := asn1.Marshal(e.Nonce)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(2, nonce)...)

	// Tag 3: key-expiration (optional)
	if !e.KeyExp.IsZero() {
		keyExp, err := asn1.MarshalWithParams(e.KeyExp, "generalized")
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(3, keyExp)...)
	}

	// Tag 4: flags
	flags, err := asn1.Marshal(e.Flags)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(4, flags)...)

	// Tag 5: authtime
	authTime, err := asn1.MarshalWithParams(e.AuthTime, "generalized")
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(5, authTime)...)

	// Tag 6: starttime (optional)
	if !e.StartTime.IsZero() {
		startTime, err := asn1.MarshalWithParams(e.StartTime, "generalized")
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(6, startTime)...)
	}

	// Tag 7: endtime
	endTime, err := asn1.MarshalWithParams(e.EndTime, "generalized")
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(7, endTime)...)

	// Tag 8: renew-till (optional)
	if !e.RenewTill.IsZero() {
		renewTill, err := asn1.MarshalWithParams(e.RenewTill, "generalized")
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(8, renewTill)...)
	}

	// Tag 9: srealm (GeneralString)
	srealm := marshalGeneralString(e.SRealm)
	parts = append(parts, wrapExplicit(9, srealm)...)

	// Tag 10: sname (PrincipalName with GeneralString)
	sname, err := marshalPrincipalName(e.SName)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(10, sname)...)

	// Tag 11: caddr (optional)
	if len(e.CAddr) > 0 {
		caddr, err := asn1.Marshal(e.CAddr)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(11, caddr)...)
	}

	// Wrap in SEQUENCE
	seq := wrapSequence(parts)

	// Wrap in APPLICATION tag
	return wrapApplication(appTag, seq), nil
}

// marshalLastReq marshals LastReq as a SEQUENCE OF LastReqEntry.
func marshalLastReq(entries []lastReqEntry) ([]byte, error) {
	var entriesBytes []byte
	for _, entry := range entries {
		var parts []byte

		// Tag 0: lr-type
		lrType, err := asn1.Marshal(entry.LRType)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(0, lrType)...)

		// Tag 1: lr-value
		lrValue, err := asn1.MarshalWithParams(entry.LRValue, "generalized")
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(1, lrValue)...)

		entriesBytes = append(entriesBytes, wrapSequence(parts)...)
	}
	return wrapSequence(entriesBytes), nil
}

// marshalAuthenticator marshals Authenticator with APPLICATION 2 tag.
// This manually constructs the ASN.1 to properly encode GeneralStrings.
func marshalAuthenticator(a authenticator) ([]byte, error) {
	var parts []byte

	// Tag 0: authenticator-vno
	authVno, err := asn1.Marshal(a.AuthVNO)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(0, authVno)...)

	// Tag 1: crealm (GeneralString)
	crealm := marshalGeneralString(a.CRealm)
	parts = append(parts, wrapExplicit(1, crealm)...)

	// Tag 2: cname (PrincipalName with GeneralString)
	cname, err := marshalPrincipalName(a.CName)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(2, cname)...)

	// Tag 3: cksum (optional)
	if a.Cksum.CksumType != 0 || len(a.Cksum.Checksum) > 0 {
		cksum, err := asn1.Marshal(a.Cksum)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(3, cksum)...)
	}

	// Tag 4: cusec
	cusec, err := asn1.Marshal(a.CUSec)
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(4, cusec)...)

	// Tag 5: ctime
	ctime, err := asn1.MarshalWithParams(a.CTime, "generalized")
	if err != nil {
		return nil, err
	}
	parts = append(parts, wrapExplicit(5, ctime)...)

	// Tag 6: subkey (optional)
	if len(a.SubKey.KeyValue) > 0 {
		subkey, err := asn1.Marshal(a.SubKey)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(6, subkey)...)
	}

	// Tag 7: seq-number (optional)
	if a.SeqNumber != 0 {
		seqNum, err := asn1.Marshal(a.SeqNumber)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(7, seqNum)...)
	}

	// Tag 8: authorization-data (optional)
	if len(a.AuthData) > 0 {
		authData, err := asn1.Marshal(a.AuthData)
		if err != nil {
			return nil, err
		}
		parts = append(parts, wrapExplicit(8, authData)...)
	}

	// Wrap in SEQUENCE
	seq := wrapSequence(parts)

	// Wrap in APPLICATION tag for Authenticator
	return wrapApplication(appTagAuthenticator, seq), nil
}

// marshalEncAPRepPart marshals EncAPRepPart with APPLICATION tag.
func marshalEncAPRepPart(e encAPRepPart) ([]byte, error) {
	return marshalWithAppTag(e, appTagEncAPRepPart)
}

// marshalWithAppTag marshals a value wrapped in an APPLICATION tag.
func marshalWithAppTag(v interface{}, tag int) ([]byte, error) {
	inner, err := asn1.Marshal(v)
	if err != nil {
		return nil, err
	}
	wrapped := asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        tag,
		IsCompound: true,
		Bytes:      inner,
	}
	return asn1.Marshal(wrapped)
}

// wrapExplicit wraps content in a CONTEXT-SPECIFIC explicit tag.
func wrapExplicit(tag int, content []byte) []byte {
	return wrapTag(asn1.ClassContextSpecific, tag, true, content)
}

// wrapApplication wraps content in an APPLICATION tag.
func wrapApplication(tag int, content []byte) []byte {
	return wrapTag(asn1.ClassApplication, tag, true, content)
}

// wrapSequence wraps content in a SEQUENCE.
func wrapSequence(content []byte) []byte {
	return wrapTag(asn1.ClassUniversal, asn1.TagSequence, true, content)
}

// marshalGeneralString encodes a string as ASN.1 GeneralString (tag 27).
// Go's encoding/asn1 doesn't support GeneralString, but Kerberos requires it.
func marshalGeneralString(s string) []byte {
	return wrapTag(asn1.ClassUniversal, asn1.TagGeneralString, false, []byte(s))
}

// marshalPrincipalName marshals a PrincipalName with GeneralString encoding.
func marshalPrincipalName(p principalName) ([]byte, error) {
	var parts []byte

	// Tag 0: name-type
	nameType, _ := asn1.Marshal(p.NameType)
	parts = append(parts, wrapExplicit(0, nameType)...)

	// Tag 1: name-string (SEQUENCE OF GeneralString)
	var nameStrings []byte
	for _, s := range p.NameString {
		nameStrings = append(nameStrings, marshalGeneralString(s)...)
	}
	parts = append(parts, wrapExplicit(1, wrapSequence(nameStrings))...)

	return wrapSequence(parts), nil
}

// wrapTag wraps content with an ASN.1 tag.
func wrapTag(class, tag int, isCompound bool, content []byte) []byte {
	// Build tag byte(s)
	var tagBytes []byte
	tagByte := byte(class << 6)
	if isCompound {
		tagByte |= 0x20
	}
	if tag < 31 {
		tagByte |= byte(tag)
		tagBytes = []byte{tagByte}
	} else {
		// High tag number form
		tagByte |= 0x1f
		tagBytes = []byte{tagByte}
		// Encode tag in base 128
		var encodedTag []byte
		t := tag
		for t > 0 {
			encodedTag = append([]byte{byte(t & 0x7f)}, encodedTag...)
			t >>= 7
		}
		for i := 0; i < len(encodedTag)-1; i++ {
			encodedTag[i] |= 0x80
		}
		tagBytes = append(tagBytes, encodedTag...)
	}

	// Build length
	length := len(content)
	var lengthBytes []byte
	if length < 128 {
		lengthBytes = []byte{byte(length)}
	} else {
		// Long form length
		var lenBuf []byte
		l := length
		for l > 0 {
			lenBuf = append([]byte{byte(l & 0xff)}, lenBuf...)
			l >>= 8
		}
		lengthBytes = append([]byte{byte(0x80 | len(lenBuf))}, lenBuf...)
	}

	result := make([]byte, 0, len(tagBytes)+len(lengthBytes)+len(content))
	result = append(result, tagBytes...)
	result = append(result, lengthBytes...)
	result = append(result, content...)
	return result
}

// unmarshalASReq unmarshals an AS-REQ from APPLICATION 10 tagged data.
func unmarshalASReq(data []byte) (*asReq, error) {
	inner, tag, err := unwrapAppTag(data)
	if err != nil {
		return nil, err
	}
	if tag != msgTypeASReq {
		return nil, fmt.Errorf("expected AS-REQ (tag 10), got tag %d", tag)
	}
	var req asReq
	_, err = asn1.Unmarshal(inner, &req)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

// unmarshalTGSReq unmarshals a TGS-REQ from APPLICATION 12 tagged data.
func unmarshalTGSReq(data []byte) (*tgsReq, error) {
	inner, tag, err := unwrapAppTag(data)
	if err != nil {
		return nil, err
	}
	if tag != msgTypeTGSReq {
		return nil, fmt.Errorf("expected TGS-REQ (tag 12), got tag %d", tag)
	}
	var req tgsReq
	_, err = asn1.Unmarshal(inner, &req)
	if err != nil {
		return nil, err
	}
	return &req, nil
}

// unmarshalAPReq unmarshals an AP-REQ from APPLICATION 14 tagged data.
// This manually parses to extract the ticket bytes with APPLICATION 1 tag preserved.
func unmarshalAPReq(data []byte) (*apReq, error) {
	inner, tag, err := unwrapAppTag(data)
	if err != nil {
		return nil, err
	}
	if tag != msgTypeAPReq {
		return nil, fmt.Errorf("expected AP-REQ (tag 14), got tag %d", tag)
	}

	// inner is the SEQUENCE, we need to get its content
	var seqRaw asn1.RawValue
	if _, err := asn1.Unmarshal(inner, &seqRaw); err != nil {
		return nil, fmt.Errorf("unmarshal SEQUENCE: %w", err)
	}

	// Parse the fields inside the SEQUENCE
	var req apReq
	rest := seqRaw.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, fmt.Errorf("unmarshal field: %w", err)
		}

		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch field.Tag {
		case 0: // PVNO
			var pvno int
			if _, err := asn1.Unmarshal(field.Bytes, &pvno); err != nil {
				return nil, fmt.Errorf("unmarshal pvno: %w", err)
			}
			req.PVNO = pvno
		case 1: // msg-type
			var msgType int
			if _, err := asn1.Unmarshal(field.Bytes, &msgType); err != nil {
				return nil, fmt.Errorf("unmarshal msg-type: %w", err)
			}
			req.MsgType = msgType
		case 2: // ap-options
			var apOpts asn1.BitString
			if _, err := asn1.Unmarshal(field.Bytes, &apOpts); err != nil {
				return nil, fmt.Errorf("unmarshal ap-options: %w", err)
			}
			req.APOptions = apOpts
		case 3: // ticket - preserve raw bytes including APPLICATION 1 tag
			req.TicketBytes = field.Bytes
		case 4: // authenticator
			var auth encryptedData
			if _, err := asn1.Unmarshal(field.Bytes, &auth); err != nil {
				return nil, fmt.Errorf("unmarshal authenticator: %w", err)
			}
			req.Auth = auth
		}
	}

	return &req, nil
}

// unmarshalASRep unmarshals an AS-REP from APPLICATION 11 tagged data.
// This manually parses to extract the ticket bytes with APPLICATION 1 tag preserved.
func unmarshalASRep(data []byte) (*asRep, error) {
	inner, tag, err := unwrapAppTag(data)
	if err != nil {
		return nil, err
	}
	if tag != msgTypeASRep {
		return nil, fmt.Errorf("expected AS-REP (tag 11), got tag %d", tag)
	}

	// inner is the SEQUENCE, we need to get its content
	var seqRaw asn1.RawValue
	if _, err := asn1.Unmarshal(inner, &seqRaw); err != nil {
		return nil, fmt.Errorf("unmarshal SEQUENCE: %w", err)
	}

	// Parse the fields inside the SEQUENCE
	var rep asRep
	rest := seqRaw.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, fmt.Errorf("unmarshal field: %w", err)
		}

		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch field.Tag {
		case 0: // PVNO
			var pvno int
			if _, err := asn1.Unmarshal(field.Bytes, &pvno); err != nil {
				return nil, fmt.Errorf("unmarshal pvno: %w", err)
			}
			rep.PVNO = pvno
		case 1: // msg-type
			var msgType int
			if _, err := asn1.Unmarshal(field.Bytes, &msgType); err != nil {
				return nil, fmt.Errorf("unmarshal msg-type: %w", err)
			}
			rep.MsgType = msgType
		case 2: // padata (optional)
			var padata []paData
			if _, err := asn1.Unmarshal(field.Bytes, &padata); err != nil {
				return nil, fmt.Errorf("unmarshal padata: %w", err)
			}
			rep.PAData = padata
		case 3: // crealm
			var crealm string
			if _, err := asn1.UnmarshalWithParams(field.Bytes, &crealm, "general"); err != nil {
				return nil, fmt.Errorf("unmarshal crealm: %w", err)
			}
			rep.CRealm = crealm
		case 4: // cname
			var cname principalName
			if _, err := asn1.Unmarshal(field.Bytes, &cname); err != nil {
				return nil, fmt.Errorf("unmarshal cname: %w", err)
			}
			rep.CName = cname
		case 5: // ticket - preserve raw bytes including APPLICATION 1 tag
			rep.TicketBytes = field.Bytes
		case 6: // enc-part
			var encPart encryptedData
			if _, err := asn1.Unmarshal(field.Bytes, &encPart); err != nil {
				return nil, fmt.Errorf("unmarshal enc-part: %w", err)
			}
			rep.EncPart = encPart
		}
	}

	return &rep, nil
}

// unmarshalTGSRep unmarshals a TGS-REP from APPLICATION 13 tagged data.
// This manually parses to extract the ticket bytes with APPLICATION 1 tag preserved.
func unmarshalTGSRep(data []byte) (*tgsRep, error) {
	inner, tag, err := unwrapAppTag(data)
	if err != nil {
		return nil, err
	}
	if tag != msgTypeTGSRep {
		return nil, fmt.Errorf("expected TGS-REP (tag 13), got tag %d", tag)
	}

	// inner is the SEQUENCE, we need to get its content
	var seqRaw asn1.RawValue
	if _, err := asn1.Unmarshal(inner, &seqRaw); err != nil {
		return nil, fmt.Errorf("unmarshal SEQUENCE: %w", err)
	}

	// Parse the fields inside the SEQUENCE
	var rep tgsRep
	rest := seqRaw.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, fmt.Errorf("unmarshal field: %w", err)
		}

		if field.Class != asn1.ClassContextSpecific {
			continue
		}

		switch field.Tag {
		case 0: // PVNO
			var pvno int
			if _, err := asn1.Unmarshal(field.Bytes, &pvno); err != nil {
				return nil, fmt.Errorf("unmarshal pvno: %w", err)
			}
			rep.PVNO = pvno
		case 1: // msg-type
			var msgType int
			if _, err := asn1.Unmarshal(field.Bytes, &msgType); err != nil {
				return nil, fmt.Errorf("unmarshal msg-type: %w", err)
			}
			rep.MsgType = msgType
		case 2: // padata (optional)
			var padata []paData
			if _, err := asn1.Unmarshal(field.Bytes, &padata); err != nil {
				return nil, fmt.Errorf("unmarshal padata: %w", err)
			}
			rep.PAData = padata
		case 3: // crealm
			var crealm string
			if _, err := asn1.UnmarshalWithParams(field.Bytes, &crealm, "general"); err != nil {
				return nil, fmt.Errorf("unmarshal crealm: %w", err)
			}
			rep.CRealm = crealm
		case 4: // cname
			var cname principalName
			if _, err := asn1.Unmarshal(field.Bytes, &cname); err != nil {
				return nil, fmt.Errorf("unmarshal cname: %w", err)
			}
			rep.CName = cname
		case 5: // ticket - preserve raw bytes including APPLICATION 1 tag
			rep.TicketBytes = field.Bytes
		case 6: // enc-part
			var encPart encryptedData
			if _, err := asn1.Unmarshal(field.Bytes, &encPart); err != nil {
				return nil, fmt.Errorf("unmarshal enc-part: %w", err)
			}
			rep.EncPart = encPart
		}
	}

	return &rep, nil
}

// unmarshalTicket unmarshals a Ticket from APPLICATION tagged data.
func unmarshalTicket(data []byte) (*ticket, error) {
	inner, tag, err := unwrapAppTag(data)
	if err != nil {
		return nil, err
	}
	if tag != appTagTicket {
		return nil, fmt.Errorf("expected Ticket (tag %d), got tag %d", appTagTicket, tag)
	}
	var t ticket
	_, err = asn1.Unmarshal(inner, &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// unwrapAppTag extracts the inner content and tag from an APPLICATION-tagged value.
func unwrapAppTag(data []byte) (inner []byte, tag int, err error) {
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(data, &raw)
	if err != nil {
		return nil, 0, fmt.Errorf("unmarshal APPLICATION tag: %w", err)
	}
	if raw.Class != asn1.ClassApplication {
		return nil, 0, fmt.Errorf("expected APPLICATION class, got %d", raw.Class)
	}
	return raw.Bytes, raw.Tag, nil
}

// getMsgType returns the message type from a Kerberos message without fully parsing it.
func getMsgType(data []byte) (int, error) {
	_, tag, err := unwrapAppTag(data)
	return tag, err
}
