package krb5

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Client is a Kerberos client that can obtain tickets from a KDC.
type Client struct {
	principal string
	realm     string
	password  string
	kdcAddr   string

	// Cached TGT (stored as raw bytes with APPLICATION 1 tag)
	tgtBytes  []byte
	tgtKey    EncryptionKey
	tgtExpiry time.Time
}

// NewClient creates a new Kerberos client.
func NewClient(principal, realm, password, kdcAddr string) *Client {
	return &Client{
		principal: principal,
		realm:     realm,
		password:  password,
		kdcAddr:   kdcAddr,
	}
}

// GetServiceTicket obtains a service ticket for the given service principal.
// This first obtains a TGT if needed, then exchanges it for a service ticket.
// Returns the raw ticket bytes (with APPLICATION 1 tag) and session key.
func (c *Client) GetServiceTicket(servicePrincipal string) ([]byte, EncryptionKey, error) {
	// Get TGT if we don't have one or it's expired
	if c.tgtBytes == nil || time.Now().After(c.tgtExpiry) {
		if err := c.getTGT(); err != nil {
			return nil, EncryptionKey{}, fmt.Errorf("get TGT: %w", err)
		}
	}

	// Exchange TGT for service ticket
	return c.getServiceTicket(servicePrincipal)
}

// GetAPReq creates an AP-REQ for the given service.
// This is what gets sent to the service in the SPNEGO token.
func (c *Client) GetAPReq(servicePrincipal string) ([]byte, EncryptionKey, error) {
	ticketBytes, sessionKey, err := c.GetServiceTicket(servicePrincipal)
	if err != nil {
		return nil, EncryptionKey{}, err
	}

	// Build authenticator
	now := time.Now().UTC()
	auth := authenticator{
		AuthVNO: 5,
		CRealm:  c.realm,
		CName: principalName{
			NameType:   nameTypePrincipal,
			NameString: []string{c.principal},
		},
		CUSec: now.Nanosecond() / 1000,
		CTime: now,
	}

	authBytes, err := marshalAuthenticator(auth)
	if err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("marshal authenticator: %w", err)
	}

	// Encrypt authenticator with session key
	encAuth, err := encrypt(sessionKey, keyUsageAPReqAuth, authBytes)
	if err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("encrypt authenticator: %w", err)
	}

	// Build AP-REQ (ticketBytes already has APPLICATION 1 tag)
	apReq := apReq{
		PVNO:        5,
		MsgType:     msgTypeAPReq,
		APOptions:   asn1.BitString{Bytes: []byte{0x20, 0x00, 0x00, 0x00}, BitLength: 32}, // MUTUAL-REQUIRED
		TicketBytes: ticketBytes,
		Auth:        encAuth,
	}

	apReqBytes, err := marshalAPReq(apReq)
	if err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("marshal AP-REQ: %w", err)
	}

	return apReqBytes, sessionKey, nil
}

func (c *Client) getTGT() error {
	// Build AS-REQ
	nonce, err := randomNonce()
	if err != nil {
		return err
	}

	reqBody := kdcReqBody{
		KDCOptions: asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32},
		CName: principalName{
			NameType:   nameTypePrincipal,
			NameString: []string{c.principal},
		},
		Realm: c.realm,
		SName: principalName{
			NameType:   nameTypeSrvInst,
			NameString: []string{"krbtgt", c.realm},
		},
		Till:  time.Now().Add(24 * time.Hour).UTC(),
		Nonce: nonce,
		EType: []int32{eTypeAES256SHA1, eTypeAES128SHA1},
	}

	// First request without pre-auth
	asReq := asReq{
		PVNO:    5,
		MsgType: msgTypeASReq,
		ReqBody: reqBody,
	}

	resp, err := c.sendKDCRequest(asReq, msgTypeASReq)
	if err != nil {
		return err
	}

	// Check if we got pre-auth required error
	msgType, err := getMsgType(resp)
	if err != nil {
		return err
	}

	var etype int32 = eTypeAES256SHA1 // default

	if msgType == msgTypeError {
		// Parse error to get etype info
		inner, _, err := unwrapAppTag(resp)
		if err != nil {
			return fmt.Errorf("unwrap error: %w", err)
		}
		var krbErr krbError
		if _, err := asn1.Unmarshal(inner, &krbErr); err != nil {
			return fmt.Errorf("unmarshal error: %w", err)
		}

		if krbErr.ErrorCode != errPreAuthRequired {
			return fmt.Errorf("KDC error: %d - %s", krbErr.ErrorCode, krbErr.EText)
		}

		// Parse ETYPE-INFO2 from error data
		if len(krbErr.EData) > 0 {
			var paData []paData
			if _, err := asn1.Unmarshal(krbErr.EData, &paData); err == nil {
				for _, pa := range paData {
					if pa.PADataType == paTypeETypeInfo2 {
						var info []eTypeInfo2Entry
						if _, err := asn1.Unmarshal(pa.PADataValue, &info); err == nil && len(info) > 0 {
							etype = info[0].EType
						}
					}
				}
			}
		}

		// Retry with pre-auth
		return c.getTGTWithPreAuth(reqBody, etype)
	}

	// We got AS-REP without pre-auth (unlikely)
	return c.processASRep(resp, etype)
}

func (c *Client) getTGTWithPreAuth(reqBody kdcReqBody, etype int32) error {
	// Derive key from password
	clientKey, err := deriveKeyFromPassword(etype, c.password, c.principal, c.realm)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	// Build encrypted timestamp
	now := time.Now().UTC()
	ts := paEncTimestamp{
		PATimestamp: now,
		PAUSec:      now.Nanosecond() / 1000,
	}
	tsBytes, err := asn1.Marshal(ts)
	if err != nil {
		return fmt.Errorf("marshal timestamp: %w", err)
	}

	encTS, err := encrypt(EncryptionKey{KeyType: etype, KeyValue: clientKey},
		keyUsageASReqTimestamp, tsBytes)
	if err != nil {
		return fmt.Errorf("encrypt timestamp: %w", err)
	}

	encTSBytes, err := asn1.Marshal(encTS)
	if err != nil {
		return fmt.Errorf("marshal encrypted timestamp: %w", err)
	}

	// Build AS-REQ with pre-auth
	nonce, _ := randomNonce()
	reqBody.Nonce = nonce

	asReq := asReq{
		PVNO:    5,
		MsgType: msgTypeASReq,
		PAData: []paData{{
			PADataType:  paTypeEncTimestamp,
			PADataValue: encTSBytes,
		}},
		ReqBody: reqBody,
	}

	resp, err := c.sendKDCRequest(asReq, msgTypeASReq)
	if err != nil {
		return err
	}

	// Check response type
	msgType, err := getMsgType(resp)
	if err != nil {
		return err
	}

	if msgType == msgTypeError {
		inner, _, _ := unwrapAppTag(resp)
		var krbErr krbError
		asn1.Unmarshal(inner, &krbErr)
		return fmt.Errorf("KDC error: %d - %s", krbErr.ErrorCode, krbErr.EText)
	}

	return c.processASRep(resp, etype)
}

func (c *Client) processASRep(data []byte, etype int32) error {
	rep, err := unmarshalASRep(data)
	if err != nil {
		return fmt.Errorf("unmarshal AS-REP: %w", err)
	}

	// Derive key and decrypt encrypted part
	clientKey, err := deriveKeyFromPassword(etype, c.password, c.principal, c.realm)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	encPartData, err := decrypt(EncryptionKey{KeyType: etype, KeyValue: clientKey},
		keyUsageASRepEncPart, rep.EncPart)
	if err != nil {
		return fmt.Errorf("decrypt AS-REP: %w", err)
	}

	// Unmarshal EncKDCRepPart
	encInner, _, err := unwrapAppTag(encPartData)
	if err != nil {
		return fmt.Errorf("unwrap EncKDCRepPart: %w", err)
	}

	var encPart encKDCRepPart
	if _, err := asn1.Unmarshal(encInner, &encPart); err != nil {
		return fmt.Errorf("unmarshal EncKDCRepPart: %w", err)
	}

	// Store TGT (rep.TicketBytes has APPLICATION 1 tag)
	c.tgtBytes = rep.TicketBytes
	c.tgtKey = encPart.Key
	c.tgtExpiry = encPart.EndTime

	return nil
}

func (c *Client) getServiceTicket(servicePrincipal string) ([]byte, EncryptionKey, error) {
	// Build TGS-REQ
	nonce, _ := randomNonce()

	// Parse service principal (format: "service/host")
	sname := parsePrincipal(servicePrincipal)

	reqBody := kdcReqBody{
		KDCOptions: asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32},
		Realm:      c.realm,
		SName:      sname,
		Till:       time.Now().Add(24 * time.Hour).UTC(),
		Nonce:      nonce,
		EType:      []int32{c.tgtKey.KeyType},
	}

	// Build AP-REQ for TGS
	apReqBytes, err := c.buildTGSAPReq()
	if err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("build TGS AP-REQ: %w", err)
	}

	tgsReq := tgsReq{
		PVNO:    5,
		MsgType: msgTypeTGSReq,
		PAData: []paData{{
			PADataType:  paTypeTGSReq,
			PADataValue: apReqBytes,
		}},
		ReqBody: reqBody,
	}

	resp, err := c.sendKDCRequest(tgsReq, msgTypeTGSReq)
	if err != nil {
		return nil, EncryptionKey{}, err
	}

	// Check response type
	msgType, err := getMsgType(resp)
	if err != nil {
		return nil, EncryptionKey{}, err
	}

	if msgType == msgTypeError {
		inner, _, _ := unwrapAppTag(resp)
		var krbErr krbError
		asn1.Unmarshal(inner, &krbErr)
		return nil, EncryptionKey{}, fmt.Errorf("KDC error: %d - %s", krbErr.ErrorCode, krbErr.EText)
	}

	// Parse TGS-REP
	rep, err := unmarshalTGSRep(resp)
	if err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("unmarshal TGS-REP: %w", err)
	}

	// Decrypt encrypted part with TGT session key
	encPartData, err := decrypt(c.tgtKey, keyUsageTGSRepEncPart, rep.EncPart)
	if err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("decrypt TGS-REP: %w", err)
	}

	// Unmarshal EncKDCRepPart
	encInner, _, err := unwrapAppTag(encPartData)
	if err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("unwrap EncKDCRepPart: %w", err)
	}

	var encPart encKDCRepPart
	if _, err := asn1.Unmarshal(encInner, &encPart); err != nil {
		return nil, EncryptionKey{}, fmt.Errorf("unmarshal EncKDCRepPart: %w", err)
	}

	// Return ticket bytes (preserves APPLICATION 1 tag)
	return rep.TicketBytes, encPart.Key, nil
}

func (c *Client) buildTGSAPReq() ([]byte, error) {
	// Build authenticator
	now := time.Now().UTC()
	auth := authenticator{
		AuthVNO: 5,
		CRealm:  c.realm,
		CName: principalName{
			NameType:   nameTypePrincipal,
			NameString: []string{c.principal},
		},
		CUSec: now.Nanosecond() / 1000,
		CTime: now,
	}

	authBytes, err := marshalAuthenticator(auth)
	if err != nil {
		return nil, fmt.Errorf("marshal authenticator: %w", err)
	}

	// Encrypt authenticator with TGT session key
	encAuth, err := encrypt(c.tgtKey, keyUsageTGSReqAuth, authBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt authenticator: %w", err)
	}

	// Use TGT bytes directly (preserves APPLICATION 1 tag)
	apReq := apReq{
		PVNO:        5,
		MsgType:     msgTypeAPReq,
		APOptions:   asn1.BitString{Bytes: []byte{0x00, 0x00, 0x00, 0x00}, BitLength: 32},
		TicketBytes: c.tgtBytes,
		Auth:        encAuth,
	}

	return marshalAPReq(apReq)
}

func (c *Client) sendKDCRequest(req interface{}, msgType int) ([]byte, error) {
	var data []byte
	var err error

	switch msgType {
	case msgTypeASReq:
		data, err = marshalASReq(req.(asReq))
	case msgTypeTGSReq:
		data, err = marshalTGSReq(req.(tgsReq))
	default:
		return nil, fmt.Errorf("unsupported request type: %d", msgType)
	}
	if err != nil {
		return nil, err
	}

	// Try TCP first (more reliable for larger messages)
	conn, err := net.DialTimeout("tcp", c.kdcAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to KDC: %w", err)
	}
	defer conn.Close()

	// Send with length prefix
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(data)))

	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("write length: %w", err)
	}
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("write data: %w", err)
	}

	// Read response
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}

	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen > 65535 {
		return nil, fmt.Errorf("response too large: %d", respLen)
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	return resp, nil
}

func randomNonce() (int64, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	// Use 31 bits to ensure positive value
	return int64(binary.BigEndian.Uint32(buf[:]) & 0x7FFFFFFF), nil
}

func parsePrincipal(s string) principalName {
	parts := splitPrincipal(s)
	if len(parts) == 1 {
		return principalName{
			NameType:   nameTypePrincipal,
			NameString: parts,
		}
	}
	return principalName{
		NameType:   nameTypeSrvInst,
		NameString: parts,
	}
}

func splitPrincipal(s string) []string {
	// Split on "/" for service principals
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}
