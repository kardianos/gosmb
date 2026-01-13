package krb5

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/kardianos/gosmb/smblog"
)

// PrincipalType identifies the type of Kerberos principal.
type PrincipalType int

const (
	// PrincipalUser is a user/client principal (NT-PRINCIPAL).
	// Examples: "alice", "bob", "admin"
	// Used when clients request TGTs (AS-REQ).
	PrincipalUser PrincipalType = iota

	// PrincipalService is a service principal (NT-SRV-INST).
	// Examples: "cifs/fileserver.example.com", "http/web.example.com", "krbtgt/REALM"
	// Used when issuing service tickets (TGS-REQ).
	PrincipalService
)

func (t PrincipalType) String() string {
	switch t {
	case PrincipalUser:
		return "user"
	case PrincipalService:
		return "service"
	default:
		return "unknown"
	}
}

// PrincipalStore looks up keys for Kerberos principals.
// Implement this interface to back the KDC with a database, LDAP, Active Directory, etc.
//
// This is the core interface for principal management. In Active Directory terms:
//   - PrincipalUser corresponds to user accounts (e.g., alice@REALM)
//   - PrincipalService corresponds to machine accounts (e.g., FILESERVER$) and their
//     registered SPNs (e.g., cifs/fileserver.example.com)
//
// Enrollment and key rotation are handled outside the KDC via separate protocols:
//   - Domain join: MS-RPC over SMB named pipes (\\DC\IPC$\PIPE\samr, \PIPE\netlogon)
//   - Machine password rotation: MS-NRPC (NetLogon) over SMB
//   - SPN registration: LDAP modifications to servicePrincipalName attribute
//
// NOTE: This implementation only supports AES256-CTS-HMAC-SHA1-96 (etype 18).
// To extend for multiple encryption types, GetKey would need to accept an etype
// parameter and return the appropriate pre-computed key for that type.
type PrincipalStore interface {
	// GetKey returns the pre-computed AES256 key for a principal.
	// Keys must be derived using DeriveKey(password, principal, realm).
	//
	// For PrincipalUser: called during AS-REQ to verify pre-authentication
	// and encrypt the AS-REP.
	//
	// For PrincipalService: called during TGS-REQ to encrypt the service ticket.
	// The service principal (e.g., "cifs/fileserver") must be registered.
	//
	// Returns an error if the principal is not found or not authorized.
	GetKey(principalType PrincipalType, principal, realm string) (key []byte, err error)
}

// PrincipalStoreFunc is a function adapter for PrincipalStore.
type PrincipalStoreFunc func(principalType PrincipalType, principal, realm string) (key []byte, err error)

func (f PrincipalStoreFunc) GetKey(principalType PrincipalType, principal, realm string) ([]byte, error) {
	return f(principalType, principal, realm)
}

// KDCConfig configures the KDC.
type KDCConfig struct {
	// Realm is the Kerberos realm (e.g., "EXAMPLE.COM").
	Realm string

	// ListenAddr is the address to listen on (default ":88").
	ListenAddr string

	// Principals provides key lookup for users and services.
	// This is called for both AS-REQ (user authentication) and TGS-REQ (service tickets).
	Principals PrincipalStore

	// TicketLifetime is how long tickets are valid (default 10 hours).
	TicketLifetime time.Duration

	// Logger for debug output. If nil, logs are discarded.
	Logger *smblog.Logger
}

// KDC is a Kerberos Key Distribution Center.
type KDC struct {
	config KDCConfig

	// krbtgt key for TGT encryption
	krbtgtKey []byte

	udpListener *net.UDPConn
	tcpListener net.Listener

	mu      sync.Mutex
	running bool
	wg      sync.WaitGroup

	// Lifecycle channels
	ready chan struct{} // closed when listeners are ready
	done  chan struct{} // closed when fully stopped
}

// NewKDC creates a new KDC with the given configuration.
func NewKDC(cfg KDCConfig) (*KDC, error) {
	if cfg.Realm == "" {
		return nil, fmt.Errorf("realm is required")
	}
	if cfg.Principals == nil {
		return nil, fmt.Errorf("principal store is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":88"
	}
	if cfg.TicketLifetime == 0 {
		cfg.TicketLifetime = 10 * time.Hour
	}

	// Derive krbtgt key from a fixed password (for testing)
	// In production, this would be randomly generated and stored securely
	krbtgtKey, err := deriveKeyFromPassword(eTypeAES256SHA1, "krbtgt-secret-key", "krbtgt/"+cfg.Realm, cfg.Realm)
	if err != nil {
		return nil, fmt.Errorf("derive krbtgt key: %w", err)
	}

	return &KDC{
		config:    cfg,
		krbtgtKey: krbtgtKey,
		ready:     make(chan struct{}),
		done:      make(chan struct{}),
	}, nil
}

// Start starts the KDC in the background, listening on UDP and TCP.
// The KDC will automatically stop when ctx is cancelled.
// Use Wait() to block until the KDC has fully stopped.
// Use Ready() to get a channel that closes when the KDC is ready to accept connections.
func (k *KDC) Start(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if k.running {
		return fmt.Errorf("KDC already running")
	}

	// Start UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", k.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP addr: %w", err)
	}
	k.udpListener, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}

	// Start TCP listener
	k.tcpListener, err = net.Listen("tcp", k.config.ListenAddr)
	if err != nil {
		k.udpListener.Close()
		return fmt.Errorf("listen TCP: %w", err)
	}

	k.running = true

	// Start handler goroutines
	k.wg.Add(2)
	go k.serveUDP(ctx)
	go k.serveTCP(ctx)

	// Start shutdown watcher
	go k.watchContext(ctx)

	k.log("KDC started on %s (realm: %s)", k.config.ListenAddr, k.config.Realm)

	// Signal that we're ready
	close(k.ready)

	return nil
}

// watchContext monitors the context and stops the KDC when cancelled.
func (k *KDC) watchContext(ctx context.Context) {
	<-ctx.Done()
	k.stop()
}

// stop stops the KDC (internal, called by context watcher).
func (k *KDC) stop() {
	k.mu.Lock()
	if !k.running {
		k.mu.Unlock()
		return
	}
	k.running = false
	k.mu.Unlock()

	// Close listeners to stop accepting
	if k.udpListener != nil {
		k.udpListener.Close()
	}
	if k.tcpListener != nil {
		k.tcpListener.Close()
	}

	k.wg.Wait()
	k.log("KDC stopped")

	// Signal that we're done
	close(k.done)
}

// Wait blocks until the KDC has fully stopped.
// Call this after cancelling the context passed to Start.
func (k *KDC) Wait() {
	<-k.done
}

// Ready blocks until the KDC is ready to accept connections or the context is cancelled.
// Returns nil if ready, or the context error if cancelled before ready.
func (k *KDC) Ready(ctx context.Context) error {
	select {
	case <-k.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Addr returns the actual address the KDC is listening on.
// This is useful when ListenAddr uses port 0 for dynamic port assignment.
func (k *KDC) Addr() string {
	if k.tcpListener != nil {
		return k.tcpListener.Addr().String()
	}
	return k.config.ListenAddr
}

// Serve starts the KDC and blocks until ctx is cancelled.
// Deprecated: Use Start() and Wait() instead for more control.
func (k *KDC) Serve(ctx context.Context) error {
	if err := k.Start(ctx); err != nil {
		return err
	}
	k.Wait()
	return nil
}

func (k *KDC) serveUDP(ctx context.Context) {
	defer k.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		n, addr, err := k.udpListener.ReadFromUDP(buf)
		if err != nil {
			if k.isRunning() {
				k.log("UDP read error: %v", err)
			}
			return
		}

		// Handle request
		resp, err := k.handleRequest(buf[:n])
		if err != nil {
			k.log("UDP request from %s error: %v", addr, err)
			continue
		}

		// Send response
		_, err = k.udpListener.WriteToUDP(resp, addr)
		if err != nil {
			k.log("UDP write to %s error: %v", addr, err)
		}
	}
}

func (k *KDC) serveTCP(ctx context.Context) {
	defer k.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := k.tcpListener.Accept()
		if err != nil {
			if k.isRunning() {
				k.log("TCP accept error: %v", err)
			}
			return
		}

		go k.handleTCPConn(conn)
	}
}

func (k *KDC) handleTCPConn(conn net.Conn) {
	defer conn.Close()

	// TCP Kerberos uses 4-byte length prefix
	lenBuf := make([]byte, 4)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		_, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			if err != io.EOF {
				k.log("TCP read length error: %v", err)
			}
			return
		}

		msgLen := binary.BigEndian.Uint32(lenBuf)
		if msgLen > 65535 {
			k.log("TCP message too large: %d", msgLen)
			return
		}

		msgBuf := make([]byte, msgLen)
		_, err = io.ReadFull(conn, msgBuf)
		if err != nil {
			k.log("TCP read message error: %v", err)
			return
		}

		resp, err := k.handleRequest(msgBuf)
		if err != nil {
			k.log("TCP request error: %v", err)
			// Send error response
			resp = k.makeErrorResponse(err)
		}

		// Write response with length prefix
		respLen := make([]byte, 4)
		binary.BigEndian.PutUint32(respLen, uint32(len(resp)))
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(respLen); err != nil {
			k.log("TCP write length error: %v", err)
			return
		}
		if _, err := conn.Write(resp); err != nil {
			k.log("TCP write message error: %v", err)
			return
		}
	}
}

func (k *KDC) handleRequest(data []byte) ([]byte, error) {
	msgType, err := getMsgType(data)
	if err != nil {
		return nil, fmt.Errorf("get message type: %w", err)
	}

	switch msgType {
	case msgTypeASReq:
		return k.handleASReq(data)
	case msgTypeTGSReq:
		return k.handleTGSReq(data)
	default:
		return nil, fmt.Errorf("unsupported message type: %d", msgType)
	}
}

func (k *KDC) handleASReq(data []byte) ([]byte, error) {
	req, err := unmarshalASReq(data)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AS-REQ: %w", err)
	}

	// Extract client principal
	clientPrincipal := req.ReqBody.CName.String()
	realm := req.ReqBody.Realm

	k.log("AS-REQ from %s@%s (PAData count: %d)", clientPrincipal, realm, len(req.PAData))

	// Verify realm
	if !strings.EqualFold(realm, k.config.Realm) {
		return k.makeKRBError(errClientNotFound, realm, req.ReqBody.CName, req.ReqBody.SName, "realm mismatch")
	}

	// Get client's pre-computed key from principal store
	clientKey, err := k.config.Principals.GetKey(PrincipalUser, clientPrincipal, realm)
	if err != nil {
		k.log("Client authentication failed for %s: %v", clientPrincipal, err)
		return k.makeKRBError(errClientNotFound, realm, req.ReqBody.CName, req.ReqBody.SName, "client not found")
	}

	// Verify client supports AES256 (we only support this encryption type)
	etype := k.selectEType(req.ReqBody.EType)
	if etype == 0 {
		return k.makeKRBError(errGeneric, realm, req.ReqBody.CName, req.ReqBody.SName, "no supported encryption type (AES256 required)")
	}
	// Check for pre-authentication
	hasPreAuth := false
	for _, pa := range req.PAData {
		if pa.PADataType == paTypeEncTimestamp {
			// Verify encrypted timestamp
			var encTS encryptedData
			if _, err := asn1.Unmarshal(pa.PADataValue, &encTS); err != nil {
				k.log("Failed to unmarshal PA-ENC-TIMESTAMP: %v", err)
				continue
			}

			tsData, err := decrypt(EncryptionKey{KeyType: etype, KeyValue: clientKey},
				keyUsageASReqTimestamp, encTS)
			if err != nil {
				k.log("Failed to decrypt PA-ENC-TIMESTAMP: %v", err)
				return k.makeKRBError(errPreAuthFailed, realm, req.ReqBody.CName, req.ReqBody.SName, "pre-authentication failed")
			}

			var ts paEncTimestamp
			if _, err := asn1.Unmarshal(tsData, &ts); err != nil {
				k.log("Failed to unmarshal timestamp: %v", err)
				continue
			}

			// Check timestamp is recent (within 5 minutes)
			diff := time.Since(ts.PATimestamp)
			if diff < 0 {
				diff = -diff
			}
			if diff > 5*time.Minute {
				return k.makeKRBError(errPreAuthFailed, realm, req.ReqBody.CName, req.ReqBody.SName, "timestamp out of range")
			}

			hasPreAuth = true
			break
		}
	}

	if !hasPreAuth {
		// Request pre-authentication
		return k.makePreAuthRequired(realm, req.ReqBody.CName, req.ReqBody.SName, etype)
	}

	// Generate session key
	sessionKey, err := generateSessionKey(etype)
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	// Build TGT
	now := time.Now().UTC()
	endTime := now.Add(k.config.TicketLifetime)

	tgt, err := k.buildTGT(req.ReqBody.CName, realm, sessionKey, now, endTime)
	if err != nil {
		return nil, fmt.Errorf("build TGT: %w", err)
	}

	// Build AS-REP
	rep, err := k.buildASRep(req, clientKey, sessionKey, tgt, now, endTime)
	if err != nil {
		return nil, fmt.Errorf("build AS-REP: %w", err)
	}

	k.log("AS-REP sent to %s@%s", clientPrincipal, realm)
	return rep, nil
}

func (k *KDC) handleTGSReq(data []byte) ([]byte, error) {
	req, err := unmarshalTGSReq(data)
	if err != nil {
		return nil, fmt.Errorf("unmarshal TGS-REQ: %w", err)
	}

	// Find AP-REQ in PA-DATA (contains the TGT)
	var apReqData []byte
	for _, pa := range req.PAData {
		if pa.PADataType == paTypeTGSReq {
			apReqData = pa.PADataValue
			break
		}
	}
	if apReqData == nil {
		return k.makeKRBError(errGeneric, k.config.Realm, principalName{}, req.ReqBody.SName, "no PA-TGS-REQ")
	}

	// Parse AP-REQ
	apReq, err := unmarshalAPReq(apReqData)
	if err != nil {
		return nil, fmt.Errorf("unmarshal AP-REQ: %w", err)
	}

	// Extract Ticket from RawValue
	apReqTicket, err := unmarshalTicket(apReq.TicketBytes)
	if err != nil {
		return nil, fmt.Errorf("parse ticket from AP-REQ: %w", err)
	}

	// Decrypt TGT
	tgtKey := EncryptionKey{
		KeyType:  eTypeAES256SHA1,
		KeyValue: k.krbtgtKey,
	}

	ticketData, err := decrypt(tgtKey, keyUsageTicket, apReqTicket.EncPart)
	if err != nil {
		k.log("Failed to decrypt TGT: %v", err)
		return k.makeKRBError(errBadIntegrity, k.config.Realm, principalName{}, req.ReqBody.SName, "invalid TGT")
	}

	// Unmarshal ticket
	inner, _, err := unwrapAppTag(ticketData)
	if err != nil {
		return nil, fmt.Errorf("unwrap EncTicketPart: %w", err)
	}
	var encTicket encTicketPart
	if _, err := asn1.Unmarshal(inner, &encTicket); err != nil {
		return nil, fmt.Errorf("unmarshal EncTicketPart: %w", err)
	}

	// Check ticket expiry
	if time.Now().After(encTicket.EndTime) {
		return k.makeKRBError(errTicketExpired, k.config.Realm, encTicket.CName, req.ReqBody.SName, "TGT expired")
	}

	// Get session key from TGT
	tgtSessionKey := encTicket.Key

	// Decrypt authenticator
	authData, err := decrypt(tgtSessionKey, keyUsageTGSReqAuth, apReq.Auth)
	if err != nil {
		k.log("Failed to decrypt authenticator: %v", err)
		return k.makeKRBError(errBadIntegrity, k.config.Realm, encTicket.CName, req.ReqBody.SName,
			"invalid authenticator")
	}

	// Unmarshal authenticator
	inner, _, err = unwrapAppTag(authData)
	if err != nil {
		return nil, fmt.Errorf("unwrap authenticator: %w", err)
	}
	var auth authenticator
	if _, err := asn1.Unmarshal(inner, &auth); err != nil {
		return nil, fmt.Errorf("unmarshal authenticator: %w", err)
	}

	// Verify authenticator matches ticket
	if auth.CRealm != encTicket.CRealm || auth.CName.String() != encTicket.CName.String() {
		return k.makeKRBError(errBadIntegrity, k.config.Realm, encTicket.CName, req.ReqBody.SName, "authenticator mismatch")
	}

	// Get service principal
	servicePrincipal := req.ReqBody.SName.String()
	k.log("TGS-REQ from %s@%s for %s", encTicket.CName.String(), encTicket.CRealm, servicePrincipal)

	// Look up pre-computed service key from principal store
	serviceKeyBytes, err := k.config.Principals.GetKey(PrincipalService, servicePrincipal, k.config.Realm)
	if err != nil {
		k.log("Service not found: %s: %v", servicePrincipal, err)
		return k.makeKRBError(errServiceNotFound, k.config.Realm, encTicket.CName, req.ReqBody.SName, "service not found")
	}

	// Use AES256 for all service tickets (only supported encryption type)
	serviceKey := EncryptionKey{KeyType: eTypeAES256SHA1, KeyValue: serviceKeyBytes}

	// Generate new session key for service (AES256 only)
	newSessionKey, err := generateSessionKey(eTypeAES256SHA1)
	if err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}

	// Build service ticket
	now := time.Now().UTC()
	endTime := now.Add(k.config.TicketLifetime)
	if endTime.After(encTicket.EndTime) {
		endTime = encTicket.EndTime
	}

	serviceTicket, err := k.buildServiceTicket(encTicket.CName, encTicket.CRealm,
		req.ReqBody.SName, newSessionKey, serviceKey,
		now, endTime)
	if err != nil {
		return nil, fmt.Errorf("build service ticket: %w", err)
	}

	// Build TGS-REP
	rep, err := k.buildTGSRep(req, encTicket.CName, encTicket.CRealm, tgtSessionKey, newSessionKey, serviceTicket, now, endTime)
	if err != nil {
		return nil, fmt.Errorf("build TGS-REP: %w", err)
	}

	k.log("TGS-REP sent for %s", servicePrincipal)
	return rep, nil
}

func (k *KDC) selectEType(clientTypes []int32) int32 {
	// This KDC only supports AES256-CTS-HMAC-SHA1-96 (etype 18).
	// To extend for multiple encryption types:
	// 1. Change Services from map[string][]byte to map[string]map[int32][]byte
	//    to store pre-computed keys for each supported etype.
	// 2. Update ClientAuthenticator.GetKey() to accept an etype parameter
	//    and return the appropriate key for that encryption type.
	// 3. Modify this function to negotiate based on what keys are available.
	// 4. Update handleASReq and handleTGSReq to use the negotiated etype.
	for _, ct := range clientTypes {
		if ct == eTypeAES256SHA1 {
			return eTypeAES256SHA1
		}
	}
	return 0
}

func (k *KDC) buildTGT(cname principalName, realm string, sessionKey EncryptionKey,
	authTime, endTime time.Time) (ticket, error) {

	// Build EncTicketPart
	encPart := encTicketPart{
		Flags:     asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32}, // INITIAL, PRE-AUTHENT
		Key:       sessionKey,
		CRealm:    realm,
		CName:     cname,
		Transited: transitedEnc{TRType: 1, Contents: []byte{}},
		AuthTime:  authTime,
		EndTime:   endTime,
	}

	encPartBytes, err := marshalEncTicketPart(encPart)
	if err != nil {
		return ticket{}, fmt.Errorf("marshal EncTicketPart: %w", err)
	}

	// Encrypt with krbtgt key
	tgtKey := EncryptionKey{
		KeyType:  eTypeAES256SHA1,
		KeyValue: k.krbtgtKey,
	}
	encData, err := encrypt(tgtKey, keyUsageTicket, encPartBytes)
	if err != nil {
		return ticket{}, fmt.Errorf("encrypt TGT: %w", err)
	}

	return ticket{
		TktVNO: 5,
		Realm:  realm,
		SName: principalName{
			NameType:   nameTypeSrvInst,
			NameString: []string{"krbtgt", realm},
		},
		EncPart: encData,
	}, nil
}

func (k *KDC) buildServiceTicket(cname principalName, crealm string, sname principalName,
	sessionKey, serviceKey EncryptionKey, authTime, endTime time.Time) (ticket, error) {

	encPart := encTicketPart{
		Flags:     asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32},
		Key:       sessionKey,
		CRealm:    crealm,
		CName:     cname,
		Transited: transitedEnc{TRType: 1, Contents: []byte{}},
		AuthTime:  authTime,
		EndTime:   endTime,
	}

	encPartBytes, err := marshalEncTicketPart(encPart)
	if err != nil {
		return ticket{}, fmt.Errorf("marshal EncTicketPart: %w", err)
	}

	encData, err := encrypt(serviceKey, keyUsageTicket, encPartBytes)
	if err != nil {
		return ticket{}, fmt.Errorf("encrypt ticket: %w", err)
	}

	return ticket{
		TktVNO:  5,
		Realm:   k.config.Realm,
		SName:   sname,
		EncPart: encData,
	}, nil
}

func (k *KDC) buildASRep(req *asReq, clientKey []byte, sessionKey EncryptionKey,
	ticket ticket, authTime, endTime time.Time) ([]byte, error) {

	// Marshal ticket with APPLICATION 1 tag
	ticketBytes, err := marshalTicket(ticket)
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	// Build EncKDCRepPart
	encRepPart := encKDCRepPart{
		Key:      sessionKey,
		LastReq:  []lastReqEntry{{LRType: 0, LRValue: authTime}},
		Nonce:    req.ReqBody.Nonce,
		Flags:    asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32},
		AuthTime: authTime,
		EndTime:  endTime,
		SRealm:   k.config.Realm,
		SName:    ticket.SName,
	}

	encRepPartBytes, err := marshalEncASRepPart(encRepPart)
	if err != nil {
		return nil, fmt.Errorf("marshal EncKDCRepPart: %w", err)
	}

	// Encrypt with client key
	encData, err := encrypt(EncryptionKey{KeyType: sessionKey.KeyType, KeyValue: clientKey}, keyUsageASRepEncPart, encRepPartBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt AS-REP: %w", err)
	}

	rep := asRep{
		PVNO:        5,
		MsgType:     msgTypeASRep,
		CRealm:      req.ReqBody.Realm,
		CName:       req.ReqBody.CName,
		TicketBytes: ticketBytes, // Already has APPLICATION 1 tag
		EncPart:     encData,
	}

	return marshalASRep(rep)
}

func (k *KDC) buildTGSRep(req *tgsReq, cname principalName, crealm string,
	tgtSessionKey, newSessionKey EncryptionKey,
	ticket ticket, authTime, endTime time.Time) ([]byte, error) {

	// Marshal ticket with APPLICATION 1 tag
	ticketBytes, err := marshalTicket(ticket)
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	// Build EncKDCRepPart
	encRepPart := encKDCRepPart{
		Key:      newSessionKey,
		LastReq:  []lastReqEntry{{LRType: 0, LRValue: authTime}},
		Nonce:    req.ReqBody.Nonce,
		Flags:    asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32},
		AuthTime: authTime,
		EndTime:  endTime,
		SRealm:   k.config.Realm,
		SName:    req.ReqBody.SName,
	}

	encRepPartBytes, err := marshalEncTGSRepPart(encRepPart)
	if err != nil {
		return nil, fmt.Errorf("marshal EncKDCRepPart: %w", err)
	}

	// Encrypt with TGT session key
	encData, err := encrypt(tgtSessionKey, keyUsageTGSRepEncPart, encRepPartBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt TGS-REP: %w", err)
	}

	rep := tgsRep{
		PVNO:        5,
		MsgType:     msgTypeTGSRep,
		CRealm:      crealm,
		CName:       cname,
		TicketBytes: ticketBytes, // Already has APPLICATION 1 tag
		EncPart:     encData,
	}

	return marshalTGSRep(rep)
}

func (k *KDC) makePreAuthRequired(realm string, cname, sname principalName, etype int32) ([]byte, error) {
	// Build ETYPE-INFO2 with GeneralString encoding.
	// Currently only AES256 is advertised since selectEType only returns AES256.
	// To support multiple etypes, add additional entries to etypeInfo for each
	// supported encryption type.
	etypeInfo := []eTypeInfo2Entry{{
		EType: etype,
		Salt:  realm + cname.String(),
	}}

	etypeInfoBytes, err := marshalETypeInfo2(etypeInfo)
	if err != nil {
		return nil, err
	}

	// Include both PA-ENC-TIMESTAMP (type 2) as accepted method
	// and PA-ETYPE-INFO2 (type 19) with etype/salt info
	errData := []paData{
		{
			PADataType:  paTypeEncTimestamp, // PA-ENC-TIMESTAMP - indicates this method is accepted
			PADataValue: nil,                // Empty value - just indicates the method is supported
		},
		{
			PADataType:  paTypeETypeInfo2, // PA-ETYPE-INFO2 - provides etype and salt info
			PADataValue: etypeInfoBytes,
		},
	}
	errDataBytes, err := marshalPAData(errData)
	if err != nil {
		return nil, err
	}

	krbErr := krbError{
		PVNO:      5,
		MsgType:   msgTypeError,
		STime:     time.Now().UTC(),
		SUSec:     0,
		ErrorCode: errPreAuthRequired,
		Realm:     realm,
		SName:     sname,
		EText:     "Pre-authentication required",
		EData:     errDataBytes,
	}

	data, err := marshalKRBError(krbErr)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (k *KDC) makeKRBError(code int32, realm string, cname, sname principalName, text string) ([]byte, error) {
	krbErr := krbError{
		PVNO:      5,
		MsgType:   msgTypeError,
		STime:     time.Now().UTC(),
		SUSec:     0,
		ErrorCode: code,
		CRealm:    realm,
		CName:     cname,
		Realm:     realm,
		SName:     sname,
		EText:     text,
	}

	return marshalKRBError(krbErr)
}

func (k *KDC) makeErrorResponse(err error) []byte {
	resp, _ := k.makeKRBError(errGeneric, k.config.Realm, principalName{}, principalName{}, err.Error())
	return resp
}

func (k *KDC) isRunning() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.running
}

func (k *KDC) log(format string, args ...any) {
	if k.config.Logger != nil {
		k.config.Logger.Printf(smblog.AreaAuth, "[KDC] "+format, args...)
	}
}
