package krb5

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// ClientAuthenticator authenticates clients for the KDC.
// Implement this interface to provide custom authentication logic.
type ClientAuthenticator interface {
	// Authenticate is called when a client requests a TGT.
	// Returns the client's password if authentication succeeds, or an error.
	// The password is used to derive keys and verify pre-authentication.
	Authenticate(principal, realm string) (password string, err error)
}

// ClientAuthenticatorFunc is a function adapter for ClientAuthenticator.
type ClientAuthenticatorFunc func(principal, realm string) (password string, err error)

func (f ClientAuthenticatorFunc) Authenticate(principal, realm string) (string, error) {
	return f(principal, realm)
}

// ServiceKey represents a service principal's key material.
type ServiceKey struct {
	Principal string // e.g., "cifs/server.example.com"
	Password  string // Used to derive keys
}

// KDCConfig configures the KDC.
type KDCConfig struct {
	// Realm is the Kerberos realm (e.g., "EXAMPLE.COM").
	Realm string

	// ListenAddr is the address to listen on (default ":88").
	ListenAddr string

	// ClientAuth authenticates clients requesting TGTs.
	ClientAuth ClientAuthenticator

	// Services maps service principal names to their passwords.
	// The KDC uses these to encrypt service tickets.
	Services map[string]string

	// TicketLifetime is how long tickets are valid (default 10 hours).
	TicketLifetime time.Duration

	// Logger for debug output. If nil, logs are discarded.
	Logger *log.Logger
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
	if cfg.ClientAuth == nil {
		return nil, fmt.Errorf("client authenticator is required")
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":88"
	}
	if cfg.TicketLifetime == 0 {
		cfg.TicketLifetime = 10 * time.Hour
	}

	// Derive krbtgt key from a fixed password (for testing)
	// In production, this would be randomly generated and stored securely
	krbtgtKey, err := DeriveKey(ETypeAES256SHA1, "krbtgt-secret-key", "krbtgt/"+cfg.Realm, cfg.Realm)
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
	go k.serveUDP()
	go k.serveTCP()

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

// Done returns a channel that is closed when the KDC has fully stopped.
func (k *KDC) Done() <-chan struct{} {
	return k.done
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

func (k *KDC) serveUDP() {
	defer k.wg.Done()

	buf := make([]byte, 65535)
	for {
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

func (k *KDC) serveTCP() {
	defer k.wg.Done()

	for {
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
		return k.makeKRBError(errClientNotFound, realm, req.ReqBody.CName, req.ReqBody.SName,
			"realm mismatch")
	}

	// Authenticate client
	password, err := k.config.ClientAuth.Authenticate(clientPrincipal, realm)
	if err != nil {
		k.log("Client authentication failed for %s: %v", clientPrincipal, err)
		return k.makeKRBError(errClientNotFound, realm, req.ReqBody.CName, req.ReqBody.SName,
			"client not found")
	}

	// Select encryption type (prefer what client supports)
	etype := k.selectEType(req.ReqBody.EType)
	if etype == 0 {
		return k.makeKRBError(errGeneric, realm, req.ReqBody.CName, req.ReqBody.SName,
			"no supported encryption type")
	}

	// Derive client key
	clientKey, err := DeriveKey(etype, password, clientPrincipal, realm)
	if err != nil {
		return nil, fmt.Errorf("derive client key: %w", err)
	}
	// Check for pre-authentication
	hasPreAuth := false
	for _, pa := range req.PAData {
		if pa.PADataType == paEncTimestamp {
			// Verify encrypted timestamp
			var encTS EncryptedData
			if _, err := asn1.Unmarshal(pa.PADataValue, &encTS); err != nil {
				k.log("Failed to unmarshal PA-ENC-TIMESTAMP: %v", err)
				continue
			}

			tsData, err := Decrypt(EncryptionKey{KeyType: etype, KeyValue: clientKey},
				keyUsageASReqTimestamp, encTS)
			if err != nil {
				k.log("Failed to decrypt PA-ENC-TIMESTAMP: %v", err)
				return k.makeKRBError(errPreAuthFailed, realm, req.ReqBody.CName, req.ReqBody.SName,
					"pre-authentication failed")
			}

			var ts PAEncTimestamp
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
				return k.makeKRBError(errPreAuthFailed, realm, req.ReqBody.CName, req.ReqBody.SName,
					"timestamp out of range")
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
	sessionKey, err := GenerateSessionKey(etype)
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
		if pa.PADataType == 1 { // PA-TGS-REQ
			apReqData = pa.PADataValue
			break
		}
	}
	if apReqData == nil {
		return k.makeKRBError(errGeneric, k.config.Realm, PrincipalName{}, req.ReqBody.SName,
			"no PA-TGS-REQ")
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
		KeyType:  ETypeAES256SHA1,
		KeyValue: k.krbtgtKey,
	}

	ticketData, err := Decrypt(tgtKey, keyUsageTicket, apReqTicket.EncPart)
	if err != nil {
		k.log("Failed to decrypt TGT: %v", err)
		return k.makeKRBError(errBadIntegrity, k.config.Realm, PrincipalName{}, req.ReqBody.SName,
			"invalid TGT")
	}

	// Unmarshal ticket
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
		return k.makeKRBError(errTicketExpired, k.config.Realm, encTicket.CName, req.ReqBody.SName,
			"TGT expired")
	}

	// Get session key from TGT
	tgtSessionKey := encTicket.Key

	// Decrypt authenticator (key usage 7 for TGS-REQ)
	authData, err := Decrypt(tgtSessionKey, 7, apReq.Auth)
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
	var auth Authenticator
	if _, err := asn1.Unmarshal(inner, &auth); err != nil {
		return nil, fmt.Errorf("unmarshal authenticator: %w", err)
	}

	// Verify authenticator matches ticket
	if auth.CRealm != encTicket.CRealm || auth.CName.String() != encTicket.CName.String() {
		return k.makeKRBError(errBadIntegrity, k.config.Realm, encTicket.CName, req.ReqBody.SName,
			"authenticator mismatch")
	}

	// Get service principal
	servicePrincipal := req.ReqBody.SName.String()
	k.log("TGS-REQ from %s@%s for %s", encTicket.CName.String(), encTicket.CRealm, servicePrincipal)

	// Look up service key
	servicePassword, ok := k.config.Services[servicePrincipal]
	if !ok {
		return k.makeKRBError(errServiceNotFound, k.config.Realm, encTicket.CName, req.ReqBody.SName,
			"service not found")
	}

	// Derive service key
	etype := tgtSessionKey.KeyType
	serviceKey, err := DeriveKey(etype, servicePassword, servicePrincipal, k.config.Realm)
	if err != nil {
		return nil, fmt.Errorf("derive service key: %w", err)
	}

	// Generate new session key for service
	newSessionKey, err := GenerateSessionKey(etype)
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
		req.ReqBody.SName, newSessionKey, EncryptionKey{KeyType: etype, KeyValue: serviceKey},
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
	// Prefer AES256, then AES128
	preferred := []int32{ETypeAES256SHA1, ETypeAES128SHA1}
	for _, pref := range preferred {
		for _, ct := range clientTypes {
			if ct == pref {
				return pref
			}
		}
	}
	return 0
}

func (k *KDC) buildTGT(cname PrincipalName, realm string, sessionKey EncryptionKey,
	authTime, endTime time.Time) (Ticket, error) {

	// Build EncTicketPart
	encPart := EncTicketPart{
		Flags:     asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32}, // INITIAL, PRE-AUTHENT
		Key:       sessionKey,
		CRealm:    realm,
		CName:     cname,
		Transited: TransitedEnc{TRType: 1, Contents: []byte{}},
		AuthTime:  authTime,
		EndTime:   endTime,
	}

	encPartBytes, err := marshalEncTicketPart(encPart)
	if err != nil {
		return Ticket{}, fmt.Errorf("marshal EncTicketPart: %w", err)
	}

	// Encrypt with krbtgt key
	tgtKey := EncryptionKey{
		KeyType:  ETypeAES256SHA1,
		KeyValue: k.krbtgtKey,
	}
	encData, err := Encrypt(tgtKey, keyUsageTicket, encPartBytes)
	if err != nil {
		return Ticket{}, fmt.Errorf("encrypt TGT: %w", err)
	}

	return Ticket{
		TktVNO: 5,
		Realm:  realm,
		SName: PrincipalName{
			NameType:   nameTypeSrvInst,
			NameString: []string{"krbtgt", realm},
		},
		EncPart: encData,
	}, nil
}

func (k *KDC) buildServiceTicket(cname PrincipalName, crealm string, sname PrincipalName,
	sessionKey, serviceKey EncryptionKey, authTime, endTime time.Time) (Ticket, error) {

	encPart := EncTicketPart{
		Flags:     asn1.BitString{Bytes: []byte{0x40, 0x80, 0x00, 0x00}, BitLength: 32},
		Key:       sessionKey,
		CRealm:    crealm,
		CName:     cname,
		Transited: TransitedEnc{TRType: 1, Contents: []byte{}},
		AuthTime:  authTime,
		EndTime:   endTime,
	}

	encPartBytes, err := marshalEncTicketPart(encPart)
	if err != nil {
		return Ticket{}, fmt.Errorf("marshal EncTicketPart: %w", err)
	}

	encData, err := Encrypt(serviceKey, keyUsageTicket, encPartBytes)
	if err != nil {
		return Ticket{}, fmt.Errorf("encrypt ticket: %w", err)
	}

	return Ticket{
		TktVNO:  5,
		Realm:   k.config.Realm,
		SName:   sname,
		EncPart: encData,
	}, nil
}

func (k *KDC) buildASRep(req *ASReq, clientKey []byte, sessionKey EncryptionKey,
	ticket Ticket, authTime, endTime time.Time) ([]byte, error) {

	// Marshal ticket with APPLICATION 1 tag
	ticketBytes, err := marshalTicket(ticket)
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	// Build EncKDCRepPart
	encRepPart := EncKDCRepPart{
		Key:      sessionKey,
		LastReq:  []LastReqEntry{{LRType: 0, LRValue: authTime}},
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
	encData, err := Encrypt(EncryptionKey{KeyType: sessionKey.KeyType, KeyValue: clientKey},
		keyUsageASRepEncPart, encRepPartBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt AS-REP: %w", err)
	}

	rep := ASRep{
		PVNO:        5,
		MsgType:     msgTypeASRep,
		CRealm:      req.ReqBody.Realm,
		CName:       req.ReqBody.CName,
		TicketBytes: ticketBytes, // Already has APPLICATION 1 tag
		EncPart:     encData,
	}

	return marshalASRep(rep)
}

func (k *KDC) buildTGSRep(req *TGSReq, cname PrincipalName, crealm string,
	tgtSessionKey, newSessionKey EncryptionKey,
	ticket Ticket, authTime, endTime time.Time) ([]byte, error) {

	// Marshal ticket with APPLICATION 1 tag
	ticketBytes, err := marshalTicket(ticket)
	if err != nil {
		return nil, fmt.Errorf("marshal ticket: %w", err)
	}

	// Build EncKDCRepPart
	encRepPart := EncKDCRepPart{
		Key:      newSessionKey,
		LastReq:  []LastReqEntry{{LRType: 0, LRValue: authTime}},
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
	encData, err := Encrypt(tgtSessionKey, keyUsageTGSRepEncPart, encRepPartBytes)
	if err != nil {
		return nil, fmt.Errorf("encrypt TGS-REP: %w", err)
	}

	rep := TGSRep{
		PVNO:        5,
		MsgType:     msgTypeTGSRep,
		CRealm:      crealm,
		CName:       cname,
		TicketBytes: ticketBytes, // Already has APPLICATION 1 tag
		EncPart:     encData,
	}

	return marshalTGSRep(rep)
}

func (k *KDC) makePreAuthRequired(realm string, cname, sname PrincipalName, etype int32) ([]byte, error) {
	// Build ETYPE-INFO2 with GeneralString encoding
	etypeInfo := []ETypeInfo2Entry{{
		EType: etype,
		Salt:  realm + cname.String(),
	}}

	etypeInfoBytes, err := marshalETypeInfo2(etypeInfo)
	if err != nil {
		return nil, err
	}

	// Include both PA-ENC-TIMESTAMP (type 2) as accepted method
	// and PA-ETYPE-INFO2 (type 19) with etype/salt info
	errData := []PAData{
		{
			PADataType:  paEncTimestamp, // PA-ENC-TIMESTAMP - indicates this method is accepted
			PADataValue: nil,            // Empty value - just indicates the method is supported
		},
		{
			PADataType:  paETypeInfo2, // PA-ETYPE-INFO2 - provides etype and salt info
			PADataValue: etypeInfoBytes,
		},
	}
	errDataBytes, err := marshalPAData(errData)
	if err != nil {
		return nil, err
	}

	krbErr := KRBError{
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

func (k *KDC) makeKRBError(code int32, realm string, cname, sname PrincipalName, text string) ([]byte, error) {
	krbErr := KRBError{
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
	resp, _ := k.makeKRBError(errGeneric, k.config.Realm, PrincipalName{}, PrincipalName{}, err.Error())
	return resp
}

func (k *KDC) isRunning() bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.running
}

func (k *KDC) log(format string, args ...interface{}) {
	if k.config.Logger != nil {
		k.config.Logger.Printf("[KDC] "+format, args...)
	}
}
