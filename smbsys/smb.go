package smbsys

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/crypto/md4"
	"golang.org/x/sys/unix"
)

// --- Configuration ---
const (
	moduleName = "ksmbd"
	genlName   = "SMBD_GENL" // Use the family name discovered via NLM_F_DUMP
)

// Protocol version constants for MinProtocol and MaxProtocol configuration.
const (
	ProtocolSMB2   = "SMB2"   // SMB 2.0
	ProtocolSMB21  = "SMB21"  // SMB 2.1
	ProtocolSMB300 = "SMB300" // SMB 3.0
	ProtocolSMB302 = "SMB302" // SMB 3.0.2
	ProtocolSMB311 = "SMB311" // SMB 3.1.1
)

// PassHash is a 16-byte NTLM password hash (MD4 of UTF-16LE encoded password).
// While MD4 is cryptographically weak, NTLM uses this hash in a challenge-response
// protocol where the server sends a random nonce and the client proves knowledge
// of the hash via HMAC-MD5, so the hash itself is not transmitted directly.
type PassHash [16]byte

// NewPassHash computes an NTLM password hash from a plaintext password.
// The password is converted to UTF-16LE and hashed with MD4.
func NewPassHash(password string) PassHash {
	// Convert password to UTF-16 code units (handles surrogates for chars outside BMP)
	runes := []rune(password)
	u16 := utf16.Encode(runes)

	// Convert to little-endian bytes
	buf := make([]byte, len(u16)*2)
	for i, v := range u16 {
		buf[i*2] = byte(v)
		buf[i*2+1] = byte(v >> 8)
	}

	// Compute MD4 hash
	h := md4.New()
	h.Write(buf)
	var hash PassHash
	copy(hash[:], h.Sum(nil))
	return hash
}

// UserCredentials contains the credentials for an authenticated user.
type UserCredentials struct {
	PasswordHash PassHash
	UID          uint32
	GID          uint32
}

// NTLMAuthenticator provides NTLM-based user authentication for the SMB server.
// This authenticator is used for NTLMv2 authentication (the default for modern
// Windows clients when Kerberos is not available).
//
// Implement this interface to provide custom NTLM authentication logic.
// For Kerberos-based authentication, implement KerberosAuthenticator instead.
//
// At least one of NTLMAuthenticator or KerberosAuthenticator must be provided
// when starting the SMB server.
type NTLMAuthenticator interface {
	// Authenticate checks if the given username exists and returns credentials.
	// Return credentials, nil if the user exists.
	// Return nil, nil if the user doesn't exist (login will be rejected).
	// Return nil, error if there was an error during authentication.
	//
	// Note: PasswordHash must be the NTLM hash (MD4 of UTF-16LE password) because
	// the kernel uses it to verify the client's NTLMv2 challenge-response.
	Authenticate(handle uint32, username string) (*UserCredentials, error)
}

// StaticNTLMAuthenticator is a simple NTLM authenticator that uses a static user list.
// Use NewPassHash to compute the NTLM hash from a plain-text password.
type StaticNTLMAuthenticator struct {
	Users map[string]*UserCredentials
}

// NewStaticNTLMAuthenticator creates a new static NTLM authenticator from a user map.
// The UserCredentials.PasswordHash must contain the NTLM hash (use NewPassHash).
func NewStaticNTLMAuthenticator(users map[string]*UserCredentials) *StaticNTLMAuthenticator {
	return &StaticNTLMAuthenticator{Users: users}
}

// Authenticate implements NTLMAuthenticator.
func (a *StaticNTLMAuthenticator) Authenticate(handle uint32, username string) (*UserCredentials, error) {
	if a.Users == nil {
		return nil, nil
	}
	creds, ok := a.Users[username]
	if !ok {
		return nil, nil
	}
	return creds, nil
}

// --- Security Configuration ---

// Signing configuration options for ksmbd.
// These control whether SMB packet signing is required.
const (
	// SigningDisabled disables packet signing entirely (INSECURE).
	// Data can be modified in transit without detection.
	SigningDisabled = 0

	// SigningEnabled enables signing if the client supports it.
	// Clients that support signing will use it, others won't.
	SigningEnabled = 1

	// SigningAuto lets ksmbd decide based on negotiation.
	SigningAuto = 2

	// SigningMandatory requires signing for all connections (RECOMMENDED).
	// Clients that don't support signing will be rejected.
	SigningMandatory = 3
)

// Global configuration flags for ksmbd startup.
// These flags correspond to KSMBD_GLOBAL_FLAG_* in the kernel netlink interface.
const (
	// GlobalFlagSMB2Leases enables SMB2 lease support.
	GlobalFlagSMB2Leases = 1 << 0

	// GlobalFlagSMB2Encryption enables SMB3 encryption support.
	// When enabled, encryption can be negotiated with clients.
	GlobalFlagSMB2Encryption = 1 << 1

	// GlobalFlagSMB3Multichannel enables SMB3 multichannel support.
	GlobalFlagSMB3Multichannel = 1 << 2

	// GlobalFlagSMB2EncryptionOff explicitly disables encryption.
	// Use this to ensure no encryption is used (INSECURE).
	GlobalFlagSMB2EncryptionOff = 1 << 3
)

// ServerConfig holds security and operational configuration for the SMB server.
type ServerConfig struct {
	// Signing controls packet signing behavior.
	// Use SigningMandatory for secure deployments.
	// Default: SigningEnabled
	Signing int32

	// Encryption enables SMB3 encryption support.
	// When true, GlobalFlagSMB2Encryption is set.
	// Default: true
	Encryption bool

	// RequireEncryption when true, only allows encrypted connections.
	// Requires Encryption to be true.
	// Default: false
	RequireEncryption bool

	// MinProtocol is the minimum SMB protocol version.
	// Valid values: "SMB2", "SMB21", "SMB300", "SMB302", "SMB311"
	// Default: "SMB300" (SMB 3.0 - no SMB1/SMB2.0)
	MinProtocol string

	// MaxProtocol is the maximum SMB protocol version.
	// Default: "SMB311" (SMB 3.1.1)
	MaxProtocol string

	// TCPPort is the TCP port to listen on.
	// Default: 445 (standard SMB port)
	TCPPort uint16

	// NetBIOSName is the server's NetBIOS name.
	// Default: "GO-SERVER"
	NetBIOSName string

	// WorkGroup is the server's workgroup.
	// Default: "WORKGROUP"
	WorkGroup string

	// ServerString is the server description string.
	// Default: "Go KSMBD Server"
	ServerString string

	// MaxConnections limits simultaneous connections.
	// Default: 100
	MaxConnections uint32
}

// DefaultServerConfig returns a secure default configuration.
// - Signing is ENABLED (upgrade to MANDATORY for high-security environments)
// - Encryption is ENABLED
// - Minimum protocol is SMB 3.0 (no SMB1 or SMB 2.0)
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Signing:        SigningEnabled,
		Encryption:     true,
		MinProtocol:    "SMB300",
		MaxProtocol:    "SMB311",
		TCPPort:        445,
		NetBIOSName:    "GO-SERVER",
		WorkGroup:      "WORKGROUP",
		ServerString:   "Go KSMBD Server",
		MaxConnections: 100,
	}
}

// SecureServerConfig returns a high-security configuration.
// - Signing is MANDATORY
// - Encryption is ENABLED
// - Minimum protocol is SMB 3.0
func SecureServerConfig() ServerConfig {
	cfg := DefaultServerConfig()
	cfg.Signing = SigningMandatory
	return cfg
}

// --- Logging ---

// LogArea identifies different logging areas for filtering.
type LogArea int

const (
	LogAreaGeneral LogArea = iota
	LogAreaNetlink
	LogAreaRPC
	LogAreaAuth
	LogAreaShare
	LogAreaTree
)

// Logger provides logging with areas and verbosity control.
type Logger struct {
	output    io.Writer
	enabled   bool
	verbosity int              // 0=errors only, 1=info, 2=debug, 3=trace
	areas     map[LogArea]bool // nil means all areas enabled
}

// NewLogger creates a new logger. If output is nil, logging is disabled.
func NewLogger(output io.Writer) *Logger {
	return &Logger{
		output:    output,
		enabled:   output != nil,
		verbosity: 1,
		areas:     nil, // all areas enabled by default
	}
}

// SetVerbosity sets the verbosity level (0-3).
func (l *Logger) SetVerbosity(level int) {
	l.verbosity = level
}

// EnableArea enables logging for a specific area.
func (l *Logger) EnableArea(area LogArea) {
	if l.areas == nil {
		l.areas = make(map[LogArea]bool)
	}
	l.areas[area] = true
}

// DisableArea disables logging for a specific area.
func (l *Logger) DisableArea(area LogArea) {
	if l.areas == nil {
		return
	}
	delete(l.areas, area)
}

func (l *Logger) shouldLog(area LogArea, level int) bool {
	if !l.enabled || l.output == nil {
		return false
	}
	if level > l.verbosity {
		return false
	}
	if l.areas != nil && !l.areas[area] {
		return false
	}
	return true
}

func (l *Logger) log(area LogArea, level int, format string, args ...interface{}) {
	if !l.shouldLog(area, level) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.output, "%s %s\n", time.Now().Format("2006/01/02 15:04:05"), msg)
}

// Printf logs a general message at info level.
func (l *Logger) Printf(area LogArea, format string, args ...interface{}) {
	l.log(area, 1, format, args...)
}

// Debugf logs a debug message.
func (l *Logger) Debugf(area LogArea, format string, args ...interface{}) {
	l.log(area, 2, format, args...)
}

// Tracef logs a trace message (most verbose).
func (l *Logger) Tracef(area LogArea, format string, args ...interface{}) {
	l.log(area, 3, format, args...)
}

// Fatalf logs and exits.
func (l *Logger) Fatalf(format string, args ...interface{}) {
	if l.output != nil {
		msg := fmt.Sprintf(format, args...)
		fmt.Fprintf(l.output, "%s FATAL: %s\n", time.Now().Format("2006/01/02 15:04:05"), msg)
	}
	os.Exit(1)
}

// --- Handler Errors ---

// HandlerError is an error that occurred in a handler function.
// It includes the LogArea for appropriate logging at higher levels.
type HandlerError struct {
	Area    LogArea
	Message string
	Err     error // underlying error, if any
}

func (e *HandlerError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *HandlerError) Unwrap() error {
	return e.Err
}

// newHandlerError creates a new HandlerError with the given area and message.
func newHandlerError(area LogArea, format string, args ...interface{}) *HandlerError {
	return &HandlerError{
		Area:    area,
		Message: fmt.Sprintf(format, args...),
	}
}

// wrapHandlerError creates a new HandlerError wrapping an underlying error.
func wrapHandlerError(area LogArea, err error, format string, args ...interface{}) *HandlerError {
	return &HandlerError{
		Area:    area,
		Message: fmt.Sprintf(format, args...),
		Err:     err,
	}
}

// --- Sys: Primary Server Instance ---

// SysOpt contains configuration options for starting an SMB server.
// At least one of NTLMAuthenticator or KerberosAuthenticator must be provided.
type SysOpt struct {
	Config                ServerConfig
	ShareProvider         ShareProvider
	NTLMAuthenticator     NTLMAuthenticator     // For NTLMv2 password-based authentication
	KerberosAuthenticator KerberosAuthenticator // For Kerberos/SPNEGO authentication
	Logger                *Logger
}

// Sys is the primary SMB server instance.
// It encapsulates all state for a single ksmbd server.
type Sys struct {
	config                ServerConfig
	shareProvider         ShareProvider
	ntlmAuthenticator     NTLMAuthenticator
	kerberosAuthenticator KerberosAuthenticator
	logger                *Logger

	// Internal state
	rpcResponses map[uint32][]byte
	pendingLogin struct {
		sync.Mutex
		handle   uint32
		username string
	}
	fd       int
	familyID uint16
	portID   uint32
	done     chan struct{} // closed when eventLoop exits
}

// NewSys creates a new SMB server instance.
func NewSys() *Sys {
	return &Sys{
		rpcResponses: make(map[uint32][]byte),
		done:         make(chan struct{}),
	}
}

// Wait blocks until the server has fully shut down.
// Call this after cancelling the context passed to Start.
func (s *Sys) Wait() {
	<-s.done
}

// Done returns a channel that is closed when the server has fully shut down.
func (s *Sys) Done() <-chan struct{} {
	return s.done
}

// --- Netlink Constants & Structs (Mirrors kernel fs/smb/server/ksmbd_netlink.h) ---

const (
	// Netlink commands/events (internal, mirrors kernel ksmbd_netlink.h)
	ksmbdEventUnspec               = 0
	ksmbdEventHeartbeatRequest     = 1
	ksmbdEventStartingUp           = 2
	ksmbdEventShuttingDown         = 3
	ksmbdEventLoginRequest         = 4
	ksmbdEventLoginResponse        = 5
	ksmbdEventShareConfigRequest   = 6
	ksmbdEventShareConfigResponse  = 7
	ksmbdEventTreeConnectRequest   = 8
	ksmbdEventTreeConnectResponse  = 9
	ksmbdEventTreeDisconnectReq    = 10
	ksmbdEventLogoutRequest        = 11
	ksmbdEventRpcRequest           = 12
	ksmbdEventRpcResponse          = 13
	ksmbdEventSpnegoAuthenRequest  = 14
	ksmbdEventSpnegoAuthenResponse = 15

	ksmbdShareFlagAvailable     = 1 << 0
	ksmbdShareFlagBrowseable    = 1 << 1
	ksmbdShareFlagWriteable     = 1 << 2
	ksmbdShareFlagStoreDosAttrs = 1 << 6
	ksmbdShareFlagOplocks       = 1 << 7
	ksmbdShareFlagPipe          = 1 << 8

	// Tree connect response flags
	ksmbdTreeConnFlagWritable = 1 << 2

	// Size constants
	ksmbdReqMaxAccountNameSz = 48
	ksmbdReqMaxHashSz        = 18 // Matches kernel v6.8
	ksmbdReqMaxShareName     = 64

	// RPC Flags (fs/smb/server/ksmbd_netlink.h)
	ksmbdRpcMethodReturn       = 1 << 0
	ksmbdRpcSrvsvcMethodInvoke = 1 << 1
	ksmbdRpcWkssvcMethodInvoke = 1 << 2
	ksmbdRpcIoctlMethod        = (1 << 3) | ksmbdRpcMethodReturn
	ksmbdRpcOpenMethod         = 1 << 4
	ksmbdRpcWriteMethod        = 1 << 5
	ksmbdRpcReadMethod         = (1 << 6) | ksmbdRpcMethodReturn
	ksmbdRpcCloseMethod        = 1 << 7
	ksmbdRpcRestrictedContext  = 1 << 9
	ksmbdRpcSamrMethodInvoke   = 1 << 10
	ksmbdRpcLsarpcMethodInvoke = 1 << 11

	// Aliases for readability
	methodReturn = ksmbdRpcMethodReturn
	openMethod   = ksmbdRpcOpenMethod
	writeMethod  = ksmbdRpcWriteMethod
	readMethod   = ksmbdRpcReadMethod
	srvsvcInvoke = ksmbdRpcSrvsvcMethodInvoke
)

// DCE/RPC packet types (MS-RPCE Section 2.2.2.1)
const (
	rpcPacketTypeRequest  = 0  // Request (client → server)
	rpcPacketTypeResponse = 2  // Response (server → client)
	rpcPacketTypeBind     = 11 // Bind request (client → server)
	rpcPacketTypeBindAck  = 12 // Bind acknowledgment (server → client)
)

// DCE/RPC header flags (MS-RPCE Section 2.2.2.3)
const (
	rpcFlagFirstFrag = 0x01 // First fragment
	rpcFlagLastFrag  = 0x02 // Last fragment
)

// DCE/RPC version
const (
	rpcVersionMajor = 5 // DCE/RPC version 5.0
	rpcVersionMinor = 0
)

// SRVSVC interface UUID: 4B324FC8-1670-01D3-1278-5A47BF6EE188
// This is the Server Service interface for NetShareEnumAll, etc.
var srvsvcInterfaceUUID = [16]byte{
	0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
	0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
}

// NDR transfer syntax UUID: 8A885D04-1CEB-11C9-9FE8-08002B104860
// This identifies NDR (Network Data Representation) encoding.
var ndrTransferSyntaxUUID = [16]byte{
	0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
	0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
}

// NetShareEnumAll opnum in SRVSVC interface
const srvsvcOpnumNetShareEnumAll = 15

// Share types for NetShareEnumAll response (MS-SRVS Section 2.2.2.4)
const (
	stypeDisktree = 0x00000000 // Disk share
	stypeIPC      = 0x80000003 // IPC$ (named pipe share with special flag)
)

// buildRPCBindAck constructs a DCE/RPC BIND_ACK response for the SRVSVC interface.
//
// DCE/RPC BIND_ACK packet structure (MS-RPCE Section 2.2.2.4):
//
//	Offset  Size  Field                Description
//	------  ----  -----                -----------
//	0       1     rpc_vers             RPC version major (5)
//	1       1     rpc_vers_minor       RPC version minor (0)
//	2       1     PTYPE                Packet type (12 = bind_ack)
//	3       1     pfc_flags            Flags (0x03 = first+last frag)
//	4       4     packed_drep          Data representation (little-endian)
//	8       2     frag_length          Total fragment length
//	10      2     auth_length          Auth trailer length (0)
//	12      4     call_id              Call ID from BIND request
//	16      2     max_xmit_frag        Max transmit fragment size
//	18      2     max_recv_frag        Max receive fragment size
//	20      4     assoc_group_id       Association group ID
//	24      2     sec_addr_len         Secondary address length (13 for \PIPE\srvsvc)
//	26      13    sec_addr             Secondary address: "\PIPE\srvsvc\0"
//	39      1     padding              Alignment padding
//	40      1     n_results            Number of results (1)
//	41      3     reserved             Reserved
//	44      2     result               Result (0 = acceptance)
//	46      2     reason               Reason (0)
//	48      16    transfer_syntax      NDR transfer syntax UUID
//	64      4     syntax_version       Transfer syntax version (2)
//
// Total: 68 bytes (0x44)
func buildRPCBindAck(callID uint32) []byte {
	buf := new(bytes.Buffer)

	// DCE/RPC header (bytes 0-15)
	buf.WriteByte(rpcVersionMajor)                             // rpc_vers
	buf.WriteByte(rpcVersionMinor)                             // rpc_vers_minor
	buf.WriteByte(rpcPacketTypeBindAck)                        // PTYPE
	buf.WriteByte(rpcFlagFirstFrag | rpcFlagLastFrag)          // pfc_flags
	binary.Write(buf, binary.LittleEndian, uint32(0x00000010)) // packed_drep (little-endian)
	binary.Write(buf, binary.LittleEndian, uint16(68))         // frag_length
	binary.Write(buf, binary.LittleEndian, uint16(0))          // auth_length
	binary.Write(buf, binary.LittleEndian, callID)             // call_id

	// Bind ACK body (bytes 16-23)
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // max_xmit_frag
	binary.Write(buf, binary.LittleEndian, uint16(4280)) // max_recv_frag
	binary.Write(buf, binary.LittleEndian, uint32(0))    // assoc_group_id

	// Secondary address (bytes 24-39): "\PIPE\srvsvc"
	secAddr := []byte("\\PIPE\\srvsvc\x00")
	binary.Write(buf, binary.LittleEndian, uint16(len(secAddr))) // sec_addr_len (13)
	buf.Write(secAddr)                                           // sec_addr
	buf.WriteByte(0)                                             // padding for alignment

	// Results array (bytes 40-47)
	buf.WriteByte(1)          // n_results
	buf.Write([]byte{0, 0, 0}) // reserved (3 bytes)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // result (acceptance)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // reason

	// Transfer syntax (bytes 48-67): NDR UUID + version
	buf.Write(ndrTransferSyntaxUUID[:])
	binary.Write(buf, binary.LittleEndian, uint32(2)) // syntax version

	return buf.Bytes()
}

// Structs matching kernel memory layout (internal).
// Note: These structs are __packed in kernel. binary.Write writes fields contiguously,
// effectively packing them, so we must define fields carefully.

type ksmbdStartupRequest struct {
	Flags              uint32
	Signing            int32
	MinProt            [16]int8
	MaxProt            [16]int8
	NetbiosName        [16]int8
	WorkGroup          [64]int8
	ServerString       [64]int8
	TcpPort            uint16
	IpcTimeout         uint16
	Deadtime           uint32
	FileMax            uint32
	Smb2MaxWrite       uint32
	Smb2MaxRead        uint32
	Smb2MaxTrans       uint32
	ShareFakeFscaps    uint32
	SubAuth            [3]uint32
	Smb2MaxCredits     uint32
	SmbdMaxIoSize      uint32
	MaxConnections     uint32
	BindInterfacesOnly int8
	MaxIpConnections   [4]byte
	Reserved           [499]int8
	IfcListSz          [4]byte
	// Payload follows (interfaces)
}

type ksmbdLoginRequest struct {
	Handle   uint32
	Account  [ksmbdReqMaxAccountNameSz]int8
	Reserved [16]uint32
}

type ksmbdLoginResponse struct {
	Handle   uint32
	Gid      uint32
	Uid      uint32
	Account  [ksmbdReqMaxAccountNameSz]int8
	Status   uint16
	HashSz   uint16
	Hash     [ksmbdReqMaxHashSz]int8
	Pad      [2]int8 // Alignment to 4 bytes for Reserved
	Reserved [16]uint32
}

type ksmbdShareConfigRequest struct {
	Handle    uint32
	ShareName [ksmbdReqMaxShareName]int8
	Reserved  [16]uint32
}

type ksmbdShareConfigResponse struct {
	Handle             uint32
	Flags              uint32
	CreateMask         uint16
	DirectoryMask      uint16
	ForceCreateMode    uint16
	ForceDirectoryMode uint16
	ForceUid           uint16
	ForceGid           uint16
	ShareName          [ksmbdReqMaxShareName]int8
	Reserved           [111]uint32
	PayloadSz          uint32
	VetoListSz         uint32
	// Payload follows (Veto list + Share Path)
}

// toConfigResponse builds a ksmbdShareConfigResponse from ShareInfo.
func (s *ShareInfo) toConfigResponse(handle uint32, shareName [ksmbdReqMaxShareName]int8) ksmbdShareConfigResponse {
	flags := uint32(ksmbdShareFlagAvailable | ksmbdShareFlagStoreDosAttrs | ksmbdShareFlagOplocks)
	if !s.Hidden {
		flags |= ksmbdShareFlagBrowseable
	}
	if !s.ReadOnly {
		flags |= ksmbdShareFlagWriteable
	}

	createMask := s.CreateMask
	if createMask == 0 {
		createMask = DefaultCreateMask
	}
	directoryMask := s.DirectoryMask
	if directoryMask == 0 {
		directoryMask = DefaultDirectoryMask
	}
	forceUID := s.ForceUID
	if forceUID == 0 {
		forceUID = NoForceUID
	}
	forceGID := s.ForceGID
	if forceGID == 0 {
		forceGID = NoForceGID
	}

	resp := ksmbdShareConfigResponse{
		Handle:             handle,
		Flags:              flags,
		CreateMask:         createMask,
		DirectoryMask:      directoryMask,
		ForceCreateMode:    s.ForceCreateMode,
		ForceDirectoryMode: s.ForceDirectoryMode,
		ForceUid:           forceUID,
		ForceGid:           forceGID,
	}
	copy(resp.ShareName[:], shareName[:])
	return resp
}

type ksmbdHeartbeat struct {
	Handle uint32
}

type ksmbdLogoutRequest struct {
	Account      [ksmbdReqMaxAccountNameSz]int8
	AccountFlags uint32
	Reserved     [16]uint32
}

type ksmbdRpc struct {
	Handle    uint32
	Flags     uint32
	PayloadSz uint32
	// Payload follows
}

type ksmbdTreeConnectRequest struct {
	Handle       uint32
	AccountFlags uint16
	Flags        uint16
	SessionId    uint64
	ConnectId    uint64
	Account      [ksmbdReqMaxAccountNameSz]int8
	Share        [ksmbdReqMaxShareName]int8
	PeerAddr     [64]int8
	Reserved     [16]uint32
}

type ksmbdTreeConnectResponse struct {
	Handle          uint32
	Status          uint16
	ConnectionFlags uint16
	Reserved        [16]uint32
}

type ksmbdTreeDisconnectRequest struct {
	SessionId uint64
	ConnectId uint64
	Reserved  [16]uint32
}

// ksmbdSpnegoAuthenRequest is a Kerberos/SPNEGO authentication request from kernel.
type ksmbdSpnegoAuthenRequest struct {
	Handle        uint32
	SpnegoBlobLen uint16
	// SpnegoBlob follows (variable length)
}

// ksmbdSpnegoAuthenResponse is a Kerberos/SPNEGO authentication response to kernel.
type ksmbdSpnegoAuthenResponse struct {
	Handle        uint32
	LoginResponse ksmbdLoginResponse
	SessionKeyLen uint16
	SpnegoBlobLen uint16
	// Payload follows: session_key + spnego_blob
}

// loadModule loads the ksmbd kernel module using syscalls.
// It first tries FinitModule (syscall), then falls back to modprobe for dependency handling.
func loadModule(name string) error {
	// Try to find the module file
	var unameInfo unix.Utsname
	if err := unix.Uname(&unameInfo); err != nil {
		return exec.Command("modprobe", name).Run()
	}
	release := unix.ByteSliceToString(unameInfo.Release[:])

	// Standard module paths to try
	paths := []string{
		filepath.Join("/lib/modules", release, "kernel/fs/smb/server", name+".ko"),
		filepath.Join("/lib/modules", release, "kernel/fs/smb/server", name+".ko.xz"),
		filepath.Join("/lib/modules", release, "kernel/fs/smb/server", name+".ko.zst"),
	}

	for _, path := range paths {
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		err = unix.FinitModule(fd, "", 0)
		unix.Close(fd)
		if err == nil {
			return nil
		}
		// EEXIST means module already loaded - that's fine
		if err == unix.EEXIST {
			return nil
		}
	}

	// Fallback to modprobe for dependency handling or non-standard locations
	return exec.Command("modprobe", name).Run()
}

// unloadModule unloads a kernel module using the DeleteModule syscall.
func unloadModule(name string) error {
	err := unix.DeleteModule(name, 0)
	if err == unix.ENOENT {
		// Module not loaded - that's fine
		return nil
	}
	return err
}

// Start initializes and starts the SMB server.
// It returns after the server is ready to accept connections.
// The event loop runs in a background goroutine until ctx is cancelled.
// On shutdown, the ksmbd kernel module is unloaded.
func (s *Sys) Start(ctx context.Context, opt SysOpt) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}

	// Validate that at least one authenticator is provided
	if opt.NTLMAuthenticator == nil && opt.KerberosAuthenticator == nil {
		return fmt.Errorf("at least one of NTLMAuthenticator or KerberosAuthenticator must be provided")
	}

	// Apply configuration from options
	s.config = opt.Config
	s.shareProvider = opt.ShareProvider
	s.ntlmAuthenticator = opt.NTLMAuthenticator
	s.kerberosAuthenticator = opt.KerberosAuthenticator
	s.logger = opt.Logger
	if s.logger == nil {
		s.logger = NewLogger(nil) // disabled logger
	}

	// 1. Load ksmbd kernel module
	s.logger.Printf(LogAreaGeneral, "Loading ksmbd module...")
	if err := loadModule(moduleName); err != nil {
		s.logger.Printf(LogAreaGeneral, "Warning: module load returned error: %v", err)
	}

	// 2. Connect to Generic Netlink
	fd, familyID, groups, portID, err := s.connectGenl()
	if err != nil {
		return fmt.Errorf("netlink connection failed: %w", err)
	}

	s.fd = fd
	s.familyID = familyID
	s.portID = portID

	s.logger.Printf(LogAreaNetlink, "Connected to ksmbd netlink (Family ID: %d, Port ID: %d)", familyID, portID)

	// Set socket read timeout so we can check for context cancellation
	tv := syscall.Timeval{Sec: 1, Usec: 0}
	syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Join Multicast Groups (required to receive kernel events)
	for _, g := range groups {
		s.logger.Debugf(LogAreaNetlink, "Joining multicast group %d", g)
		if err := syscall.SetsockoptInt(fd, 270, syscall.NETLINK_ADD_MEMBERSHIP, int(g)); err != nil {
			syscall.Close(fd)
			return fmt.Errorf("failed to join multicast group %d: %w", g, err)
		}
	}

	// 3. Start ksmbd Server
	if err := s.sendStartup(); err != nil {
		syscall.Close(fd)
		return fmt.Errorf("failed to start ksmbd: %w", err)
	}
	s.logger.Printf(LogAreaGeneral, "ksmbd server initialized.")

	// 4. Start event loop in background goroutine
	go s.eventLoop(ctx, fd, familyID)

	return nil
}

// eventLoop handles kernel events until ctx is cancelled.
func (s *Sys) eventLoop(ctx context.Context, fd int, familyID uint16) {
	// Signal completion when eventLoop exits (runs last due to LIFO)
	defer close(s.done)

	defer func() {
		// Unload ksmbd module on exit
		unloadModule(moduleName)
	}()

	defer syscall.Close(fd)

	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf(LogAreaGeneral, "eventLoop PANIC: %v\nstack: %s", r, debug.Stack())
		}
	}()

	s.logger.Printf(LogAreaGeneral, "Listening for kernel events...")
	buf := make([]byte, 8192)
	for {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			s.logger.Printf(LogAreaGeneral, "Context cancelled, shutting down...")
			return
		default:
		}

		nr, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			// Timeout is expected due to SO_RCVTIMEO - just continue to check context
			if err == syscall.EAGAIN {
				continue
			}
			s.logger.Printf(LogAreaNetlink, "Recv error: %v", err)
			continue
		}
		if nr < syscall.NLMSG_HDRLEN {
			continue
		}

		// Parse Netlink Header
		msgs, err := syscall.ParseNetlinkMessage(buf[:nr])
		if err != nil {
			s.logger.Printf(LogAreaNetlink, "Parse error: %v", err)
			continue
		}

		for _, m := range msgs {
			s.logger.Tracef(LogAreaNetlink, "RX Netlink: Type=%d, Flags=%x, Seq=%d, Len=%d, Pid=%d", m.Header.Type, m.Header.Flags, m.Header.Seq, m.Header.Len, m.Header.Pid)
			if len(m.Data) > 0 {
				s.logger.Tracef(LogAreaNetlink, "RX Payload (%d bytes): %x", len(m.Data), m.Data)
			}

			switch m.Header.Type {
			case syscall.NLMSG_ERROR:
				var errVal int32
				if len(m.Data) >= 4 {
					errVal = *(*int32)(unsafe.Pointer(&m.Data[0]))
				}
				s.logger.Debugf(LogAreaNetlink, "Received NLMSG_ERROR: %d", errVal)
				continue
			case uint16(familyID):
				if err := s.handleKsmbdEvent(m.Header.Seq, m.Data); err != nil {
					if he, ok := err.(*HandlerError); ok {
						s.logger.Printf(he.Area, "%v", he)
					} else {
						s.logger.Printf(LogAreaGeneral, "Handler error: %v", err)
					}
				}
			default:
				s.logger.Tracef(LogAreaNetlink, "Ignoring non-family message Type=%d", m.Header.Type)
			}
		}
	}
}

// --- Implementation Details ---

func (s *Sys) handleKsmbdEvent(seq uint32, data []byte) error {
	// Generic Netlink Header (4 bytes): cmd (1), ver (1), reserved (2)
	if len(data) < 4 {
		return newHandlerError(LogAreaNetlink, "event data too short: %d bytes", len(data))
	}
	cmd := data[0]
	// Payload starts after Genl header (4 bytes)
	payload := data[4:]

	switch cmd {
	case ksmbdEventStartingUp:
		s.logger.Debugf(LogAreaNetlink, "Received Startup Event (Seq %d) - Replying OK", seq)
		s.sendResponse(seq, 0, ksmbdEventStartingUp, []byte{})
		return nil
	case ksmbdEventLoginRequest:
		return s.handleLogin(seq, payload)
	case ksmbdEventShareConfigRequest:
		return s.handleShareConfig(seq, payload)
	case ksmbdEventHeartbeatRequest:
		return s.handleHeartbeat(seq, payload)
	case ksmbdEventLogoutRequest:
		return s.handleLogout(seq, payload)
	case ksmbdEventRpcRequest:
		return s.handleRpc(seq, payload)
	case ksmbdEventTreeConnectRequest:
		return s.handleTreeConnect(seq, payload)
	case ksmbdEventTreeDisconnectReq:
		return s.handleTreeDisconnect(seq, payload)
	case ksmbdEventSpnegoAuthenRequest:
		return s.handleSpnegoAuthen(seq, payload)
	default:
		s.logger.Debugf(LogAreaNetlink, "Received unhandled event cmd: %d", cmd)
		return nil
	}
}

func (s *Sys) handleHeartbeat(seq uint32, payload []byte) error {
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaNetlink, err, "failed to parse heartbeat attributes")
	}
	data, ok := attrs[ksmbdEventHeartbeatRequest]
	if !ok {
		return newHandlerError(LogAreaNetlink, "heartbeat: missing attribute %d", ksmbdEventHeartbeatRequest)
	}

	var req ksmbdHeartbeat
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &req); err != nil {
		return wrapHandlerError(LogAreaNetlink, err, "failed to read heartbeat struct")
	}
	s.logger.Debugf(LogAreaNetlink, "Handling Heartbeat Request (Handle: %d)", req.Handle)

	// Reply with same handle
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, req.Handle)
	s.sendResponse(seq, 0, ksmbdEventHeartbeatRequest, buf.Bytes())
	return nil
}

func (s *Sys) handleLogin(seq uint32, payload []byte) error {
	s.logger.Tracef(LogAreaAuth, "handleLogin: payload=%x", payload)
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaAuth, err, "failed to parse login attributes")
	}
	s.logger.Tracef(LogAreaAuth, "handleLogin: attributes found: %v, target constant=%d", attrs, ksmbdEventLoginRequest)
	data, ok := attrs[uint16(ksmbdEventLoginRequest)]
	if !ok {
		// Fallback: check if there's ONLY one attribute and use it
		if len(attrs) == 1 {
			for k, v := range attrs {
				s.logger.Tracef(LogAreaAuth, "Login request: Falling back to only attribute %d", k)
				data = v
				ok = true
			}
		}
		if !ok {
			return newHandlerError(LogAreaAuth, "login request: missing attribute %d", ksmbdEventLoginRequest)
		}
	}

	var req ksmbdLoginRequest
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &req); err != nil {
		return wrapHandlerError(LogAreaAuth, err, "failed to parse login request struct")
	}

	user := stringInt8(req.Account[:])
	s.logger.Debugf(LogAreaAuth, "Handling Login for User: '%s' (Handle: %d)", user, req.Handle)

	resp := ksmbdLoginResponse{
		Handle: req.Handle,
		Uid:    0,
		Gid:    0,
		Status: 9, // KSMBD_USER_FLAG_OK (1) | KSMBD_USER_FLAG_KSMBD_USER (8)
	}
	copy(resp.Account[:], req.Account[:])

	// Authenticate user via the configured authenticator
	var creds *UserCredentials
	if s.ntlmAuthenticator != nil {
		creds, err = s.ntlmAuthenticator.Authenticate(req.Handle, user)
		if err != nil {
			return wrapHandlerError(LogAreaAuth, err, "authentication error for user '%s'", user)
		}
	}

	if creds != nil {
		// Auth success: Provide binary 16-byte NTLM hash
		resp.HashSz = 16
		for i, b := range creds.PasswordHash {
			resp.Hash[i] = int8(b)
		}
		s.logger.Tracef(LogAreaAuth, "Sending Hash (Binary 16): %x", creds.PasswordHash)
		s.logger.Debugf(LogAreaAuth, "Login Response: Status=%d, Size=%d, Uid=%d", resp.Status, resp.HashSz, resp.Uid)

		// Track pending login for share config correlation
		s.pendingLogin.Lock()
		s.pendingLogin.handle = req.Handle
		s.pendingLogin.username = user
		s.pendingLogin.Unlock()

		// Notify share provider about the login
		if s.shareProvider != nil {
			if err := s.shareProvider.OnLogin(req.Handle, user); err != nil {
				return wrapHandlerError(LogAreaAuth, err, "share provider OnLogin error")
			}
		}
	} else {
		resp.Status = 0 // Fail
		s.logger.Debugf(LogAreaAuth, "Unknown user '%s', rejecting", user)
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, resp)
	s.logger.Tracef(LogAreaAuth, "Login Response Bytes (%d): %x", buf.Len(), buf.Bytes())
	attrBytes := makeAttribute(ksmbdEventLoginResponse, buf.Bytes())
	s.logger.Tracef(LogAreaAuth, "Login Response Attr bytes: %x", attrBytes)
	s.sendResponse(seq, 0, ksmbdEventLoginResponse, attrBytes)
	return nil
}

func (s *Sys) handleShareConfig(seq uint32, payload []byte) error {
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaShare, err, "failed to parse share config attributes")
	}
	data, ok := attrs[ksmbdEventShareConfigRequest]
	if !ok {
		return newHandlerError(LogAreaShare, "share config request: missing attribute %d", ksmbdEventShareConfigRequest)
	}

	var req ksmbdShareConfigRequest
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &req); err != nil {
		return wrapHandlerError(LogAreaShare, err, "failed to read share config request struct")
	}

	share := stringInt8(req.ShareName[:])
	s.logger.Debugf(LogAreaShare, "Share config request for: %s", share)

	// Handle IPC$ internally - it's required for named pipes and RPC
	if strings.EqualFold(share, "IPC$") {
		s.sendIPCShareConfig(seq, req)
		return nil
	}

	// Look up share from provider
	if s.shareProvider == nil {
		return newHandlerError(LogAreaShare, "no share provider configured")
	}

	// Get session context (handle from request, username from pending login)
	s.pendingLogin.Lock()
	username := s.pendingLogin.username
	s.pendingLogin.Unlock()

	sess := Session{
		Handle: req.Handle,
		User:   username,
		Share:  share,
	}

	shareInfo := s.shareProvider.GetShare(sess)
	if shareInfo == nil {
		return newHandlerError(LogAreaShare, "share '%s' not found or access denied for user '%s'", share, username)
	}

	resp := shareInfo.toConfigResponse(req.Handle, req.ShareName)

	// Get path from share provider
	path := s.shareProvider.PathForSession(sess)
	s.logger.Debugf(LogAreaShare, "Share '%s' path: %s (handle: %d, user: %s)", share, path, sess.Handle, sess.User)
	s.logger.Debugf(LogAreaShare, "Share '%s': Hidden=%v, ReadOnly=%v, Flags=%x", share, shareInfo.Hidden, shareInfo.ReadOnly, resp.Flags)
	pathBytes := append([]byte(path), 0) // Null terminated
	resp.PayloadSz = uint32(len(pathBytes))
	resp.VetoListSz = 0

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, resp)
	buf.Write(pathBytes)
	attrBytes := makeAttribute(ksmbdEventShareConfigResponse, buf.Bytes())
	s.sendResponse(seq, 0, ksmbdEventShareConfigResponse, attrBytes)
	return nil
}

// sendIPCShareConfig sends the IPC$ share configuration response.
// IPC$ is a special share for named pipes used by RPC services.
func (s *Sys) sendIPCShareConfig(seq uint32, req ksmbdShareConfigRequest) {
	resp := ksmbdShareConfigResponse{
		Handle:             req.Handle,
		Flags:              ksmbdShareFlagAvailable | ksmbdShareFlagPipe,
		CreateMask:         0777,
		DirectoryMask:      0777,
		ForceCreateMode:    0000,
		ForceDirectoryMode: 0000,
		ForceUid:           0xFFFF,
		ForceGid:           0xFFFF,
	}
	copy(resp.ShareName[:], req.ShareName[:])

	// IPC$ doesn't need a real path
	pathBytes := []byte("/dev/null\x00")
	resp.PayloadSz = uint32(len(pathBytes))
	resp.VetoListSz = 0

	s.logger.Debugf(LogAreaShare, "IPC$ share configured (internal)")

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, resp)
	buf.Write(pathBytes)
	attrBytes := makeAttribute(ksmbdEventShareConfigResponse, buf.Bytes())
	s.sendResponse(seq, 0, ksmbdEventShareConfigResponse, attrBytes)
}

func (s *Sys) handleLogout(seq uint32, payload []byte) error {
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaAuth, err, "failed to parse logout attributes")
	}
	data, ok := attrs[ksmbdEventLogoutRequest]
	if !ok {
		return newHandlerError(LogAreaAuth, "logout request: missing attribute %d", ksmbdEventLogoutRequest)
	}

	var req ksmbdLogoutRequest
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &req); err != nil {
		return wrapHandlerError(LogAreaAuth, err, "failed to read logout request struct")
	}
	user := stringInt8(req.Account[:])
	s.logger.Debugf(LogAreaAuth, "Handling Logout for User: '%s' (Flags: %d)", user, req.AccountFlags)

	// Logout doesn't have a response struct in the kernel header
	_ = seq // unused
	return nil
}

func (s *Sys) handleRpc(seq uint32, payload []byte) error {
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaRPC, err, "failed to parse RPC attributes")
	}
	data, ok := attrs[ksmbdEventRpcRequest]
	if !ok {
		return newHandlerError(LogAreaRPC, "RPC request: missing attribute %d", ksmbdEventRpcRequest)
	}

	// Read first 12 bytes (Handle, Flags, PayloadSz)
	var req struct {
		Handle    uint32
		Flags     uint32
		PayloadSz uint32
	}
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &req); err != nil {
		return wrapHandlerError(LogAreaRPC, err, "failed to read RPC request struct")
	}
	s.logger.Debugf(LogAreaRPC, "Handling RPC Request (Handle: %d, Flags: %x, Sz: %d)", req.Handle, req.Flags, req.PayloadSz)
	s.logger.Tracef(LogAreaRPC, "DEBUG: openMethod=%x, srvsvcInvoke=%x, req.Flags&openMethod=%x", openMethod, srvsvcInvoke, req.Flags&openMethod)

	respFlags := uint32(0) // KSMBD_RPC_OK
	rpcPayload := []byte{}

	switch {
	case req.Flags&openMethod != 0:
		s.logger.Debugf(LogAreaRPC, "RPC OPEN acknowledged (Handle: %d, Flags: %x)", req.Handle, req.Flags)
		rpcPayload = nil

	case req.PayloadSz > 0:
		// Process DCE/RPC Payload
		rpcIn := data[12:]
		if len(rpcIn) < 24 {
			return newHandlerError(LogAreaRPC, "RPC: request too small for parsing (Sz: %d)", len(rpcIn))
		}
		packetType := rpcIn[2]
		callID := binary.LittleEndian.Uint32(rpcIn[12:16])
		s.logger.Debugf(LogAreaRPC, "RPC: Payload RX PacketType: %d, CallID: %d", packetType, callID)

		var output []byte
		switch packetType {
		case rpcPacketTypeBind:
			s.logger.Debugf(LogAreaRPC, "RPC: BIND received (CallID: %d)", callID)
			output = buildRPCBindAck(callID)
		case rpcPacketTypeRequest:
			opnum := binary.LittleEndian.Uint16(rpcIn[22:24])
			contextID := binary.LittleEndian.Uint16(rpcIn[20:22])
			s.logger.Debugf(LogAreaRPC, "RPC: REQUEST received (CallID: %d, ContextID: %d, Opnum: %d)", callID, contextID, opnum)

			if opnum == srvsvcOpnumNetShareEnumAll {
				s.logger.Debugf(LogAreaRPC, "RPC: Handling NetShareEnumAll")

				// Collect shares from provider, filtering out hidden ones
				type shareEntry struct {
					Name    string
					Type    uint32
					Comment string
				}
				var entries []shareEntry

				// Add IPC$ first (required for RPC)
				entries = append(entries, shareEntry{
					Name:    "IPC$",
					Type:    stypeIPC,
					Comment: "IPC Service",
				})

				// Add shares from provider (non-hidden only)
				if s.shareProvider != nil {
					for _, sh := range s.shareProvider.ListShares(req.Handle) {
						if !sh.Hidden {
							entries = append(entries, shareEntry{
								Name:    sh.Name,
								Type:    stypeDisktree,
								Comment: sh.Comment,
							})
						}
					}
				}

				count := uint32(len(entries))
				ndr := new(bytes.Buffer)
				ptrID := uint32(0) // Pointer counter like ksmbd-tools

				// 1. Union: Level written twice (per NDR non-encapsulated union rules)
				binary.Write(ndr, binary.LittleEndian, uint32(1)) // Level 1
				binary.Write(ndr, binary.LittleEndian, uint32(1)) // Union Disc (Level 1)

				// 2. Conformant structure: EntriesRead as first max_count
				binary.Write(ndr, binary.LittleEndian, count) // Moved max count

				// 3. Varying array header (per ksmbd-tools: max, offset=1, actual)
				binary.Write(ndr, binary.LittleEndian, count)     // Max Count
				binary.Write(ndr, binary.LittleEndian, uint32(1)) // Offset = 1 (like ksmbd-tools!)
				binary.Write(ndr, binary.LittleEndian, count)     // Actual Count

				// 4. Share Entries (SHARE_INFO_1): name_ptr, type, comment_ptr
				for _, entry := range entries {
					ptrID++
					binary.Write(ndr, binary.LittleEndian, ptrID) // Name Ptr
					binary.Write(ndr, binary.LittleEndian, entry.Type)
					ptrID++
					binary.Write(ndr, binary.LittleEndian, ptrID) // Comment Ptr
				}

				// 5. Deferred strings - write name AND comment for each share
				for _, entry := range entries {
					writeNDRString(ndr, entry.Name)
					writeNDRString(ndr, entry.Comment)
				}

				// 6. Total Entries
				binary.Write(ndr, binary.LittleEndian, count)

				// 7. Resume Handle (unique pointer)
				ptrID++
				binary.Write(ndr, binary.LittleEndian, ptrID)     // Ptr for Resume Handle
				binary.Write(ndr, binary.LittleEndian, uint32(0)) // Resume Handle Value

				// 8. WERROR
				binary.Write(ndr, binary.LittleEndian, uint32(0)) // Success

				ndrBytes := ndr.Bytes()
				buf := new(bytes.Buffer)
				totalLen := uint16(24 + len(ndrBytes))
				buf.Write([]byte{0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00})
				binary.Write(buf, binary.LittleEndian, totalLen)
				buf.Write([]byte{0x00, 0x00})
				binary.Write(buf, binary.LittleEndian, callID)
				binary.Write(buf, binary.LittleEndian, uint32(len(ndrBytes)))
				binary.Write(buf, binary.LittleEndian, contextID)
				buf.Write([]byte{0x00, 0x00})
				buf.Write(ndrBytes)
				output = buf.Bytes()
			}
		}

		// Immediate or Stateful Return
		if req.Flags&(1<<3) != 0 { // IOCTL_METHOD
			s.logger.Debugf(LogAreaRPC, "RPC: Returning IOCTL payload immediately")
			rpcPayload = output
		} else {
			s.logger.Debugf(LogAreaRPC, "RPC: Buffering response for handle %d", req.Handle)
			s.rpcResponses[req.Handle] = output
			rpcPayload = nil
		}

	case req.Flags&readMethod != 0:
		rpcPayload = s.rpcResponses[req.Handle]
		if rpcPayload != nil {
			s.logger.Debugf(LogAreaRPC, "RPC: Returning buffered response for Handle %d (%d bytes)", req.Handle, len(rpcPayload))
			delete(s.rpcResponses, req.Handle)
		} else {
			s.logger.Debugf(LogAreaRPC, "RPC: No buffered response for Handle %d", req.Handle)
			rpcPayload = []byte{}
		}

	case req.Flags&ksmbdRpcCloseMethod != 0:
		s.logger.Debugf(LogAreaRPC, "RPC CLOSE acknowledged")
		rpcPayload = nil

	default:
		s.logger.Debugf(LogAreaRPC, "RPC: Unhandled method (Flags: %x)", req.Flags)
		rpcPayload = nil
	}

	resp := ksmbdRpc{
		Handle:    req.Handle, // Echo exactly
		Flags:     respFlags,
		PayloadSz: uint32(len(rpcPayload)),
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, resp)
	buf.Write(rpcPayload)
	s.logger.Debugf(LogAreaRPC, "Sending RPC Response: Handle=%d, Flags=%d, Sz=%d", resp.Handle, resp.Flags, resp.PayloadSz)
	if len(rpcPayload) > 0 {
		s.logger.Tracef(LogAreaRPC, "RPC Resp Payload hex: %x", rpcPayload)
	}

	attrBytes := makeAttribute(ksmbdEventRpcResponse, buf.Bytes())
	s.sendResponse(seq, 0, ksmbdEventRpcResponse, attrBytes)
	return nil
}

func writeNDRString(buf *bytes.Buffer, s string) {
	// Alignment before header (standard for uint32 fields)
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-buf.Len()%4))
	}
	utf := toUTF16(s)
	binary.Write(buf, binary.LittleEndian, uint32(len(utf)/2)) // Max Count
	binary.Write(buf, binary.LittleEndian, uint32(0))          // Offset
	binary.Write(buf, binary.LittleEndian, uint32(len(utf)/2)) // Actual Count
	buf.Write(utf)
	// Alignment after string (ksmbd-tools rpc.c:442)
	if buf.Len()%4 != 0 {
		buf.Write(make([]byte, 4-buf.Len()%4))
	}
}

func (s *Sys) handleTreeConnect(seq uint32, payload []byte) error {
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaTree, err, "failed to parse tree connect attributes")
	}
	data, ok := attrs[ksmbdEventTreeConnectRequest]
	if !ok {
		return newHandlerError(LogAreaTree, "tree connect: missing attribute %d", ksmbdEventTreeConnectRequest)
	}

	var req ksmbdTreeConnectRequest
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &req); err != nil {
		return wrapHandlerError(LogAreaTree, err, "failed to read tree connect request struct")
	}

	share := stringInt8(req.Share[:])
	user := stringInt8(req.Account[:])
	s.logger.Debugf(LogAreaTree, "Handling Tree Connect for Share: '%s' (Handle: %d, User: %s)", share, req.Handle, user)

	// Notify share provider about tree connect
	if s.shareProvider != nil {
		sess := Session{
			Handle: req.Handle,
			User:   user,
			Share:  share,
		}
		tree := TreeContext{
			SessionID:    req.SessionId,
			ConnectionID: req.ConnectId,
		}
		if err := s.shareProvider.OnTreeConnect(sess, tree); err != nil {
			return wrapHandlerError(LogAreaTree, err, "share provider OnTreeConnect error")
		}
	}

	// Response
	resp := ksmbdTreeConnectResponse{
		Handle:          req.Handle,
		Status:          0, // KSMBD_TREE_CONN_STATUS_OK
		ConnectionFlags: ksmbdTreeConnFlagWritable,
	}

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, resp)
	attrBytes := makeAttribute(ksmbdEventTreeConnectResponse, buf.Bytes())
	s.sendResponse(seq, syscall.NLM_F_REQUEST, ksmbdEventTreeConnectResponse, attrBytes)
	return nil
}

func (s *Sys) handleTreeDisconnect(seq uint32, payload []byte) error {
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaTree, err, "failed to parse tree disconnect attributes")
	}
	data, ok := attrs[ksmbdEventTreeDisconnectReq]
	if !ok {
		return newHandlerError(LogAreaTree, "tree disconnect: missing attribute %d", ksmbdEventTreeDisconnectReq)
	}

	var req ksmbdTreeDisconnectRequest
	if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &req); err != nil {
		return wrapHandlerError(LogAreaTree, err, "failed to read tree disconnect request struct")
	}
	s.logger.Debugf(LogAreaTree, "Handling Tree Disconnect (Session: %d, Connect: %d)", req.SessionId, req.ConnectId)

	// Notify share provider about tree disconnect
	if s.shareProvider != nil {
		tree := TreeContext{
			SessionID:    req.SessionId,
			ConnectionID: req.ConnectId,
		}
		if err := s.shareProvider.OnTreeDisconnect(tree); err != nil {
			return wrapHandlerError(LogAreaTree, err, "share provider OnTreeDisconnect error")
		}
	}

	// Tree disconnect doesn't have a response struct in the kernel
	_ = seq // unused
	return nil
}

func (s *Sys) handleSpnegoAuthen(seq uint32, payload []byte) error {
	attrs, err := getAttributes(payload)
	if err != nil {
		return wrapHandlerError(LogAreaAuth, err, "failed to parse SPNEGO attributes")
	}
	data, ok := attrs[ksmbdEventSpnegoAuthenRequest]
	if !ok {
		return newHandlerError(LogAreaAuth, "SPNEGO request: missing attribute %d", ksmbdEventSpnegoAuthenRequest)
	}

	// Read fixed header (handle + blob_len)
	if len(data) < 6 {
		return newHandlerError(LogAreaAuth, "SPNEGO request too short: %d bytes", len(data))
	}
	handle := binary.LittleEndian.Uint32(data[0:4])
	blobLen := binary.LittleEndian.Uint16(data[4:6])
	s.logger.Debugf(LogAreaAuth, "SPNEGO request (Handle: %d, BlobLen: %d)", handle, blobLen)

	if len(data) < 6+int(blobLen) {
		return newHandlerError(LogAreaAuth, "SPNEGO blob truncated: have %d, need %d", len(data)-6, blobLen)
	}
	spnegoBlob := data[6 : 6+blobLen]

	// Check if Kerberos authenticator is configured
	if s.kerberosAuthenticator == nil {
		s.logger.Printf(LogAreaAuth, "SPNEGO request rejected: no Kerberos authenticator configured")
		s.sendSpnegoFailure(seq, handle)
		return nil
	}

	// Decode SPNEGO negTokenInit
	mechOID, apReq, err := decodeNegTokenInit(spnegoBlob)
	if err != nil {
		s.logger.Printf(LogAreaAuth, "SPNEGO decode error: %v", err)
		s.sendSpnegoFailure(seq, handle)
		return nil
	}
	s.logger.Debugf(LogAreaAuth, "SPNEGO mechanism: %v, AP-REQ len: %d", mechOID, len(apReq))

	// Validate Kerberos AP-REQ
	authResult, err := s.kerberosAuthenticator.ValidateAPReq(apReq)
	if err != nil {
		s.logger.Printf(LogAreaAuth, "Kerberos validation failed: %v", err)
		s.sendSpnegoFailure(seq, handle)
		return nil
	}
	s.logger.Printf(LogAreaAuth, "Kerberos authenticated user: %s", authResult.Username)

	// Build SPNEGO response token
	respBlob, err := encodeNegTokenResp(spnegoAcceptCompleted, mechOID, authResult.APRep)
	if err != nil {
		s.logger.Printf(LogAreaAuth, "Failed to encode SPNEGO response: %v", err)
		s.sendSpnegoFailure(seq, handle)
		return nil
	}

	// Look up user credentials (for UID/GID)
	var loginResp ksmbdLoginResponse
	loginResp.Handle = handle
	loginResp.Status = 9 // KSMBD_USER_FLAG_OK | KSMBD_USER_FLAG_KSMBD_USER
	copyInt8(loginResp.Account[:], authResult.Username)

	if s.ntlmAuthenticator != nil {
		creds, err := s.ntlmAuthenticator.Authenticate(handle, authResult.Username)
		if err == nil && creds != nil {
			loginResp.Uid = creds.UID
			loginResp.Gid = creds.GID
		}
	}

	// Track login for share config correlation
	s.pendingLogin.Lock()
	s.pendingLogin.handle = handle
	s.pendingLogin.username = authResult.Username
	s.pendingLogin.Unlock()

	// Notify share provider
	if s.shareProvider != nil {
		if err := s.shareProvider.OnLogin(handle, authResult.Username); err != nil {
			s.logger.Printf(LogAreaAuth, "Share provider OnLogin error: %v", err)
		}
	}

	// Build response
	sessionKeyLen := uint16(len(authResult.SessionKey))
	spnegoBlobLen := uint16(len(respBlob))

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, handle)
	binary.Write(buf, binary.LittleEndian, loginResp)
	binary.Write(buf, binary.LittleEndian, sessionKeyLen)
	binary.Write(buf, binary.LittleEndian, spnegoBlobLen)
	buf.Write(authResult.SessionKey)
	buf.Write(respBlob)

	s.logger.Debugf(LogAreaAuth, "SPNEGO response: SessionKeyLen=%d, SpnegoBlobLen=%d, Total=%d",
		sessionKeyLen, spnegoBlobLen, buf.Len())

	attrBytes := makeAttribute(ksmbdEventSpnegoAuthenResponse, buf.Bytes())
	s.sendResponse(seq, 0, ksmbdEventSpnegoAuthenResponse, attrBytes)
	return nil
}

func (s *Sys) sendSpnegoFailure(seq uint32, handle uint32) {
	var loginResp ksmbdLoginResponse
	loginResp.Handle = handle
	loginResp.Status = 0 // KSMBD_USER_FLAG_INVALID

	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, handle)
	binary.Write(buf, binary.LittleEndian, loginResp)
	binary.Write(buf, binary.LittleEndian, uint16(0)) // sessionKeyLen
	binary.Write(buf, binary.LittleEndian, uint16(0)) // spnegoBlobLen

	attrBytes := makeAttribute(ksmbdEventSpnegoAuthenResponse, buf.Bytes())
	s.sendResponse(seq, 0, ksmbdEventSpnegoAuthenResponse, attrBytes)
}

func (s *Sys) sendStartup() error {
	cfg := s.config

	// Build global flags based on configuration
	var flags uint32 = GlobalFlagSMB2Leases // Always enable leases
	if cfg.Encryption {
		flags |= GlobalFlagSMB2Encryption
	} else {
		flags |= GlobalFlagSMB2EncryptionOff
	}

	// Log Kerberos configuration if enabled.
	// Note: The ksmbd kernel module handles SPNEGO negotiation internally and builds
	// its own mechlist. We can't control what mechanisms the kernel advertises.
	// However, when a client sends a Kerberos SPNEGO token, the kernel forwards
	// it to userspace via KSMBD_EVENT_SPNEGO_AUTHEN_REQUEST, which we handle.
	if s.kerberosAuthenticator != nil {
		spnegoCfg := s.kerberosAuthenticator.SPNEGOConfig()
		if spnegoCfg != nil {
			s.logger.Printf(LogAreaAuth, "Kerberos authenticator configured: principal=%s@%s",
				spnegoCfg.ServicePrincipal, spnegoCfg.Realm)
		}
	}

	// Determine TCP port - use config or default for tests
	tcpPort := cfg.TCPPort
	if tcpPort == 0 {
		tcpPort = 445
	}

	req := ksmbdStartupRequest{
		Flags:          flags,
		TcpPort:        tcpPort,
		IpcTimeout:     30,
		Signing:        cfg.Signing,
		FileMax:        16384,
		Smb2MaxRead:    1024 * 1024,
		Smb2MaxWrite:   1024 * 1024,
		Smb2MaxTrans:   1024 * 1024,
		SmbdMaxIoSize:  1024 * 1024,
		MaxConnections: cfg.MaxConnections,
	}

	// Copy strings from configuration
	netbiosName := cfg.NetBIOSName
	if netbiosName == "" {
		netbiosName = "GO-SERVER"
	}
	workGroup := cfg.WorkGroup
	if workGroup == "" {
		workGroup = "WORKGROUP"
	}
	serverString := cfg.ServerString
	if serverString == "" {
		serverString = "Go KSMBD Server"
	}
	minProt := cfg.MinProtocol
	if minProt == "" {
		minProt = "SMB300"
	}
	maxProt := cfg.MaxProtocol
	if maxProt == "" {
		maxProt = "SMB311"
	}

	copyInt8(req.NetbiosName[:], netbiosName)
	copyInt8(req.WorkGroup[:], workGroup)
	copyInt8(req.ServerString[:], serverString)
	copyInt8(req.MinProt[:], minProt)
	copyInt8(req.MaxProt[:], maxProt)

	// Log security configuration
	signingStr := "DISABLED"
	switch cfg.Signing {
	case SigningEnabled:
		signingStr = "ENABLED"
	case SigningMandatory:
		signingStr = "MANDATORY"
	case SigningAuto:
		signingStr = "AUTO"
	}
	s.logger.Printf(LogAreaGeneral, "Security: Signing=%s, Encryption=%v, MinProtocol=%s",
		signingStr, cfg.Encryption, minProt)

	// Wrap in Netlink Attribute (Type=2 ksmbdEventStartingUp)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, req)
	reqBytes := buf.Bytes()

	attrBytes := makeAttribute(ksmbdEventStartingUp, reqBytes)

	// Send as ksmbdEventStartingUp (Cmd=2) with NLM_F_REQUEST | NLM_F_ACK
	nlFlags := uint16(syscall.NLM_F_REQUEST | syscall.NLM_F_ACK)
	return s.sendResponseWithSeq(1, nlFlags, ksmbdEventStartingUp, attrBytes)
}

// --- Helpers ---

func (s *Sys) connectGenl() (int, uint16, []uint32, uint32, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_GENERIC)
	if err != nil {
		return 0, 0, nil, 0, err
	}

	// Bind
	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, addr); err != nil {
		return 0, 0, nil, 0, err
	}

	// Get assigned Port ID
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return 0, 0, nil, 0, err
	}
	localID := sa.(*syscall.SockaddrNetlink).Pid
	s.logger.Debugf(LogAreaNetlink, "Bound to Netlink Port ID: %d", localID)

	// Resolve Family ID using CTRL_CMD_GETFAMILY
	id, groups, err := s.resolveFamily(fd, genlName)
	return fd, id, groups, localID, err
}

func (s *Sys) resolveFamily(fd int, name string) (uint16, []uint32, error) {
	b := new(bytes.Buffer)
	// Netlink Header place holder
	b.Write(make([]byte, 16))
	// Genl Header: Cmd=3 (GETFAMILY), Ver=1
	b.Write([]byte{3, 1, 0, 0})

	// Attribute: Family Name
	nameBytes := append([]byte(name), 0)
	pad := (4 - (len(nameBytes) % 4)) % 4
	attrLen := 4 + len(nameBytes)
	binary.Write(b, binary.LittleEndian, uint16(attrLen))
	binary.Write(b, binary.LittleEndian, uint16(2)) // CTRL_ATTR_FAMILY_NAME
	b.Write(nameBytes)
	b.Write(make([]byte, pad))

	data := b.Bytes()
	nlHdr := (*syscall.NlMsghdr)(unsafe.Pointer(&data[0]))
	nlHdr.Len = uint32(len(data))
	nlHdr.Type = 0x10 // GENL_ID_CTRL
	nlHdr.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	nlHdr.Pid = uint32(os.Getpid()) // Improve uniqueness

	syscall.Sendto(fd, data, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})

	// Read response
	resp := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(fd, resp, 0)
	if err != nil {
		return 0, nil, err
	}

	// Parse response
	cursor := 20
	var familyID uint16
	var mcastGroups []uint32

	s.logger.Tracef(LogAreaNetlink, "resolveFamily Recv: %d bytes", n)

	for cursor < n {
		if cursor+4 > n {
			break
		}
		attrLen := binary.LittleEndian.Uint16(resp[cursor : cursor+2])
		attrType := binary.LittleEndian.Uint16(resp[cursor+2 : cursor+4])
		next := cursor + int((attrLen+3)&^uint16(3))

		s.logger.Tracef(LogAreaNetlink, "Genl Attr: Type=%d, Len=%d", attrType, attrLen)

		switch attrType {
		case 1: // CTRL_ATTR_FAMILY_ID
			familyID = binary.LittleEndian.Uint16(resp[cursor+4 : cursor+6])
			s.logger.Tracef(LogAreaNetlink, "Found Family ID: %d", familyID)
		case 4: // CTRL_ATTR_HDRSIZE
			hdrSize := binary.LittleEndian.Uint32(resp[cursor+4 : cursor+8])
			s.logger.Tracef(LogAreaNetlink, "Found HDRSIZE: %d", hdrSize)
		case 7: // CTRL_ATTR_MCAST_GROUPS
			s.logger.Tracef(LogAreaNetlink, "Found Multicast Groups Attribute (7)")
			nestStart := cursor + 4
			nestEnd := cursor + int(attrLen)
			if nestEnd > n {
				nestEnd = n
			}
			c2 := nestStart
			for c2 < nestEnd {
				if c2+4 > nestEnd {
					break
				}
				gLen := binary.LittleEndian.Uint16(resp[c2 : c2+2])
				gNext := c2 + int((gLen+3)&^uint16(3))
				c3 := c2 + 4
				gEnd := c2 + int(gLen)
				if gEnd > nestEnd {
					gEnd = nestEnd
				}
				for c3 < gEnd {
					if c3+4 > gEnd {
						break
					}
					subLen := binary.LittleEndian.Uint16(resp[c3 : c3+2])
					subType := binary.LittleEndian.Uint16(resp[c3+2 : c3+4])
					if subType == 2 { // CTRL_ATTR_MCAST_GRP_ID
						grpID := binary.LittleEndian.Uint32(resp[c3+4 : c3+8])
						mcastGroups = append(mcastGroups, grpID)
						s.logger.Tracef(LogAreaNetlink, "Found Multicast Group ID: %d", grpID)
					}
					c3 += int((subLen + 3) & ^uint16(3))
				}
				c2 = gNext
			}
		}
		cursor = next
	}
	if familyID == 0 {
		return 0, nil, fmt.Errorf("family '%s' not found", name)
	}
	return familyID, mcastGroups, nil
}

func (s *Sys) sendResponse(seq uint32, flags uint16, cmd uint8, payload interface{}) error {
	// Serialize payload
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, payload)
	payloadBytes := buf.Bytes()

	return s.sendRawResponse(seq, flags, cmd, payloadBytes)
}

func (s *Sys) sendResponseWithSeq(seq uint32, flags uint16, cmd uint8, payload interface{}) error {
	return s.sendResponse(seq, flags, cmd, payload)
}

func (s *Sys) sendRawResponse(seq uint32, flags uint16, cmd uint8, payload []byte) error {
	b := new(bytes.Buffer)
	// Netlink Header placeholder
	b.Write(make([]byte, 16))
	// Generic Netlink Header
	b.WriteByte(cmd)
	b.WriteByte(1)        // Version
	b.Write([]byte{0, 0}) // Reserved

	b.Write(payload)

	data := b.Bytes()
	nlHdr := (*syscall.NlMsghdr)(unsafe.Pointer(&data[0]))
	nlHdr.Len = uint32(len(data))
	nlHdr.Type = s.familyID
	nlHdr.Flags = flags | syscall.NLM_F_REQUEST
	nlHdr.Seq = seq
	nlHdr.Pid = s.portID

	return syscall.Sendto(s.fd, data, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

func stringInt8(in []int8) string {
	b := make([]byte, len(in))
	for i, v := range in {
		b[i] = byte(v)
	}
	return strings.TrimRight(string(b), "\x00")
}

func copyInt8(dst []int8, src string) {
	l := min(len(dst), len(src))
	for i := range l {
		dst[i] = int8(src[i])
	}
}

func toUTF16(s string) []byte {
	runes := []rune(s)
	out := make([]byte, (len(runes)+1)*2)
	for i, r := range runes {
		binary.LittleEndian.PutUint16(out[i*2:], uint16(r))
	}
	// Null terminator already zeroed
	return out
}
