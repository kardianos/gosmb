package smbsys

import "strings"

// Permission mask defaults for share configuration.
const (
	// DefaultCreateMask is the default permission mask for new files (0644).
	DefaultCreateMask = 0644

	// DefaultDirectoryMask is the default permission mask for new directories (0755).
	DefaultDirectoryMask = 0755

	// NoForceMode disables forced permission bits (0000).
	NoForceMode = 0000

	// NoForceUID indicates no forced UID (use connecting user's UID).
	NoForceUID = 0xFFFF

	// NoForceGID indicates no forced GID (use connecting user's GID).
	NoForceGID = 0xFFFF
)

// ShareProvider provides share configuration and filesystem backing.
// This interface combines share enumeration with the filesystem backend,
// since the backend is responsible for knowing where shares are stored.
//
// Note: The IPC$ share is handled internally by the server and should not
// be included in your ShareProvider implementation.
type ShareProvider interface {
	// GetShare returns the share info if it exists, or nil if not.
	GetShare(name string) *ShareInfo

	// ListShares returns shares for enumeration (NetShareEnumAll).
	// Hidden shares (Hidden=true) are automatically filtered from results.
	// Return an empty slice to hide all shares from enumeration while still
	// allowing access via GetShare.
	ListShares() []ShareInfo

	// PathForSession returns the filesystem path for a session accessing a share.
	// For real filesystems, this returns the configured path for the share.
	// For FUSE backends, this may return a session-specific path like "/.s/{handle}/share".
	PathForSession(share string, handle uint32) string

	// OnLogin is called when a user authenticates.
	// The backend can use this to set up session-specific state.
	OnLogin(handle uint32, username string) error

	// OnLogout is called when a session ends.
	OnLogout(handle uint32) error

	// OnTreeConnect is called when a user connects to a share.
	OnTreeConnect(ctx TreeConnectContext) error

	// OnTreeDisconnect is called when user disconnects from a share.
	OnTreeDisconnect(sessionID, connID uint64) error

	// Close cleans up resources (unmount FUSE, etc.).
	Close() error
}

// ShareInfo defines share metadata for enumeration and access control.
// The filesystem path is provided by PathForSession, not stored here.
type ShareInfo struct {
	Name     string // Share name (e.g., "documents")
	Comment  string // Optional description shown to clients
	Hidden   bool   // If true, share is not listed in browse requests
	ReadOnly bool   // If true, share is read-only

	// CreateMask is ANDed with requested permissions when creating files.
	// Use 0 for default (DefaultCreateMask = 0644).
	CreateMask uint16

	// DirectoryMask is ANDed with requested permissions when creating directories.
	// Use 0 for default (DefaultDirectoryMask = 0755).
	DirectoryMask uint16

	// ForceCreateMode is ORed with permissions when creating files.
	// Use 0 to disable (no forced bits).
	ForceCreateMode uint16

	// ForceDirectoryMode is ORed with permissions when creating directories.
	// Use 0 to disable (no forced bits).
	ForceDirectoryMode uint16

	// ForceUID forces all files to appear owned by this UID.
	// Use 0 for default (NoForceUID = don't force).
	ForceUID uint16

	// ForceGID forces all files to appear owned by this GID.
	// Use 0 for default (NoForceGID = don't force).
	ForceGID uint16
}

// EffectiveCreateMask returns CreateMask or DefaultCreateMask if zero.
func (s *ShareInfo) EffectiveCreateMask() uint16 {
	if s.CreateMask == 0 {
		return DefaultCreateMask
	}
	return s.CreateMask
}

// EffectiveDirectoryMask returns DirectoryMask or DefaultDirectoryMask if zero.
func (s *ShareInfo) EffectiveDirectoryMask() uint16 {
	if s.DirectoryMask == 0 {
		return DefaultDirectoryMask
	}
	return s.DirectoryMask
}

// EffectiveForceUID returns ForceUID or NoForceUID if zero.
func (s *ShareInfo) EffectiveForceUID() uint16 {
	if s.ForceUID == 0 {
		return NoForceUID
	}
	return s.ForceUID
}

// EffectiveForceGID returns ForceGID or NoForceGID if zero.
func (s *ShareInfo) EffectiveForceGID() uint16 {
	if s.ForceGID == 0 {
		return NoForceGID
	}
	return s.ForceGID
}

// TreeConnectContext contains information about a tree connect event.
type TreeConnectContext struct {
	Handle       uint32
	Username     string
	ShareName    string
	SessionID    uint64
	ConnectionID uint64
}

// FSShare defines a filesystem-backed share for FSShareProvider.
type FSShare struct {
	ShareInfo        // Embedded share metadata
	Path      string // Filesystem path to share
}

// FSShareProvider is a simple share provider backed by real filesystem paths.
// This is the default provider for serving files from local directories.
type FSShareProvider struct {
	shares map[string]FSShare
}

// NewFSShareProvider creates a new filesystem share provider.
func NewFSShareProvider(shares []FSShare) *FSShareProvider {
	p := &FSShareProvider{
		shares: make(map[string]FSShare),
	}
	for _, s := range shares {
		p.shares[strings.ToLower(s.Name)] = s
	}
	return p
}

// GetShare implements ShareProvider.
func (p *FSShareProvider) GetShare(name string) *ShareInfo {
	if s, ok := p.shares[strings.ToLower(name)]; ok {
		return &s.ShareInfo
	}
	return nil
}

// ListShares implements ShareProvider.
func (p *FSShareProvider) ListShares() []ShareInfo {
	result := make([]ShareInfo, 0, len(p.shares))
	for _, s := range p.shares {
		result = append(result, s.ShareInfo)
	}
	return result
}

// PathForSession implements ShareProvider.
func (p *FSShareProvider) PathForSession(share string, handle uint32) string {
	if s, ok := p.shares[strings.ToLower(share)]; ok {
		return s.Path
	}
	return ""
}

// OnLogin implements ShareProvider.
func (p *FSShareProvider) OnLogin(handle uint32, username string) error {
	return nil
}

// OnLogout implements ShareProvider.
func (p *FSShareProvider) OnLogout(handle uint32) error {
	return nil
}

// OnTreeConnect implements ShareProvider.
func (p *FSShareProvider) OnTreeConnect(ctx TreeConnectContext) error {
	return nil
}

// OnTreeDisconnect implements ShareProvider.
func (p *FSShareProvider) OnTreeDisconnect(sessionID, connID uint64) error {
	return nil
}

// Close implements ShareProvider.
func (p *FSShareProvider) Close() error {
	return nil
}

// Ensure FSShareProvider implements ShareProvider
var _ ShareProvider = (*FSShareProvider)(nil)
