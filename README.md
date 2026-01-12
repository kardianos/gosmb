# gosmb

A Go userspace daemon for the Linux kernel's ksmbd SMB server. This library provides:

- **smbsys**: Core SMB server daemon that communicates with the ksmbd kernel module via netlink
- **smbvfs**: A FUSE-based virtual filesystem backend for serving per-user virtual files over SMB

## Requirements

- Linux kernel with ksmbd module (5.15+)
- Root privileges (for kernel module interaction)
- Go 1.21+

## Installation

```bash
go get github.com/kardianos/gosmb
```

## Quick Start

### Basic Server

See [smbsys/example_test.go](smbsys/example_test.go) for complete examples.

```go
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/gosmb/smbsys"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	sys := smbsys.NewSys()
	err := sys.Start(ctx, smbsys.SysOpt{
		Logger: smbsys.NewLogger(os.Stderr),
		Config: smbsys.DefaultServerConfig(),
		ShareProvider: smbsys.NewFSShareProvider([]smbsys.FSShare{
			{ShareInfo: smbsys.ShareInfo{Name: "documents"}, Path: "/srv/samba/documents"},
		}),
		Authenticator: smbsys.NewStaticUserAuthenticator(map[string]*smbsys.UserCredentials{
			"alice": {PasswordHash: smbsys.NewPassHash("alice-password")},
		}),
	})
	if err != nil {
		os.Exit(1)
	}
	sys.Wait()
}
```

### With Virtual Filesystem

See [smbvfs/example_test.go](smbvfs/example_test.go) for complete examples.

```go
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/gosmb/smbsys"
	"github.com/kardianos/gosmb/smbvfs"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Create an in-memory filesystem handler with per-user files
	handler := smbvfs.NewMemoryFSHandler()
	handler.InitUser("alice", map[string][]byte{
		"hello.txt":       []byte("Hello, Alice!"),
		"docs/readme.txt": []byte("Alice's documents"),
	})
	handler.InitUser("bob", map[string][]byte{
		"hello.txt": []byte("Hello, Bob!"),
	})

	// Create FUSE backend (mounts at /run/gosmb-vfs)
	backend, err := smbvfs.NewBackend(smbvfs.DefaultMountPoint, handler)
	if err != nil {
		panic(err)
	}
	defer backend.Close()

	// Start server with VFS backend as the share provider
	sys := smbsys.NewSys()
	err = sys.Start(ctx, smbsys.SysOpt{
		Logger:        smbsys.NewLogger(os.Stderr),
		Config:        smbsys.DefaultServerConfig(),
		ShareProvider: backend,
		Authenticator: smbsys.NewStaticUserAuthenticator(map[string]*smbsys.UserCredentials{
			"alice": {PasswordHash: smbsys.NewPassHash("alice-pass")},
			"bob":   {PasswordHash: smbsys.NewPassHash("bob-pass")},
		}),
	})
	if err != nil {
		os.Exit(1)
	}
	sys.Wait()
}
```

## Configuration

### Server Security Configuration

```go
// Default configuration (recommended for most uses)
cfg := smbsys.DefaultServerConfig()
// - Signing: SigningEnabled
// - Encryption: true
// - MinProtocol: "SMB300" (no SMB1/SMB2.0)
// - MaxProtocol: "SMB311"

// High-security configuration
cfg := smbsys.SecureServerConfig()
// - Signing: SigningMandatory (rejects clients without signing)

// Custom configuration
cfg := smbsys.ServerConfig{
	Signing:           smbsys.SigningMandatory,
	Encryption:        true,
	RequireEncryption: false,
	MinProtocol:       smbsys.ProtocolSMB300,
	MaxProtocol:       smbsys.ProtocolSMB311,
	TCPPort:           445,
	NetBIOSName:       "MY-SERVER",
	WorkGroup:         "WORKGROUP",
	ServerString:      "My SMB Server",
	MaxConnections:    100,
}
```

### Signing Options

| Value | Constant | Description |
|-------|----------|-------------|
| 0 | `SigningDisabled` | No packet signing (INSECURE) |
| 1 | `SigningEnabled` | Sign if client supports it (default) |
| 2 | `SigningAuto` | Let ksmbd decide |
| 3 | `SigningMandatory` | Require signing (RECOMMENDED for production) |

### Share Configuration

Shares are configured via the `ShareProvider` interface. The `GetShare` method receives a `Session` containing the share name and user context for per-user access control. Use `FSShareProvider` for filesystem-backed shares:

```go
shares := smbsys.NewFSShareProvider([]smbsys.FSShare{
	{
		ShareInfo: smbsys.ShareInfo{
			Name:              "documents",
			Comment:           "Shared Documents",
			Hidden:            false,  // Visible in browse lists
			ReadOnly:          false,
			CreateMask:        0644,   // Permission mask for new files
			DirectoryMask:     0755,   // Permission mask for new directories
			ForceUID:          1000,   // Force files to appear owned by this UID
			ForceGID:          1000,
		},
		Path: "/srv/samba/documents",
	},
})
```

## VFS Package

The `smbvfs` package provides a FUSE-based virtual filesystem that enables per-user file views over SMB.

### FSHandler Interface

Implement `smbvfs.FSHandler` to provide custom filesystem logic. All methods receive a `Session` containing the authenticated user, share name, and session handle.

```go
type FSHandler interface {
	Getattr(ctx context.Context, s Session, path string) (*Attr, error)
	Lookup(ctx context.Context, s Session, path string) (*Attr, error)
	ReadDir(ctx context.Context, s Session, path string) ([]DirEntry, error)
	Read(ctx context.Context, s Session, path string, dest []byte, offset int64) (int, error)
	Write(ctx context.Context, s Session, path string, data []byte, offset int64) (int, error)
	Create(ctx context.Context, s Session, path string, mode uint32) error
	Mkdir(ctx context.Context, s Session, path string, mode uint32) error
	Remove(ctx context.Context, s Session, path string) error
	Rename(ctx context.Context, s Session, oldPath, newPath string) error
	Truncate(ctx context.Context, s Session, path string, size uint64) error
	SetAttr(ctx context.Context, s Session, path string, attr *Attr) error
}
```

The `Session` type is defined in `smbsys` and aliased in `smbvfs` for convenience:

```go
// smbsys.Session identifies the user and share for an operation
type Session struct {
	User   string // Authenticated username (may be empty if lookup needed)
	Share  string // Share name being accessed
	Handle uint32 // ksmbd session handle
}
```

Session is used consistently across the ShareProvider and FSHandler interfaces.

### Custom Errors

FSHandler methods should return these errors for proper translation to SMB/FUSE error codes:

```go
var (
	ErrReadOnly   = errors.New("read-only filesystem")  // EROFS
	ErrNotFound   = errors.New("file not found")        // ENOENT
	ErrExists     = errors.New("file exists")           // EEXIST
	ErrNotEmpty   = errors.New("directory not empty")   // ENOTEMPTY
	ErrIsDir      = errors.New("is a directory")        // EISDIR
	ErrNotDir     = errors.New("not a directory")       // ENOTDIR
	ErrPermission = errors.New("permission denied")     // EACCES
	ErrInvalidArg = errors.New("invalid argument")      // EINVAL
)
```

### Read-Only Handler

Embed `smbvfs.ReadOnlyHandler` to get default read-only implementations:

```go
type MyHandler struct {
	smbvfs.ReadOnlyHandler // Returns ErrReadOnly for all write operations
}

func (h *MyHandler) Getattr(ctx context.Context, s smbvfs.Session, path string) (*smbvfs.Attr, error) {
	// Your implementation
}
// ... implement read operations only
```

### Built-in Handlers

- **MemoryFSHandler**: In-memory per-user filesystem (good for testing and dynamic content)

### Backend Options

```go
// Default options (secure)
opts := smbvfs.DefaultBackendOptions()
// - AllowRoot: true (only root can access FUSE mount)
// - ShareName: "vfs"

// Create with options
backend, err := smbvfs.NewBackendWithOptions("/run/gosmb-vfs", handler, opts)
```

### Security Features

- Mount point permissions: `0700` (root only)
- Session handles are not enumerable (prevents session hijacking)
- Unknown sessions are rejected (no fallback user)
- Default mount point: `/run/gosmb-vfs` (tmpfs, cleaned on reboot)

## Running Tests

Tests require root privileges and the ksmbd kernel module.

### Docker (Recommended)

Uses the host kernel's ksmbd module in a privileged container:

```bash
# Run tests
./test-docker.sh

# Run with verbose output
./test-docker.sh -v

# Run with race detector
./test-docker.sh -race

# Combined flags
./test-docker.sh -v -race

# Interactive shell
./test-docker.sh shell
```

The container image is built once and cached (tagged by Dockerfile hash). Go module and build caches are persisted in Docker volumes (`gosmb-modcache`, `gosmb-buildcache`).

### Local (Requires ksmbd on host)

```bash
go test -c -o test-smbsys ./smbsys && sudo ./test-smbsys; rm test-smbsys
go test -c -o test-smbvfs ./smbvfs && sudo ./test-smbvfs; rm test-smbvfs
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ SMB Client  │────▶│    ksmbd     │────▶│   smbsys    │
│ (Windows,   │     │   (kernel)   │     │ (userspace) │
│  smbclient) │     └──────────────┘     └──────┬──────┘
└─────────────┘            │                    │
                           │ netlink            │ ShareProvider
                           │                    ▼
                    ┌──────▼──────┐     ┌──────────────┐
                    │   Shared    │◀────│ smbvfs       │
                    │ Filesystem  │     │ (FUSE)       │
                    └─────────────┘     └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │  FSHandler   │
                                        │ (your impl)  │
                                        └──────────────┘
```

### Session Flow

1. **LOGIN_REQUEST**: User authenticates via `UserAuthenticator`
2. **SHARE_CONFIG_REQUEST**: ksmbd requests share path via `ShareProvider.PathForSession()`
3. **TREE_CONNECT_REQUEST**: User connects to share, `ShareProvider.OnTreeConnect()` called
4. File operations go through FUSE → FSHandler with `Session` context

## Examples

See the example files for complete, runnable code:

- [smbsys/example_test.go](smbsys/example_test.go) - Server configuration, authentication, shares
- [smbvfs/example_test.go](smbvfs/example_test.go) - FSHandler implementation, memory handler, custom handlers

## License

See LICENSE file.
