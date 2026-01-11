# gosmb

A Go userspace daemon for the Linux kernel's ksmbd SMB server. This library provides:

- **gosmb**: Core SMB server daemon that communicates with the ksmbd kernel module via netlink
- **vfs**: A FUSE-based virtual filesystem backend for serving per-user virtual files over SMB

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

```go
package main

import "github.com/kardianos/gosmb"

func main() {
    // Use secure defaults (signing enabled, encryption enabled, SMB 3.0+)
    cfg := gosmb.DefaultServerConfig()
    gosmb.SetServerConfig(cfg)

    // Start the SMB server (blocks forever)
    gosmb.Run()
}
```

### With Virtual Filesystem

```go
package main

import (
    "github.com/kardianos/gosmb"
    "github.com/kardianos/gosmb/vfs"
)

func main() {
    // Create an in-memory filesystem handler
    handler := vfs.NewMemoryFSHandler()

    // Initialize per-user files
    handler.InitUser("alice", map[string][]byte{
        "hello.txt":         []byte("Hello, Alice!"),
        "docs/readme.txt":   []byte("Alice's documents"),
    })
    handler.InitUser("bob", map[string][]byte{
        "hello.txt":         []byte("Hello, Bob!"),
    })

    // Create FUSE backend (mounts at /run/gosmb-vfs)
    backend, err := vfs.NewBackend(vfs.DefaultMountPoint, handler)
    if err != nil {
        panic(err)
    }
    defer backend.Close()

    // Register backend for the share
    gosmb.RegisterBackend("memshare", backend)

    // Start server
    gosmb.Run()
}
```

## Configuration

### Server Security Configuration

```go
// Default configuration (recommended for most uses)
cfg := gosmb.DefaultServerConfig()
// - Signing: SigningEnabled
// - Encryption: true
// - MinProtocol: "SMB300" (no SMB1/SMB2.0)
// - MaxProtocol: "SMB311"

// High-security configuration
cfg := gosmb.SecureServerConfig()
// - Signing: SigningMandatory (rejects clients without signing)

// Custom configuration
cfg := gosmb.ServerConfig{
    Signing:           gosmb.SigningMandatory, // 0=Disabled, 1=Enabled, 2=Auto, 3=Mandatory
    Encryption:        true,                    // Enable SMB3 encryption
    RequireEncryption: false,                   // Only allow encrypted connections
    MinProtocol:       "SMB300",                // Minimum SMB version
    MaxProtocol:       "SMB311",                // Maximum SMB version
    TCPPort:           445,                     // SMB port
    NetBIOSName:       "MY-SERVER",
    WorkGroup:         "WORKGROUP",
    ServerString:      "My SMB Server",
    MaxConnections:    100,
}
gosmb.SetServerConfig(cfg)
```

### Signing Options

| Value | Constant | Description |
|-------|----------|-------------|
| 0 | `SigningDisabled` | No packet signing (INSECURE) |
| 1 | `SigningEnabled` | Sign if client supports it (default) |
| 2 | `SigningAuto` | Let ksmbd decide |
| 3 | `SigningMandatory` | Require signing (RECOMMENDED for production) |

## VFS Package

The `vfs` package provides a FUSE-based virtual filesystem that enables per-user file views over SMB.

### FSHandler Interface

Implement `vfs.FSHandler` to provide custom filesystem logic:

```go
type FSHandler interface {
    Getattr(ctx context.Context, user, path string) (*Attr, error)
    Lookup(ctx context.Context, user, path string) (*Attr, error)
    ReadDir(ctx context.Context, user, path string) ([]DirEntry, error)
    Read(ctx context.Context, user, path string, dest []byte, offset int64) (int, error)
    Write(ctx context.Context, user, path string, data []byte, offset int64) (int, error)
    Create(ctx context.Context, user, path string, mode uint32) error
    Mkdir(ctx context.Context, user, path string, mode uint32) error
    Remove(ctx context.Context, user, path string) error
    Rename(ctx context.Context, user, oldPath, newPath string) error
    Truncate(ctx context.Context, user, path string, size uint64) error
    SetAttr(ctx context.Context, user, path string, attr *Attr) error
}
```

### Read-Only Handler

Embed `vfs.ReadOnlyHandler` to get default read-only implementations:

```go
type MyHandler struct {
    vfs.ReadOnlyHandler // Embeds EROFS responses for write operations
}

func (h *MyHandler) Getattr(ctx context.Context, user, path string) (*vfs.Attr, error) {
    // Your implementation
}
// ... implement read operations only
```

### Built-in Handlers

- **MemoryFSHandler**: In-memory per-user filesystem (good for testing)

### Backend Options

```go
// Default options (secure)
opts := vfs.DefaultBackendOptions()
// - AllowRoot: true (only root can access FUSE mount)

// Create with options
backend, err := vfs.NewBackendWithOptions("/run/gosmb-vfs", handler, opts)
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
docker-compose run --rm test

# Or use the helper script
./test-docker.sh test

# Interactive shell
./test-docker.sh shell
```

### Local (Requires ksmbd on host)

```bash
go test -c -o test-smbsys ./smbsys && sudo ./test-smbsys; rm test-smbsys
go test -c -o test-smbvfs ./smbvfs && sudo ./test-smbvfs; rm test-smbvfs
```

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ SMB Client  │────▶│    ksmbd     │────▶│   gosmb     │
│ (Windows,   │     │   (kernel)   │     │ (userspace) │
│  smbclient) │     └──────────────┘     └──────┬──────┘
└─────────────┘            │                    │
                           │ netlink            │ RegisterBackend()
                           │                    ▼
                    ┌──────▼──────┐     ┌──────────────┐
                    │   Shared    │◀────│ vfs.Backend  │
                    │ Filesystem  │     │   (FUSE)     │
                    └─────────────┘     └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │  FSHandler   │
                                        │ (your impl)  │
                                        └──────────────┘
```

### Session Flow

1. **LOGIN_REQUEST**: User authenticates, gosmb validates credentials
2. **SHARE_CONFIG_REQUEST**: ksmbd requests share path, gosmb returns session-specific FUSE path
3. **TREE_CONNECT_REQUEST**: User connects to share
4. File operations go through FUSE → FSHandler with user context

## Share Configuration

Shares are defined in `gosmb.Shares`:

```go
var Shares = []ShareDef{
    {Name: "memshare", Path: "/tmp/gosmb_test", Type: 0, Comment: ""},
    {Name: "IPC$", Path: "/dev/null", Type: 0x80000003, Comment: "IPC"},
}
```

## License

See LICENSE file.
