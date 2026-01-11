package smbsys_test

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/gosmb/smbsys"
)

// Example_basicServer demonstrates a basic SMB server with filesystem shares.
func Example_basicServer() {
	// Create context that cancels on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Create and start the SMB server
	sys := smbsys.NewSys()
	err := sys.Start(ctx, smbsys.SysOpt{
		Logger: smbsys.NewLogger(os.Stderr),
		Config: smbsys.DefaultServerConfig(),
		ShareProvider: smbsys.NewFSShareProvider([]smbsys.FSShare{
			{
				ShareInfo: smbsys.ShareInfo{
					Name:    "documents",
					Comment: "Shared Documents",
				},
				Path: "/srv/samba/documents",
			},
			{
				ShareInfo: smbsys.ShareInfo{
					Name:     "private",
					Comment:  "Private Share",
					Hidden:   true, // Won't appear in browse lists
					ReadOnly: true,
				},
				Path: "/srv/samba/private",
			},
		}),
		Authenticator: smbsys.NewStaticUserAuthenticator(map[string]*smbsys.UserCredentials{
			"alice": {PasswordHash: smbsys.NewPassHash("alice-password"), UID: 1000, GID: 1000},
			"bob":   {PasswordHash: smbsys.NewPassHash("bob-password"), UID: 1001, GID: 1001},
		}),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start server: %v\n", err)
		return
	}

	// Wait for shutdown
	sys.Wait()
}

// Example_secureServer demonstrates a high-security SMB server configuration.
func Example_secureServer() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Use secure configuration with mandatory signing
	config := smbsys.SecureServerConfig()
	config.RequireEncryption = true // Only allow encrypted connections
	config.NetBIOSName = "SECURE-SRV"

	sys := smbsys.NewSys()
	err := sys.Start(ctx, smbsys.SysOpt{
		Logger: smbsys.NewLogger(os.Stderr),
		Config: config,
		ShareProvider: smbsys.NewFSShareProvider([]smbsys.FSShare{
			{ShareInfo: smbsys.ShareInfo{Name: "secure"}, Path: "/srv/secure"},
		}),
		Authenticator: smbsys.NewStaticUserAuthenticator(map[string]*smbsys.UserCredentials{
			"admin": {PasswordHash: smbsys.NewPassHash("secure-password")},
		}),
	})
	if err != nil {
		return
	}
	sys.Wait()
}

// DatabaseAuthenticator is an example of a custom authenticator.
// In practice, this would connect to a database, LDAP, etc.
type DatabaseAuthenticator struct {
	// db *sql.DB // database connection
}

// Authenticate implements smbsys.UserAuthenticator.
func (a *DatabaseAuthenticator) Authenticate(username string) (*smbsys.UserCredentials, error) {
	// In practice, look up the user in a database:
	// user, err := a.db.FindUser(username)
	// if err != nil {
	//     return nil, err
	// }
	// if user == nil {
	//     return nil, nil // User not found
	// }
	// return &smbsys.UserCredentials{
	//     PasswordHash: user.NTLMHash,
	//     UID:          user.UID,
	//     GID:          user.GID,
	// }, nil

	// Example: reject all users
	return nil, nil
}

// Verify interface implementation at compile time
var _ smbsys.UserAuthenticator = (*DatabaseAuthenticator)(nil)

// Example_customAuthentication demonstrates implementing a custom authenticator.
func Example_customAuthentication() {
	auth := &DatabaseAuthenticator{}

	// Use the custom authenticator with the server
	_ = smbsys.SysOpt{
		Authenticator: auth,
	}
}

// Example_sharePermissions demonstrates configuring share permission masks.
func Example_sharePermissions() {
	shares := []smbsys.FSShare{
		{
			ShareInfo: smbsys.ShareInfo{
				Name:              "uploads",
				Comment:           "Upload folder",
				CreateMask:        0644, // New files get rw-r--r--
				DirectoryMask:     0755, // New dirs get rwxr-xr-x
				ForceCreateMode:   0640, // Force group readable
				ForceDirectoryMode: 0750,
				ForceUID:          1000, // All files appear owned by UID 1000
				ForceGID:          1000,
			},
			Path: "/srv/uploads",
		},
	}

	provider := smbsys.NewFSShareProvider(shares)
	_ = provider
}

// ExampleNewPassHash demonstrates creating password hashes.
func ExampleNewPassHash() {
	// Create NTLM password hash from plaintext
	hash := smbsys.NewPassHash("my-password")

	// The hash is 16 bytes (MD4 of UTF-16LE encoded password)
	fmt.Printf("Hash length: %d bytes\n", len(hash))

	// Unicode passwords work correctly
	unicodeHash := smbsys.NewPassHash("пароль") // Russian for "password"
	_ = unicodeHash

	// Output:
	// Hash length: 16 bytes
}

// ExampleDefaultServerConfig demonstrates the default configuration.
func ExampleDefaultServerConfig() {
	cfg := smbsys.DefaultServerConfig()

	fmt.Printf("Signing: %d (1=Enabled)\n", cfg.Signing)
	fmt.Printf("Encryption: %v\n", cfg.Encryption)
	fmt.Printf("MinProtocol: %s\n", cfg.MinProtocol)
	fmt.Printf("MaxProtocol: %s\n", cfg.MaxProtocol)
	fmt.Printf("TCPPort: %d\n", cfg.TCPPort)

	// Output:
	// Signing: 1 (1=Enabled)
	// Encryption: true
	// MinProtocol: SMB300
	// MaxProtocol: SMB311
	// TCPPort: 445
}
