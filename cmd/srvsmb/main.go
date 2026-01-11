package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/kardianos/gosmb/smbsys"
)

func main() {
	// Create context that cancels on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	sys := smbsys.NewSys()
	err := sys.Start(ctx, smbsys.SysOpt{
		Logger: smbsys.NewLogger(os.Stderr),
		Config: smbsys.DefaultServerConfig(),
		ShareProvider: smbsys.NewFSShareProvider([]smbsys.FSShare{
			{ShareInfo: smbsys.ShareInfo{Name: "memshare"}, Path: "/tmp/gosmb_test"},
		}),
		Authenticator: smbsys.NewStaticUserAuthenticator(map[string]*smbsys.UserCredentials{
			"testuser": {PasswordHash: smbsys.NewPassHash("my-pass")},
		}),
	})
	if err != nil {
		os.Exit(1)
	}

	// Wait for shutdown to complete
	sys.Wait()
}
