package smbsys

import (
	"fmt"

	"github.com/kardianos/gosmb/krb5"
)

// KerberosConfig configures Kerberos authentication for the SMB server.
//
// For Kerberos to work, you need:
//   - A KDC (Key Distribution Center) - Active Directory or MIT Kerberos
//   - A service principal for your SMB server (e.g., cifs/server.example.com@REALM)
//   - The service principal's password or keytab
//
// Example configuration:
//
//	cfg := KerberosConfig{
//	    ServicePrincipal: "cifs/fileserver.example.com",
//	    Realm:            "EXAMPLE.COM",
//	    Password:         "service-account-password",
//	}
type KerberosConfig struct {
	// ServicePrincipal is the Kerberos principal name for this SMB service.
	// Format: "cifs/hostname" (without the realm suffix).
	// Example: "cifs/fileserver.example.com"
	ServicePrincipal string

	// Realm is the Kerberos realm (typically uppercase domain name).
	// Example: "EXAMPLE.COM"
	Realm string

	// Password is the service principal's password.
	// Used to derive encryption keys for validating service tickets.
	Password string
}

// NewKerberosAuthenticator creates a KerberosAuthenticator from configuration.
// This creates all necessary cryptographic keys in memory.
func NewKerberosAuthenticator(cfg KerberosConfig) (KerberosAuthenticator, error) {
	if cfg.ServicePrincipal == "" {
		return nil, fmt.Errorf("ServicePrincipal is required")
	}
	if cfg.Realm == "" {
		return nil, fmt.Errorf("Realm is required")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("Password is required")
	}

	// Create the underlying krb5 service authenticator
	svc, err := krb5.NewServiceAuthenticator(krb5.ServiceAuthenticatorConfig{
		Principal: cfg.ServicePrincipal,
		Realm:     cfg.Realm,
		Password:  cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("create service authenticator: %w", err)
	}

	return &krb5Authenticator{
		service:          svc,
		servicePrincipal: cfg.ServicePrincipal,
		realm:            cfg.Realm,
	}, nil
}

// krb5Authenticator implements KerberosAuthenticator using the krb5 package.
type krb5Authenticator struct {
	service          *krb5.ServiceAuthenticator
	servicePrincipal string
	realm            string
}

// ValidateAPReq validates a Kerberos AP-REQ and returns the authentication result.
func (a *krb5Authenticator) ValidateAPReq(apReqBytes []byte) (*KerberosAuthResult, error) {
	result, err := a.service.ValidateAPReq(apReqBytes)
	if err != nil {
		return nil, fmt.Errorf("validate AP-REQ: %w", err)
	}

	return &KerberosAuthResult{
		Username:   result.Username,
		SessionKey: result.SessionKey.KeyValue,
		APRep:      result.APRep,
	}, nil
}

// SPNEGOConfig returns the SPNEGO configuration for this authenticator.
func (a *krb5Authenticator) SPNEGOConfig() *SPNEGOConfig {
	return &SPNEGOConfig{
		ServicePrincipal: a.servicePrincipal,
		Realm:            a.realm,
	}
}

// Ensure krb5Authenticator implements KerberosAuthenticator
var _ KerberosAuthenticator = (*krb5Authenticator)(nil)
