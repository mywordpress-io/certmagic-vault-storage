# certmagic-vault-storage

This is a Storage backend for CertMagic which allows storing of TLS certificates managed by it in HashiCorp's Vault.

This plugin can be used standalone in your own go-program, or it can be pulled in to Caddy by using the associated
project: https://github.com/mywordpress-io/caddy-vault-storage

## Usage

### Caddy

For usage as a Caddy plugin built with `xcaddy`, review [this project](https://github.com/mywordpress-io/caddy-vault-storage).

### Standalone

For standalone usage in your own go module:

```go
package main

import (
	certMagicVaultStorage "github.com/mywordpress-io/certmagic-vault-storage"
)

func Setup() {
	certmagic := certmagic.NewDefault()

	// Specify your setting to certMagicVaultStorage here, and assign the Storage provider to CertMagic:
	certmagic.Storage = certMagicVaultStorage.NewStorage(certMagicVaultStorage.StorageConfig{
		URL:                certMagicVaultStorage.MustParseURL("https://vault.example.org:8201"),
		SecretsPath:        "secrets",
		PathPrefix:         "production/certificates",
		InsecureSkipVerify: true,
		Token:              "baad-f00d",
		ApproleRoleId:      "dead-beef", // Required if 'token' empty
		ApproleSecretId:    "ea7-beef",  // Required if 'token' empty
		LogLevel:           "info",
	})
	
	// Now do other operations with 'certmagic' as you normally would:
	certmagic.Issuers = ...
}
```