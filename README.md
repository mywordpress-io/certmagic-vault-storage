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
	"github.com/mywordpress-io/certmagic-vault-storage"
	"github.com/mywordpress-io/caddy-vault-storage"
)

func Setup() {
	certmagic := certmagic.NewDefault()
	
	// This is the base configuration object used by certmagic_vault_storage--you can either use the
	// one specified in the caddy_vault_storage repo, or roll your own (as long as it satisfies the
	// certmagic_vault_storage.StorageConfigInterface interface).
	customLockTimeout := certmagic_vault_storage.Duration(60 * time.Second)
	customLockPollingDuration := certmagic_vault_storage.Duration(5 * time.Second)
	caddyStorage := &caddy_vault_storage.Storage{
		URL:                 certmagic_vault_storage.MustParseURL("http://localhost:8200"),
		Token:               "dead-beef",
		SecretsPath:         "secrets",
		PathPrefix:          "certificates",
		LockTimeout:         &customLockTimeout,
		LockPollingInterval: &customLockPollingDuration,
		InsecureSkipVerify:  false,
	}

	// Specify your setting to certMagicVaultStorage here, and assign the Storage provider to CertMagic:
	certmagic.Storage = certmagic_vault_storage.NewStorage(caddyStorage)
	
	// Now do other operations with 'certmagic' as you normally would:
	certmagic.Issuers = ...
}
```