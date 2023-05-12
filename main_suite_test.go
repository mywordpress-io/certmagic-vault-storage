package certmagic_vault_storage_test

import (
	"context"
	. "fmt"
	"os"
	"time"

	vaultStorage "github.com/mywordpress-io/certmagic-vault-storage"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"testing"
)

var (
	storage *vaultStorage.Storage
	keys    = []string{
		"foo.bar.com",
		"foo.bar.baz",
		"production/test1.baz.com",
		"production/test2.baz.com",
		"production/test3.baz.com",
		"staging/abc123/test3.whatever.com",
		"staging/abc456/test1.whatever.com",
		"staging/abc456/test3.whatever.com",
		"staging/test3.baz.com",
		"staging/test3.quux.org",
	}

	approleRoleId   = os.Getenv("VAULT_APPROLE_ROLE_ID")
	approleSecretId = os.Getenv("VAULT_APPROLE_SECRET_ID")
)

func TestVaultStorageSuite(test *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(test, "Storage")
}

var _ = BeforeSuite(func() {
	customLockTimeout := vaultStorage.Duration(15 * time.Second)
	customLockPollingDuration := vaultStorage.Duration(5 * time.Second)
	storage = vaultStorage.NewStorage(vaultStorage.StorageConfig{
		URL:                 vaultStorage.MustParseURL("http://localhost:8200"),
		Token:               "dead-beef",
		SecretsPath:         "secrets",
		PathPrefix:          "certificates",
		LockTimeout:         &customLockTimeout,
		LockPollingInterval: &customLockPollingDuration,
		InsecureSkipVerify:  false,
		LogLevel:            "debug",
	})
	Expect(storage).ShouldNot(BeNil())

	for _, key := range keys {
		err := storage.Store(context.Background(), key, []byte(Sprintf("This is some long text we want to store for '%s'", key)))
		Expect(err).ShouldNot(HaveOccurred())
	}
})

var _ = AfterSuite(func() {
	// Delete test keys, ignoring errors
	for _, key := range keys {
		storage.Delete(context.Background(), key) //nolint:errcheck
	}
})
