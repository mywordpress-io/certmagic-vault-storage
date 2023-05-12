package certmagic_vault_storage_test

import (
	"context"
	vaultStorage "github.com/mywordpress-io/certmagic-vault-storage"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	"io/fs"
	"strconv"
	"time"
)

var _ = Describe("Vault Storage", func() {
	ctx := context.Background()
	Context("Basic Operations", func() {
		It("Are Successful", func() {
			// Try to list
			items, err := storage.List(ctx, "does-not-exist", false)
			Expect(err).Should(Equal(fs.ErrNotExist))
			Expect(items).Should(BeEmpty())

			// Does the secret exist?
			Expect(storage.Exists(ctx, "foo.bar")).Should(Equal(false))

			// Try to load, expect err
			result, err := storage.Load(ctx, "foo.bar")
			Expect(err).Should(Equal(fs.ErrNotExist))
			Expect(result).Should(BeEmpty())

			// Try to save
			err = storage.Store(ctx, "foo.bar", []byte("This is some long text we want to store"))
			Expect(err).ShouldNot(HaveOccurred())

			// Does the secret exist?
			Expect(storage.Exists(ctx, "foo.bar")).Should(Equal(true))

			// Try to re-list
			items, err = storage.List(ctx, "", false)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(items).ShouldNot(BeEmpty())
			Expect(items[0]).Should(Equal("foo.bar"))

			// Try to re-load
			result, err = storage.Load(ctx, "foo.bar")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(string(result)).Should(Equal("This is some long text we want to store"))

			// Try to delete
			err = storage.Delete(ctx, "foo.bar")
			Expect(err).ShouldNot(HaveOccurred())
		})
	})

	Context("Stat Operations", func() {
		It("Returns correct error when key does not exist", func() {
			info, err := storage.Stat(ctx, "does-not-exist")
			Expect(err).Should(Equal(fs.ErrNotExist))
			Expect(info).Should(MatchAllFields(Fields{
				"Key":        BeEmpty(),
				"Modified":   BeZero(),
				"Size":       BeZero(),
				"IsTerminal": BeZero(),
			}))
		})

		It("Returns correct data for key", func() {
			info, err := storage.Stat(ctx, "staging/abc456/test1.whatever.com")
			Expect(err).ShouldNot(HaveOccurred())
			Expect(info).To(MatchAllFields(Fields{
				"Key":        Equal("staging/abc456/test1.whatever.com"),
				"Modified":   Not(BeZero()),
				"Size":       Equal(int64(79)),
				"IsTerminal": Equal(true),
			}))
		})
	})

	Context("List Operations", func() {
		id := func(index int, _ interface{}) string {
			return strconv.Itoa(index)
		}

		It("Works without prefix", func() {
			items, err := storage.List(ctx, "", false)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(items).ShouldNot(BeEmpty())
			Expect(len(items)).Should(Equal(2))
			Expect(items[0]).Should(Equal("foo.bar.baz"))
		})

		It("Works without prefix and recursion", func() {
			items, err := storage.List(ctx, "", true)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(items).ShouldNot(BeEmpty())
			Expect(len(items)).Should(Equal(10))
			Expect(items).To(MatchAllElementsWithIndex(id, Elements{
				"0": Equal("foo.bar.baz"),
				"1": Equal("foo.bar.com"),
				"2": Equal("production/test1.baz.com"),
				"3": Equal("production/test2.baz.com"),
				"4": Equal("production/test3.baz.com"),
				"5": Equal("staging/abc123/test3.whatever.com"),
				"6": Equal("staging/abc456/test1.whatever.com"),
				"7": Equal("staging/abc456/test3.whatever.com"),
				"8": Equal("staging/test3.baz.com"),
				"9": Equal("staging/test3.quux.org"),
			}))
		})

		It("Works with prefix", func() {
			items, err := storage.List(ctx, "staging/", false)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(items).ShouldNot(BeEmpty())
			Expect(len(items)).Should(Equal(2))
			Expect(items).To(MatchAllElementsWithIndex(id, Elements{
				"0": Equal("staging/test3.baz.com"),
				"1": Equal("staging/test3.quux.org"),
			}))
		})

		It("Works with prefix and recursion", func() {
			items, err := storage.List(ctx, "staging/", true)
			Expect(err).ShouldNot(HaveOccurred())
			Expect(items).ShouldNot(BeEmpty())
			Expect(len(items)).Should(Equal(5))
			Expect(items).To(MatchAllElementsWithIndex(id, Elements{
				"0": Equal("staging/abc123/test3.whatever.com"),
				"1": Equal("staging/abc456/test1.whatever.com"),
				"2": Equal("staging/abc456/test3.whatever.com"),
				"3": Equal("staging/test3.baz.com"),
				"4": Equal("staging/test3.quux.org"),
			}))
		})
	})

	Context("Locking", func() {
		It("Successfully Locks and Unlocks Key", func() {
			Expect(storage.Lock(ctx, "foo.bar.baz")).ShouldNot(HaveOccurred())
			Expect(storage.Unlock(ctx, "foo.bar.baz")).ShouldNot(HaveOccurred())
		})

		It("Does not allow deadlocks", func() {
			Expect(storage.Lock(ctx, "foo.bar.com")).ShouldNot(HaveOccurred())
			Expect(storage.Lock(ctx, "foo.bar.com")).ShouldNot(HaveOccurred())
			time.After(10 * time.Second)
			Expect(storage.Unlock(ctx, "foo.bar.com")).ShouldNot(HaveOccurred())
		})
	})

	Context("Approle Login and Logout", func() {
		customLockTimeout := vaultStorage.Duration(15 * time.Second)
		customLockPollingDuration := vaultStorage.Duration(5 * time.Second)
		approleStorage := vaultStorage.NewStorage(vaultStorage.StorageConfig{
			URL:                 vaultStorage.MustParseURL("http://localhost:8200"),
			Token:               "",
			ApproleLoginPath:    "auth/approle/login",
			ApproleLogoutPath:   "auth/token/revoke-self",
			ApproleRoleId:       approleRoleId,
			ApproleSecretId:     approleSecretId,
			SecretsPath:         "secrets",
			PathPrefix:          "certificates",
			LockTimeout:         &customLockTimeout,
			LockPollingInterval: &customLockPollingDuration,
			InsecureSkipVerify:  false,
			LogLevel:            "debug",
		})

		It("Successfully performs lock & unlock operations", func() {
			Expect(approleStorage.Lock(ctx, "foo.bar.baz")).ShouldNot(HaveOccurred())
			Expect(approleStorage.Unlock(ctx, "foo.bar.baz")).ShouldNot(HaveOccurred())
		})

		It("Successfully unlocks after token expired", func() {
			Expect(approleStorage.Lock(ctx, "foo.bar.baz")).ShouldNot(HaveOccurred())
			time.Sleep(35 * time.Second)
			Expect(approleStorage.Unlock(ctx, "foo.bar.baz")).ShouldNot(HaveOccurred())
		})
	})
})
