package certmagic_vault_storage

import (
	"context"
	. "fmt"
	"github.com/caddyserver/certmagic"
	"github.com/mywordpress-io/certmagic-vault-storage/internal/client"
	"github.com/mywordpress-io/certmagic-vault-storage/internal/logger"
	"go.uber.org/zap"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

var (
	defaultLockTimeout         = Duration(5 * time.Minute)
	defaultLockPollingInterval = Duration(5 * time.Second)
)

func NewStorage(config StorageConfig) *Storage {
	storage := &Storage{
		StorageConfig: config,
		client:        client.NewClient(config.InsecureSkipVerify).SetHostUrl(config.vaultBaseUrl()),
	}

	if storage.ApproleLoginPath == "" {
		storage.ApproleLoginPath = "auth/approle/login"
	}

	if storage.ApproleLogoutPath == "" {
		storage.ApproleLogoutPath = "auth/token/revoke-self"
	}

	if storage.LockTimeout == nil {
		storage.LockTimeout = &defaultLockTimeout
	}

	if storage.LockPollingInterval == nil {
		storage.LockPollingInterval = &defaultLockPollingInterval
	}

	return storage
}

type StorageConfig struct {
	// URL the URL for Vault without any API versions or paths like 'https://vault.example.org:8201'.
	URL *URL `json:"address"`

	// Token, the static Vault token.  If 'Token' is set, we blindly use that 'Token' when making any calls to
	// the Vault API. Management of the token (create, revoke, renew, etc.) is up to the caller.
	Token string `json:"token"`

	// If 'Approle*', options are available, we log in to Vault to create a short-lived token, using that token to make
	// future calls into Vault, and once we are done automatically revoke it.  Note that we will "cache" that token for
	// up to its lifetime minus 5m so it can be re-used for future calls in to Vault by subsequent CertMagic Storage
	// operations.
	//
	// Approle settings are the recommended way to manage Vault authentication
	ApproleLoginPath  string `json:"approle_login_path"`
	ApproleLogoutPath string `json:"approle_logout_path"`
	ApproleRoleId     string `json:"approle_role_id"`
	ApproleSecretId   string `json:"approle_secret_id"`

	// SecretsPath is the path in Vault to the secrets engine
	SecretsPath string `json:"secrets_path"`

	// PathPrefix is the path in the secrets engine where certificates will be placed (default: 'certificates'), assuming:
	//           URL: https://vault.example.org:8201
	//       SecretsPath: secrets/production
	//        PathPrefix: engineering/certmagic/certificates
	//
	// You will end up with paths like this in vault:
	//     'data' path: https://vault.example.org:8201/v1/secrets/production/data/engineering/certmagic/certificates
	// 'metadata' path: https://vault.example.org:8201/v1/secrets/production/metadata/engineering/certmagic/certificates
	PathPrefix string `json:"path_prefix"`

	// InsecureSkipVerify ignore TLS errors when communicating with vault - Default: false
	InsecureSkipVerify bool `json:"insecure_skip_verify"`

	// Locking mechanism
	LockTimeout         *Duration `json:"lock_timeout"`
	LockPollingInterval *Duration `json:"lock_polling_interval"`
}

func (c *StorageConfig) vaultBaseUrl() string {
	return Sprintf("%s/v1/", c.URL)
}

// Storage is the main object passed to CertMagic that implements the "Storage" interface.
type Storage struct {
	StorageConfig

	// client is the API client making requests to Vault
	client *client.Client

	// approleResponse is the successful response from Vault after logging in using ApproleRoleId/ApproleSecretId
	approleResponse *successResponse

	// approleTokenExpiration the future date when the token expires
	approleTokenExpiration *time.Time
}

func (s *Storage) Store(_ context.Context, key string, value []byte) error {
	logger.Zap.Debugw("Store() at url", "url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)))

	secret := &certificateSecret{
		Certmagic: certMagicCertificateSecret{Data: value},
	}
	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Post(s.vaultDataPath(key), secret, result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] Unable to store certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() {
		logger.Zap.Errorw(
			"[ERROR] Unable to store certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return errResponse.Error()
	}

	return nil
}

func (s *Storage) Load(_ context.Context, key string) ([]byte, error) {
	logger.Zap.Debugw("Load() from url", "url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)))

	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Get(s.vaultDataPath(key), result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] Unable to load certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return nil, err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		logger.Zap.Errorw(
			"[ERROR] Unable to load certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
	}

	if resp.IsError() && resp.StatusCode() == http.StatusNotFound {
		return nil, fs.ErrNotExist
	}

	return result.Data.Data.Certmagic.Data, nil
}

func (s *Storage) Delete(_ context.Context, key string) error {
	logger.Zap.Debugw("Delete() at url", "url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultMetadataPath(key)))

	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Delete(s.vaultMetadataPath(key), result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] Unable to delete certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		logger.Zap.Errorw(
			"[ERROR] Unable to delete certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
	}

	if resp.IsError() && resp.StatusCode() == http.StatusNotFound {
		return fs.ErrNotExist
	}

	return nil
}

func (s *Storage) Exists(_ context.Context, key string) bool {
	logger.Zap.Debugw("Exists() at url", "url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)))

	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Get(s.vaultDataPath(key), result, errResponse)
	if err != nil {
		return false
	}

	if resp.IsError() {
		return false
	}

	return len(result.Data.Data.Certmagic.Data) > 0
}

// List will recursively list all items at prefix if recursive==true.  If not, it will just return a list of items that
// are NOT "directories" in Vault.  Note that Vault's kv-v2 engine doesn't really have the idea of directories, they
// are more like paths in a tree (I guess?).
//
// Caveats:
//     - When recursive==false, we ONLY include item that do NOT have a trailing slash
//     - When recursive==true, we include ALL items from the specified prefix that do NOT have a trailing slash
func (s *Storage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	logger.Zap.Debugw("List() at url", "url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultMetadataPath(prefix)), "recursive", recursive)

	result := &listResponse{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).List(s.vaultMetadataPath(prefix), result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] Unable to list certificates",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultMetadataPath(prefix)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return []string{}, err
	}

	// Recursively list all items in vault
	items := make([]string, 0)
	for _, entry := range result.Data.Keys {
		var path string
		if strings.HasSuffix(prefix, "/") {
			path = Sprintf("%s%s", prefix, entry)
		} else {
			path = Sprintf("%s/%s", prefix, entry)
		}

		items = append(items, path)
		if recursive && strings.HasSuffix(entry, "/") {
			results, err := s.List(ctx, path, recursive)
			if err != nil {
				return []string{}, err
			}

			items = append(items, results...)
		}
	}

	// If we get nothing back, that means 'prefix' does not exist
	if len(items) == 0 {
		return items, fs.ErrNotExist
	}

	return items, nil
}

func (s *Storage) Stat(_ context.Context, key string) (certmagic.KeyInfo, error) {
	logger.Zap.Debugw("Stat() at url", "url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)))

	// Get the secret
	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Get(s.vaultDataPath(key), result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] Unable to stat certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return certmagic.KeyInfo{}, err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		logger.Zap.Errorw(
			"[ERROR] Unable to stat certificate",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
	}

	if resp.IsError() && resp.StatusCode() == http.StatusNotFound {
		return certmagic.KeyInfo{}, fs.ErrNotExist
	}

	return certmagic.KeyInfo{
		Key:        key,
		IsTerminal: true,
		Size:       int64(len(result.Data.Data.Certmagic.Data)),
		Modified:   time.Time(result.Data.Metadata.CreatedTime),
	}, nil
}

func (s *Storage) Lock(ctx context.Context, key string) error {
	lock := Sprintf("%s.lock", key)
	for {
		// Get the secret
		getResult := &response{}
		errResponse := &errorResponse{}
		resp, err := s.client.SetToken(s.getToken()).Get(s.vaultDataPath(lock), getResult, errResponse)
		if err != nil {
			logger.Zap.Errorw(
				"[ERROR] Unable to get lock",
				"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(lock)),
				"error", err.Error(),
				"vault_errors", s.vaultErrorString(errResponse),
				"response_code", resp.StatusCode(),
				"response_body", resp.String(),
			)
			return err
		}

		// If lock doesn't exist break immediately to create a new one
		if getResult.Data.Data.Certmagic.Lock == nil {
			break
		}

		// Lock exists, check if expired or sleep 5 seconds and check again
		if time.Now().After(time.Time(*getResult.Data.Data.Certmagic.Lock)) {
			if err := s.Unlock(ctx, key); err != nil {
				return err
			}
			break
		}

		select {
		case <-time.After(time.Duration(*s.LockPollingInterval)):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Lock doesn't exist, create it now
	expiration := time.Now().Add(time.Duration(*s.LockTimeout))
	secret := &certificateSecret{
		Certmagic: certMagicCertificateSecret{Lock: (*Time)(&expiration)},
	}
	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Post(s.vaultDataPath(lock), secret, result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] Unable to create lock",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(lock)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() {
		logger.Zap.Errorw(
			"[ERROR] Unable to create lock",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return errResponse.Error()
	}

	return nil
}

func (s *Storage) Unlock(_ context.Context, key string) error {
	lock := Sprintf("%s.lock", key)
	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Delete(s.vaultMetadataPath(lock), result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] Unable to remove lock",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(lock)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		logger.Zap.Errorw(
			"[ERROR] Unable to remove lock",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.vaultDataPath(key)),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
	}

	if resp.IsError() && resp.StatusCode() == http.StatusNotFound {
		return fs.ErrNotExist
	}

	return nil
}

func (s *Storage) vaultBaseUrl() string {
	return s.StorageConfig.vaultBaseUrl()
}

func (s *Storage) vaultDataPath(key string) string {
	return vaultCertMagicCertificateDataPathFormat.String(s.SecretsPath, s.PathPrefix, key)
}

func (s *Storage) vaultMetadataPath(key string) string {
	return vaultCertMagicCertificateMetadataPathFormat.String(s.SecretsPath, s.PathPrefix, key)
}

func (s *Storage) vaultErrorString(resp *errorResponse) string {
	if len(resp.Errors) > 0 {
		return resp.Error().Error()
	}

	return ""
}

func (s *Storage) SetLogger(sugaredLogger *zap.SugaredLogger) {
	logger.Zap = sugaredLogger
}

// Interface guard
var _ certmagic.Storage = (*Storage)(nil)
