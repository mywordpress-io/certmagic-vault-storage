package certmagic_vault_storage

import (
	"context"
	. "fmt"
	"github.com/caddyserver/certmagic"
	"github.com/mywordpress-io/certmagic-vault-storage/internal/client"
	"go.uber.org/zap"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

type StorageConfigInterface interface {
	GetLogger() *zap.SugaredLogger

	GetVaultBaseUrl() string
	GetToken() string

	GetApproleLoginPath() string
	GetApproleLogoutPath() string
	GetApproleRoleId() string
	GetApproleSecretId() string

	GetSecretsPath() string
	GetPathPrefix() string
	GetInsecureSkipVerify() bool

	GetLockTimeout() Duration
	GetLockPollingInterval() Duration
}

func NewStorage(config StorageConfigInterface) *Storage {
	s := new(Storage)
	s.config = config
	s.logger = config.GetLogger()
	s.client = client.NewClient(s.config.GetInsecureSkipVerify()).SetHostUrl(s.config.GetVaultBaseUrl())
	return s
}

// Storage is the main object passed to CertMagic that implements the "Storage" interface.
type Storage struct {
	config StorageConfigInterface

	// client is the API client making requests to Vault
	client *client.Client

	// approleResponse is the successful response from Vault after logging in using ApproleRoleId/ApproleSecretId
	approleResponse *successResponse

	// approleTokenExpiration the future date when the token expires
	approleTokenExpiration *time.Time

	// logger Zap sugared logger
	logger *zap.SugaredLogger
}

func (s *Storage) Store(_ context.Context, key string, value []byte) error {
	s.logger.Debugw("Store() at url", "url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)))

	secret := &certificateSecret{
		Certmagic: certMagicCertificateSecret{Data: value},
	}
	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Post(s.vaultDataPath(key), secret, result, errResponse)
	if err != nil {
		s.logger.Errorw(
			"[ERROR] Unable to store certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() {
		s.logger.Errorw(
			"[ERROR] Unable to store certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return errResponse.Error()
	}

	return nil
}

func (s *Storage) Load(_ context.Context, key string) ([]byte, error) {
	s.logger.Debugw("Load() from url", "url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)))

	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Get(s.vaultDataPath(key), result, errResponse)
	if err != nil {
		s.logger.Errorw(
			"[ERROR] Unable to load certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return nil, err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		s.logger.Errorw(
			"[ERROR] Unable to load certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
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
	s.logger.Debugw("Delete() at url", "url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultMetadataPath(key)))

	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Delete(s.vaultMetadataPath(key), result, errResponse)
	if err != nil {
		s.logger.Errorw(
			"[ERROR] Unable to delete certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		s.logger.Errorw(
			"[ERROR] Unable to delete certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
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
	s.logger.Debugw("Exists() at url", "url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)))

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
//   - When recursive==false, we ONLY include item that do NOT have a trailing slash
//   - When recursive==true, we include ALL items from the specified prefix that do NOT have a trailing slash
func (s *Storage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	s.logger.Debugw("List() at url", "operation", "list", "url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultMetadataPath(prefix)), "recursive", recursive)

	result := &listResponse{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).List(s.vaultMetadataPath(prefix), result, errResponse)
	if err != nil {
		s.logger.Errorw(
			"[ERROR] Unable to list certificates",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultMetadataPath(prefix)),
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
		path := entry
		if strings.HasSuffix(prefix, "/") {
			path = Sprintf("%s%s", prefix, entry)
		} else {
			//path = Sprintf("%s/%s", prefix, entry)
		}

		if !strings.HasSuffix(path, "/") {
			items = append(items, path)
		}

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
	s.logger.Debugw("Stat() at url", "url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)))

	// Get the secret
	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Get(s.vaultDataPath(key), result, errResponse)
	if err != nil {
		s.logger.Errorw(
			"[ERROR] Unable to stat certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return certmagic.KeyInfo{}, err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		s.logger.Errorw(
			"[ERROR] Unable to stat certificate",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
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
			s.logger.Errorw(
				"[ERROR] Unable to get lock",
				"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(lock)),
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
		case <-time.After(time.Duration(s.config.GetLockPollingInterval())):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Lock doesn't exist, create it now
	expiration := time.Now().Add(time.Duration(s.config.GetLockTimeout()))
	secret := &certificateSecret{
		Certmagic: certMagicCertificateSecret{Lock: (*Time)(&expiration)},
	}
	result := &response{}
	errResponse := &errorResponse{}
	resp, err := s.client.SetToken(s.getToken()).Post(s.vaultDataPath(lock), secret, result, errResponse)
	if err != nil {
		s.logger.Errorw(
			"[ERROR] Unable to create lock",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(lock)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() {
		s.logger.Errorw(
			"[ERROR] Unable to create lock",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
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
		s.logger.Errorw(
			"[ERROR] Unable to remove lock",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(lock)),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", resp.StatusCode(),
			"response_body", resp.String(),
		)
		return err
	}

	if resp.IsError() && resp.StatusCode() != http.StatusNotFound {
		s.logger.Errorw(
			"[ERROR] Unable to remove lock",
			"url", Sprintf("%s%s", s.config.GetVaultBaseUrl(), s.vaultDataPath(key)),
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

func (s *Storage) vaultDataPath(key string) string {
	return vaultCertMagicCertificateDataPathFormat.String(s.config.GetSecretsPath(), s.config.GetPathPrefix(), key)
}

func (s *Storage) vaultMetadataPath(key string) string {
	return vaultCertMagicCertificateMetadataPathFormat.String(s.config.GetSecretsPath(), s.config.GetPathPrefix(), key)
}

func (s *Storage) vaultErrorString(resp *errorResponse) string {
	if len(resp.Errors) > 0 {
		return resp.Error().Error()
	}

	return ""
}

// Interface guard
var _ certmagic.Storage = (*Storage)(nil)
