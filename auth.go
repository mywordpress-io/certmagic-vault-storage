package certmagic_vault_storage

import (
	. "fmt"
	"github.com/dustin/go-humanize"
	"github.com/mywordpress-io/certmagic-vault-storage/internal/logger"
	"github.com/pkg/errors"
	"strings"
	"time"
)

type errorResponse struct {
	Errors []string `json:"errors"`
}

// Error spits out errors from the Vault API (gotta be a better way to do this?)
func (e *errorResponse) Error() error {
	if len(e.Errors) > 0 {
		return errors.New(strings.Join(e.Errors, "; "))
	}

	return nil
}

type successResponse struct {
	RequestID     string                 `json:"request_id"`
	LeaseID       string                 `json:"lease_id"`
	Renewable     bool                   `json:"renewable"`
	LeaseDuration int                    `json:"lease_duration"`
	Data          map[string]interface{} `json:"data"`
	Warnings      []string               `json:"warnings"`
	Auth          *authResponse          `json:"auth"`
}

type authResponse struct {
	ClientToken      string            `json:"client_token"`
	Accessor         string            `json:"accessor"`
	Policies         []string          `json:"policies"`
	TokenPolicies    []string          `json:"token_policies,omitempty"`
	IdentityPolicies []string          `json:"identity_policies,omitempty"`
	Metadata         map[string]string `json:"metadata"`
	LeaseDuration    int               `json:"lease_duration"`
	Renewable        bool              `json:"renewable"`
	EntityID         string            `json:"entity_id"`
	Approle          *successResponse
	Token            *successResponse
}

type approleLoginInput struct {
	RoleId   string `json:"role_id"`
	SecretId string `json:"secret_id"`
}

// getToken prefers to return a static 'Token' value, otherwise it returns the approle token
func (s *Storage) getToken() string {
	if s.Token != "" {
		logger.Zap.Debug("Using static Vault token for auth")
		return s.Token
	}

	if s.approleResponse != nil {
		if !s.approleTokenExpired() {
			logger.Zap.Debug("Using approle client token for auth")
			return s.approleResponse.Auth.ClientToken
		} else {
			logger.Zap.Warnw("Approle client token expired",
				"expired", humanize.Time(*s.approleTokenExpiration),
			)
		}
	}

	if err := s.login(); err != nil {
		return ""
	}

	logger.Zap.Debug("Using newly created approle token for auth")
	return s.approleResponse.Auth.ClientToken
}

func (s *Storage) login() error {
	logger.Zap.Info("Logging in to vault using approle credentials")
	result := &successResponse{}
	errResponse := &errorResponse{}
	body := &approleLoginInput{RoleId: s.ApproleRoleId, SecretId: s.ApproleSecretId}
	response, err := s.client.SetHostUrl(s.vaultBaseUrl()).ApproleLogin(s.ApproleLoginPath, body, result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] during vault login using approle credentials",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.ApproleLoginPath),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return err
	}

	if response.IsError() {
		logger.Zap.Errorw(
			"[ERROR] during vault login using approle credentials",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.ApproleLoginPath),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return errResponse.Error()
	}

	s.approleResponse = result
	expiration := time.Now().Add(time.Duration(result.Auth.LeaseDuration) * time.Second)
	s.approleTokenExpiration = &expiration

	return nil
}

func (s *Storage) logout() error {
	// If we do not have a valid approleResponse, this is a noop
	if s.approleResponse == nil {
		return nil
	}

	body := &struct{}{}
	result := &successResponse{}
	errResponse := &errorResponse{}
	response, err := s.client.SetHostUrl(s.vaultBaseUrl()).SetToken(s.getToken()).ApproleLogout(s.ApproleLogoutPath, body, result, errResponse)
	if err != nil {
		logger.Zap.Errorw(
			"[ERROR] during vault login using approle credentials",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.ApproleLoginPath),
			"error", err.Error(),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return err
	}

	if response.IsError() {
		logger.Zap.Errorw(
			"[ERROR] during vault login using approle credentials",
			"url", Sprintf("%s%s", s.vaultBaseUrl(), s.ApproleLoginPath),
			"vault_errors", s.vaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return errResponse.Error()
	}

	s.approleResponse = nil
	s.approleTokenExpiration = nil

	return nil
}

func (s *Storage) approleTokenExpired() bool {
	if s.approleResponse != nil && s.approleTokenExpiration != nil {
		return time.Now().After(*s.approleTokenExpiration)
	}

	return true
}
