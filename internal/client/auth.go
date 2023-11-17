package client

import (
	. "fmt"
	"github.com/dustin/go-humanize"
	"time"
)

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
func (c *Client) getToken() string {
	if c.token != "" {
		c.logger.Debug("Using static Vault token for auth")
		return c.token
	}

	if c.approleResponse != nil {
		if !c.approleTokenExpired() {
			c.logger.Debug("Using approle client token for auth")
			return c.approleResponse.Auth.ClientToken
		} else {
			c.logger.Warnw("Approle client token expired",
				"expired", humanize.Time(*c.approleTokenExpiration),
			)
		}
	}

	if err := c.login(); err != nil {
		return ""
	}

	c.logger.Debug("Using newly created approle token for auth")
	return c.approleResponse.Auth.ClientToken
}

func (c *Client) login() error {
	c.logger.Info("Logging in to vault using approle credentials")
	result := &successResponse{}
	errResponse := &ErrorResponse{}
	body := &approleLoginInput{RoleId: c.approleRoleId, SecretId: c.approleSecretId}
	response, err := c.ApproleLogin(c.approleLoginPath, body, result, errResponse)
	if err != nil {
		c.logger.Errorw(
			"[ERROR] during vault login using approle credentials",
			"url", Sprintf("%s%s", c.vaultBaseUrl, c.approleLoginPath),
			"error", err.Error(),
			"vault_errors", VaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return err
	}

	if response.IsError() {
		c.logger.Errorw(
			"[ERROR] during vault login using approle credentials",
			"url", Sprintf("%s%s", c.vaultBaseUrl, c.approleLoginPath),
			"vault_errors", VaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return errResponse.Error()
	}

	c.approleResponse = result
	expiration := time.Now().Add(time.Duration(result.Auth.LeaseDuration) * time.Second)
	c.approleTokenExpiration = &expiration

	return nil
}

func (c *Client) logout() error {
	// If we do not have a valid approleResponse, this is a noop
	if c.approleResponse == nil {
		return nil
	}

	body := &struct{}{}
	result := &successResponse{}
	errResponse := &ErrorResponse{}

	response, err := c.ApproleLogout(c.approleLogoutPath, body, result, errResponse)
	if err != nil {
		c.logger.Errorw(
			"[ERROR] during vault logout using approle credentials",
			"url", Sprintf("%s%s", c.vaultBaseUrl, c.approleLogoutPath),
			"error", err.Error(),
			"vault_errors", VaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return err
	}

	if response.IsError() {
		c.logger.Errorw(
			"[ERROR] during vault logout using approle credentials",
			"url", Sprintf("%s%s", c.vaultBaseUrl, c.approleLogoutPath),
			"vault_errors", VaultErrorString(errResponse),
			"response_code", response.StatusCode(),
			"response_body", response.String(),
		)
		return errResponse.Error()
	}

	c.approleResponse = nil
	c.approleTokenExpiration = nil

	return nil
}

func (c *Client) approleTokenExpired() bool {
	if c.approleResponse != nil && c.approleTokenExpiration != nil {
		return time.Now().After(*c.approleTokenExpiration)
	}

	return true
}
