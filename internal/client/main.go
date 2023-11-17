package client

import (
	"crypto/tls"
	"go.uber.org/zap"
	"gopkg.in/resty.v1"
	"net"
	"net/http"
	"time"
)

func NewClient(logger *zap.SugaredLogger, vaultBaseUrl string, insecureSkipVerify bool, token string,
	approleLoginPath string, approleLogoutPath string, approleRoleId string, approleSecretId string) *Client {
	c := new(Client)
	c.logger = logger
	c.vaultBaseUrl = vaultBaseUrl
	c.token = token
	c.approleLoginPath = approleLoginPath
	c.approleLogoutPath = approleLogoutPath
	c.approleRoleId = approleRoleId
	c.approleSecretId = approleSecretId
	c.resty = resty.New()
	c.resty.SetTransport(&http.Transport{
		DialContext: (&net.Dialer{
			KeepAlive: 3 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	})
	c.resty.SetHostURL(vaultBaseUrl)
	return c
}

type Client struct {
	resty *resty.Client
	logger *zap.SugaredLogger

	vaultBaseUrl string

	token string

	approleLoginPath string
	approleLogoutPath string
	approleRoleId string
	approleSecretId string

	// approleResponse is the successful response from Vault after logging in using ApproleRoleId/ApproleSecretId
	approleResponse *successResponse

	// approleTokenExpiration the future date when the token expires
	approleTokenExpiration *time.Time
}

func (c *Client) request() (*resty.Request) {
	return c.resty.R().
		SetHeaders(map[string]string{
			"Accept":        "application/json",
			"Content-Type":  "application/json",
			"X-Vault-Token": c.getToken(),
		})
}

func (c *Client) Get(path string, result, error interface{}) (*resty.Response, error) {
	return c.request().SetResult(result).SetError(error).Get(path)
}

func (c *Client) List(path string, result, error interface{}) (*resty.Response, error) {
	return c.request().SetResult(result).SetError(error).Execute("LIST", path)
}

func (c *Client) Put(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.request().SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Put(path)
}

func (c *Client) Post(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.request().SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Post(path)
}

func (c *Client) ApproleLogin(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.request().SetBody(body).SetResult(result).SetError(error).Post(path)
}

func (c *Client) ApproleLogout(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.request().SetBody(body).SetResult(result).SetError(error).Post(path)
}

func (c *Client) Delete(path string, result, error interface{}) (*resty.Response, error) {
	return c.request().SetResult(result).SetError(error).Delete(path)
}

func (c *Client) Merge(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.request().SetHeader("Content-Type", "application/merge-patch+json").SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Patch(path)
}
