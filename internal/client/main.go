package client

import (
	"crypto/tls"
	"gopkg.in/resty.v1"
	"net"
	"net/http"
	"time"
)

func NewClient(insecureSkipVerify bool) *Client {
	c := new(Client)
	c.resty = resty.New()
	c.resty.SetHeaders(map[string]string{
		"Accept":       "application/json",
		"Content-Type": "application/json",
	})
	c.resty.SetTransport(&http.Transport{
		DialContext: (&net.Dialer{
			KeepAlive: 3 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	})
	return c
}

type Client struct {
	resty *resty.Client
}

func (c *Client) SetHostUrl(url string) *Client {
	c.resty.SetHostURL(url)
	return c
}

func (c *Client) Get(token, path string, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeader("X-Vault-Token", token).SetResult(result).SetError(error).Get(path)
}

func (c *Client) List(token, path string, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeader("X-Vault-Token", token).SetResult(result).SetError(error).Execute("LIST", path)
}

func (c *Client) Put(token, path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeader("X-Vault-Token", token).SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Put(path)
}

func (c *Client) Post(token, path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeader("X-Vault-Token", token).SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Post(path)
}

func (c *Client) ApproleLogin(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetBody(body).SetResult(result).SetError(error).Post(path)
}

func (c *Client) ApproleLogout(token, path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeader("X-Vault-Token", token).SetBody(body).SetResult(result).SetError(error).Post(path)
}

func (c *Client) Delete(token, path string, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeader("X-Vault-Token", token).SetResult(result).SetError(error).Delete(path)
}

func (c *Client) Merge(token, path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeaders(map[string]string{
		"Content-Type":  "application/merge-patch+json",
		"X-Vault-Token": token,
	}).SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Patch(path)
}
