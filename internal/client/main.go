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

func (c *Client) SetToken(token string) *Client {
	c.resty.SetHeader("X-Vault-Token", token)
	return c
}

func (c *Client) SetHostUrl(url string) *Client {
	c.resty.SetHostURL(url)
	return c
}

func (c *Client) Get(path string, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetResult(result).SetError(error).Get(path)
}

func (c *Client) List(path string, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetResult(result).SetError(error).Execute("LIST", path)
}

func (c *Client) Put(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Put(path)
}

func (c *Client) Post(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Post(path)
}

func (c *Client) ApproleLogin(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetBody(body).SetResult(result).SetError(error).Post(path)
}

func (c *Client) ApproleLogout(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetBody(body).SetResult(result).SetError(error).Post(path)
}

func (c *Client) Delete(path string, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetResult(result).SetError(error).Delete(path)
}

func (c *Client) Merge(path string, body, result, error interface{}) (*resty.Response, error) {
	return c.resty.R().SetHeader("Content-Type", "application/merge-patch+json").SetBody(map[string]interface{}{"data": body}).SetResult(result).SetError(error).Patch(path)
}
