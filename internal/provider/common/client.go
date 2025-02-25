package common

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Default CipherTrust Manager URL
const CipherTrustURL string = "https://10.10.10.10"

// Client
type Client struct {
	CipherTrustURL string
	HTTPClient     *http.Client
	Token          string
	AuthData       AuthStruct
}

// Bootstrap Client for CipherTrust Manager
type CMClientBootstrap struct {
	CipherTrustURL string
	HTTPClient     *http.Client
}

// AuthStruct
type AuthStruct struct {
	Username   string `json:"username"`
	Password   string `json:"password"`
	AuthDomain string `json:"auth_domain"`
	Domain     string `json:"domain"`
}

// AuthResponse
type AuthResponse struct {
	Token string `json:"jwt"`
}

// Create new client for CM with auth details
// Usable for som bootstrap API calls
func NewCMClientBoot(ctx context.Context, uuid string, address *string) (*CMClientBootstrap, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> NewCMClientBoot]["+uuid+"]")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := CMClientBootstrap{
		HTTPClient: &http.Client{
			Timeout:   180 * time.Second,
			Transport: tr,
		},
		// Default CM URL
		CipherTrustURL: CipherTrustURL,
	}

	if address != nil {
		c.CipherTrustURL = *address
	}

	tflog.Trace(ctx, MSG_METHOD_END+" [client.go -> NewCMClientBoot]["+uuid+"]")
	return &c, nil
}

// Create New Client for CipherTrust Manager
func NewClient(ctx context.Context, uuid string, address, auth_domain, domain, username, password *string) (*Client, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> NewClient]["+uuid+"]")
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	c := Client{
		HTTPClient: &http.Client{
			Timeout:   180 * time.Second,
			Transport: tr,
		},
		// Default URL
		CipherTrustURL: CipherTrustURL,
	}

	if address != nil {
		c.CipherTrustURL = *address
	}

	// If username or password not provided, return empty client
	if username == nil || password == nil {
		return &c, nil
	}

	c.AuthData = AuthStruct{
		Username:   *username,
		Password:   *password,
		AuthDomain: *auth_domain,
		Domain:     *domain,
	}

	ar, err := c.SignIn(ctx, uuid)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> NewClient]["+uuid+"]")
		return nil, err
	}

	c.Token = ar.Token

	tflog.Trace(ctx, MSG_METHOD_END+" [client.go -> NewClient]["+uuid+"]")
	return &c, nil
}

func (c *Client) doRequest(ctx context.Context, uuid string, req *http.Request, jwt *string) ([]byte, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> doRequest]["+uuid+"]")
	token := c.Token

	if jwt != nil {
		token = *jwt
	}

	var bearer = "Bearer " + token
	req.Header.Add("Authorization", bearer)
	req.Header.Add("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequest]["+uuid+"]")
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequest]["+uuid+"]")
		return nil, err
	}

	if res.StatusCode == http.StatusOK ||
		res.StatusCode == http.StatusCreated ||
		res.StatusCode == http.StatusPartialContent ||
		res.StatusCode == http.StatusAccepted ||
		res.StatusCode == http.StatusNonAuthoritativeInfo ||
		res.StatusCode == http.StatusNoContent {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return body, err
	} else {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}
}

func (c *CMClientBootstrap) doRequestBootstrap(ctx context.Context, uuid string, req *http.Request) ([]byte, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[client.go -> doRequestBootstrap]["+uuid+"]")

	req.Header.Add("Content-Type", "application/json")

	res, err := c.HTTPClient.Do(req)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequestBootstrap]["+uuid+"]")
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [client.go -> doRequestBootstrap]["+uuid+"]")
		return nil, err
	}

	if res.StatusCode == http.StatusOK ||
		res.StatusCode == http.StatusCreated ||
		res.StatusCode == http.StatusPartialContent ||
		res.StatusCode == http.StatusAccepted ||
		res.StatusCode == http.StatusNonAuthoritativeInfo ||
		res.StatusCode == http.StatusNoContent {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return body, err
	} else {
		tflog.Trace(ctx, MSG_METHOD_END+"[client.go -> doRequest]["+uuid+"]")
		return nil, fmt.Errorf("status: %d, body: %s", res.StatusCode, body)
	}
}
