package common

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

/*
SignIn - Get a new token for user.
This will take username and password as arguments and send them to CipherTrust Manager to acquire token
*/
func (c *Client) SignIn(ctx context.Context, uuid string) (*AuthResponse, error) {
	tflog.Trace(ctx, MSG_METHOD_START+"[auth.go -> SignIn]["+uuid+"]")
	if c.AuthData.Username == "" || c.AuthData.Password == "" {
		tflog.Debug(ctx, ERR_METHOD_END+"Missing Username or Password for CipherTrust Manager Login [auth.go -> SignIn]["+uuid+"]")
		return nil, fmt.Errorf("%s", ERR_SIGNIN_MISSING_ARGS)
	}
	rb, err := json.Marshal(c.AuthData)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [auth.go -> SignIn]["+uuid+"]")
		return nil, err
	}

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/%s", c.CipherTrustURL, URL_SIGNIN), strings.NewReader(string(rb)))

	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [auth.go -> SignIn]["+uuid+"]")
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	body, err := c.doRequest(ctx, uuid, req, nil)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [auth.go -> SignIn]["+uuid+"]")
		return nil, err
	}

	ar := AuthResponse{}
	err = json.Unmarshal(body, &ar)
	if err != nil {
		tflog.Debug(ctx, ERR_METHOD_END+err.Error()+" [auth.go -> SignIn]["+uuid+"]")
		return nil, err
	}

	tflog.Trace(ctx, MSG_METHOD_END+"[auth.go -> SignIn]["+uuid+"]")
	return &ar, nil
}
