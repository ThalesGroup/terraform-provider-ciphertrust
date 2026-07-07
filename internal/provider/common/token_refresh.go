package common

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const (
	tokenRefreshBuffer = 60 * time.Second
	authTokenPath      = "api/v1/auth/tokens"
)

// TokenRefreshTransport is an http.RoundTripper middleware that proactively
// refreshes the CipherTrust Manager JWT before it expires.
type TokenRefreshTransport struct {
	Base   http.RoundTripper // the underlying real transport
	client *Client           // back-reference to access/update Token + RefreshToken
	mu     sync.Mutex        // guards token refresh to be goroutine-safe
}

// RoundTrip intercepts every HTTP request. For non-auth endpoints it checks
// whether the JWT is close to expiry and refreshes it before forwarding.
func (t *TokenRefreshTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Skip expiry check for the auth/tokens endpoint itself to avoid recursion.
	if !strings.Contains(req.URL.Path, authTokenPath) {
		t.mu.Lock()
		t.maybeRefresh(req)
		t.mu.Unlock()
	}
	return t.Base.RoundTrip(req)
}

// maybeRefresh checks if the current JWT is expiring within tokenRefreshBuffer
// and triggers a refresh if so. Called with t.mu held.
func (t *TokenRefreshTransport) maybeRefresh(req *http.Request) {
	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		return
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return
	}

	expiry, err := parseJWTExpiry(parts[1])
	if err != nil {
		// Can't parse expiry — log and let the request go through as-is.
		tflog.Debug(context.Background(), "token_refresh: could not parse JWT expiry: "+err.Error())
		return
	}

	if time.Until(expiry) > tokenRefreshBuffer {
		// Token is fresh enough — nothing to do.
		return
	}

	tflog.Debug(context.Background(), fmt.Sprintf(
		"token_refresh: JWT expires at %s (in %s), refreshing now",
		expiry.Format(time.RFC3339), time.Until(expiry).Round(time.Second),
	))

	t.doRefresh(req)
}

// doRefresh attempts to get a new JWT.
// Strategy 1: refresh_token grant (uses the stored refresh token).
// Strategy 2: password grant fallback (uses username/password credentials).
// On success the new token is stored on the client and the in-flight request's
// Authorization header is updated.
func (t *TokenRefreshTransport) doRefresh(req *http.Request) {
	// --- Strategy 1: refresh_token grant ---
	if t.client.CMRefreshToken != "" {
		newJWT, newRefresh, err := t.callAuthTokens(AuthStruct{
			GrantType:         "refresh_token",
			RefreshToken:      t.client.CMRefreshToken,
			RenewRefreshToken: true,
		})
		if err == nil {
			t.client.Token = newJWT
			if newRefresh != "" {
				t.client.CMRefreshToken = newRefresh
			}
			req.Header.Set("Authorization", "Bearer "+newJWT)
			tflog.Debug(context.Background(), "token_refresh: token refreshed via refresh_token grant")
			return
		}
		tflog.Debug(context.Background(), "token_refresh: refresh_token grant failed ("+err.Error()+"), falling back to password grant")
	}

	// --- Strategy 2: password grant fallback ---
	newJWT, newRefresh, err := t.callAuthTokens(t.client.AuthData)
	if err != nil {
		tflog.Debug(context.Background(), "token_refresh: password grant fallback also failed: "+err.Error())
		return
	}
	t.client.Token = newJWT
	if newRefresh != "" {
		t.client.CMRefreshToken = newRefresh
	}
	req.Header.Set("Authorization", "Bearer "+newJWT)
	tflog.Debug(context.Background(), "token_refresh: token refreshed via password grant fallback")
}

// callAuthTokens POSTs to the CM auth/tokens endpoint and returns the new JWT
// and refresh token. It uses c.client.HTTPClient.Do() directly (not doRequest)
// so that no Authorization header is added, and the path exclusion in RoundTrip
// prevents recursive refresh checks.
func (t *TokenRefreshTransport) callAuthTokens(body AuthStruct) (jwt string, refreshToken string, err error) {
	rb, err := json.Marshal(body)
	if err != nil {
		return "", "", fmt.Errorf("marshal auth body: %w", err)
	}

	myReq, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/%s", t.client.CipherTrustURL, authTokenPath),
		strings.NewReader(string(rb)),
	)
	if err != nil {
		return "", "", fmt.Errorf("build auth request: %w", err)
	}
	myReq.Header.Set("Content-Type", "application/json")

	resp, err := t.client.HTTPClient.Do(myReq)
	if err != nil {
		return "", "", fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("read auth response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", "", fmt.Errorf("auth returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var ar AuthResponse
	if err := json.Unmarshal(respBody, &ar); err != nil {
		return "", "", fmt.Errorf("unmarshal auth response: %w", err)
	}
	if ar.Token == "" {
		return "", "", fmt.Errorf("auth response contained empty JWT")
	}

	return ar.Token, ar.RefreshToken, nil
}

// parseJWTExpiry extracts the `exp` claim from a JWT without verifying
// the signature. Uses only stdlib (base64 + json). Returns the expiry time.
func parseJWTExpiry(tokenString string) (time.Time, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("base64 decode JWT payload: %w", err)
	}

	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("unmarshal JWT claims: %w", err)
	}
	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("JWT has no exp claim")
	}

	return time.Unix(claims.Exp, 0), nil
}
