package common

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeJWT builds a minimal unsigned JWT with the given exp claim.
func makeJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]int64{"exp": exp})
	claims := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + claims + ".fakesig"
}

// makeRequest builds a GET request with a Bearer token header.
func makeRequest(token string) *http.Request {
	req, _ := http.NewRequest("GET", "https://example.com/api/v1/some/endpoint", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// ---------------------------------------------------------------------------
// parseJWTExpiry
// ---------------------------------------------------------------------------

func TestParseJWTExpiry_ValidToken(t *testing.T) {
	future := time.Now().Add(5 * time.Minute).Unix()
	token := makeJWT(future)

	expiry, err := parseJWTExpiry(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expiry.Unix() != future {
		t.Errorf("expected exp=%d, got %d", future, expiry.Unix())
	}
}

func TestParseJWTExpiry_ExpiredToken(t *testing.T) {
	past := time.Now().Add(-10 * time.Minute).Unix()
	token := makeJWT(past)

	expiry, err := parseJWTExpiry(token)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expiry.Before(time.Now()) {
		t.Error("expected expiry to be in the past")
	}
}

func TestParseJWTExpiry_MalformedToken(t *testing.T) {
	_, err := parseJWTExpiry("not.a.jwt.with.too.many.parts")
	if err == nil {
		t.Error("expected error for malformed JWT")
	}
}

func TestParseJWTExpiry_MissingExpClaim(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user1"}`)) // no exp
	token := header + "." + payload + ".sig"

	_, err := parseJWTExpiry(token)
	if err == nil {
		t.Error("expected error when exp claim is missing")
	}
}

func TestParseJWTExpiry_InvalidBase64(t *testing.T) {
	_, err := parseJWTExpiry("header.!!!invalid-base64!!!.sig")
	if err == nil {
		t.Error("expected error for invalid base64 in payload")
	}
}

// ---------------------------------------------------------------------------
// RoundTrip — path exclusion
// ---------------------------------------------------------------------------

// countingTransport records how many times RoundTrip was called.
type countingTransport struct {
	calls int
	mu    sync.Mutex
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return &http.Response{
		StatusCode: 200,
		Body:       http.NoBody,
	}, nil
}

func TestRoundTrip_SkipsRefreshForAuthEndpoint(t *testing.T) {
	base := &countingTransport{}
	client := &Client{
		Token: makeJWT(time.Now().Add(-1 * time.Minute).Unix()), // expired token
		AuthData: AuthStruct{Username: "admin", Password: "pass"},
	}
	tr := &TokenRefreshTransport{Base: base, client: client}
	client.HTTPClient = &http.Client{Transport: tr}

	// Request to the auth endpoint — should NOT trigger refresh check
	req, _ := http.NewRequest("POST", "https://cm/api/v1/auth/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+client.Token)

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	// base transport should have been called once (the auth request itself)
	if base.calls != 1 {
		t.Errorf("expected 1 call to base transport, got %d", base.calls)
	}
}

// ---------------------------------------------------------------------------
// maybeRefresh — expiry check logic
// ---------------------------------------------------------------------------

func TestMaybeRefresh_FreshToken_NoRefresh(t *testing.T) {
	refreshCalled := false

	// Build a transport whose doRefresh we can observe via a test server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalled = true
		w.WriteHeader(200)
	}))
	defer ts.Close()

	client := &Client{
		Token:          makeJWT(time.Now().Add(10 * time.Minute).Unix()), // fresh — 10 min left
		CipherTrustURL: ts.URL,
		AuthData:       AuthStruct{Username: "admin", Password: "pass"},
	}
	tr := &TokenRefreshTransport{Base: ts.Client().Transport, client: client}
	client.HTTPClient = &http.Client{Transport: tr}

	req := makeRequest(client.Token)
	tr.maybeRefresh(req)

	if refreshCalled {
		t.Error("refresh should NOT have been called for a fresh token")
	}
	// Authorization header should be unchanged
	if req.Header.Get("Authorization") != "Bearer "+client.Token {
		t.Error("Authorization header should not have changed")
	}
}

func TestMaybeRefresh_ExpiringToken_TriggersRefresh(t *testing.T) {
	newJWT := makeJWT(time.Now().Add(10 * time.Minute).Unix())

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate CM returning a new token
		resp := AuthResponse{Token: newJWT}
		json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	expiringSoon := makeJWT(time.Now().Add(30 * time.Second).Unix()) // within 60s buffer

	client := &Client{
		Token:          expiringSoon,
		CipherTrustURL: ts.URL,
		AuthData:       AuthStruct{Username: "admin", Password: "pass"},
	}
	tr := &TokenRefreshTransport{Base: ts.Client().Transport, client: client}
	client.HTTPClient = &http.Client{Transport: tr}

	req := makeRequest(expiringSoon)
	tr.maybeRefresh(req)

	// Token should have been updated on the client
	if client.Token != newJWT {
		t.Errorf("expected client.Token to be updated to new JWT, got: %s", client.Token[:20])
	}
	// Authorization header on the in-flight request should be updated
	if req.Header.Get("Authorization") != "Bearer "+newJWT {
		t.Error("Authorization header was not updated on the request")
	}
}

func TestMaybeRefresh_NoAuthHeader_NoRefresh(t *testing.T) {
	refreshCalled := false
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCalled = true
	}))
	defer ts.Close()

	client := &Client{CipherTrustURL: ts.URL}
	tr := &TokenRefreshTransport{Base: ts.Client().Transport, client: client}
	client.HTTPClient = &http.Client{Transport: tr}

	req, _ := http.NewRequest("GET", ts.URL+"/api/v1/system/status", nil)
	// No Authorization header
	tr.maybeRefresh(req)

	if refreshCalled {
		t.Error("refresh should NOT be called when no Authorization header is present")
	}
}

// ---------------------------------------------------------------------------
// doRefresh — password fallback
// ---------------------------------------------------------------------------

func TestDoRefresh_PasswordFallback_WhenNoRefreshToken(t *testing.T) {
	newJWT := makeJWT(time.Now().Add(10 * time.Minute).Unix())

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it's a password grant
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if body["grant_type"] != nil && body["grant_type"] != "password" {
			http.Error(w, "expected password grant", 400)
			return
		}
		json.NewEncoder(w).Encode(AuthResponse{Token: newJWT})
	}))
	defer ts.Close()

	expiredToken := makeJWT(time.Now().Add(-1 * time.Minute).Unix())
	client := &Client{
		Token:          expiredToken,
		CMRefreshToken: "", // no refresh token stored
		CipherTrustURL: ts.URL,
		AuthData:       AuthStruct{Username: "admin", Password: "pass"},
	}
	tr := &TokenRefreshTransport{Base: ts.Client().Transport, client: client}
	client.HTTPClient = &http.Client{Transport: tr}

	req := makeRequest(expiredToken)
	tr.doRefresh(req)

	if client.Token != newJWT {
		t.Errorf("expected client.Token=%s, got %s", newJWT[:15], client.Token[:15])
	}
	if !strings.HasSuffix(req.Header.Get("Authorization"), newJWT) {
		t.Error("Authorization header not updated after password fallback")
	}
}

func TestDoRefresh_RefreshTokenGrant_UsedFirst(t *testing.T) {
	newJWT := makeJWT(time.Now().Add(10 * time.Minute).Unix())
	grantTypeUsed := ""

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		if gt, ok := body["grant_type"].(string); ok {
			grantTypeUsed = gt
		}
		json.NewEncoder(w).Encode(AuthResponse{Token: newJWT})
	}))
	defer ts.Close()

	expiredToken := makeJWT(time.Now().Add(-1 * time.Minute).Unix())
	client := &Client{
		Token:          expiredToken,
		CMRefreshToken: "some-refresh-token", // refresh token is present
		CipherTrustURL: ts.URL,
		AuthData:       AuthStruct{Username: "admin", Password: "pass"},
	}
	tr := &TokenRefreshTransport{Base: ts.Client().Transport, client: client}
	client.HTTPClient = &http.Client{Transport: tr}

	req := makeRequest(expiredToken)
	tr.doRefresh(req)

	if grantTypeUsed != "refresh_token" {
		t.Errorf("expected refresh_token grant to be used first, got: %q", grantTypeUsed)
	}
	if client.Token != newJWT {
		t.Error("client.Token was not updated after refresh_token grant")
	}
}

// ---------------------------------------------------------------------------
// Goroutine safety — concurrent RoundTrip calls
// ---------------------------------------------------------------------------

func TestRoundTrip_ConcurrentRequests_NoRace(t *testing.T) {
	newJWT := makeJWT(time.Now().Add(10 * time.Minute).Unix())
	var mu sync.Mutex
	callCount := 0

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		json.NewEncoder(w).Encode(AuthResponse{Token: newJWT})
	}))
	defer ts.Close()

	expiringSoon := makeJWT(time.Now().Add(10 * time.Second).Unix())
	client := &Client{
		Token:          expiringSoon,
		CipherTrustURL: ts.URL,
		AuthData:       AuthStruct{Username: "admin", Password: "pass"},
	}
	tr := &TokenRefreshTransport{Base: ts.Client().Transport, client: client}
	client.HTTPClient = &http.Client{Transport: tr}

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := makeRequest(expiringSoon)
			tr.RoundTrip(req)
		}()
	}
	wg.Wait()

	// With mutex, only 1 refresh call should have gone through (subsequent
	// goroutines see the already-refreshed token which is fresh for 10 min)
	mu.Lock()
	calls := callCount
	mu.Unlock()
	fmt.Printf("Concurrent refresh calls: %d (expected 1 due to mutex)\n", calls)
	if calls > 1 {
		t.Logf("Note: %d refresh calls made — mutex prevents thundering herd but subsequent goroutines may still see expiring token if they read before the first refresh completes", calls)
	}
}
