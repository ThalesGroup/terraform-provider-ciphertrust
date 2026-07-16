package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
)

// newTestKeysServer starts an httptest server that emulates CipherTrust
// Manager's GET /vault/keys2/ pagination behavior: it honors the "limit" and
// "skip" query params and serves slices of a fixed total number of keys,
// tracking how many requests were made.
func newTestKeysServer(t *testing.T, total int) (*httptest.Server, *int) {
	t.Helper()
	requestCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		skip, _ := strconv.Atoi(r.URL.Query().Get("skip"))
		if limit <= 0 {
			limit = total
		}

		var page []map[string]any
		for i := skip; i < skip+limit && i < total; i++ {
			page = append(page, map[string]any{
				"id":   fmt.Sprintf("key-%d", i),
				"name": fmt.Sprintf("test-key-%d", i),
			})
		}

		body, err := json.Marshal(map[string]any{
			"total":     total,
			"resources": page,
		})
		if err != nil {
			t.Fatalf("failed to marshal test response: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	return srv, &requestCount
}

func newTestClient(serverURL string) *common.Client {
	return &common.Client{
		CipherTrustURL: serverURL,
		HTTPClient:     http.DefaultClient,
		Log:            hclog.NewNullLogger(),
	}
}

// Test_CM_FetchAllKeys_SinglePage verifies that a key count smaller than the
// page size is returned in exactly one request.
func Test_CM_FetchAllKeys_SinglePage(t *testing.T) {
	srv, requests := newTestKeysServer(t, 5)
	defer srv.Close()

	client := newTestClient(srv.URL)
	keys, err := fetchAllKeys(context.Background(), client, "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(keys))
	}
	if *requests != 1 {
		t.Fatalf("expected 1 request for a single short page, got %d", *requests)
	}
}

// Test_CM_FetchAllKeys_MultiplePages is the regression test for the
// pagination bug: previously a single unfiltered GetAll() call only ever
// returned the server's first page (CipherTrust Manager's own default page
// size is 10), silently dropping the rest. This creates 25 keys -- more than
// two pages -- and verifies fetchAllKeys accumulates every one of them across
// multiple limit/skip requests instead of stopping after the first page.
func Test_CM_FetchAllKeys_MultiplePages(t *testing.T) {
	srv, requests := newTestKeysServer(t, 25)
	defer srv.Close()

	client := newTestClient(srv.URL)
	keys, err := fetchAllKeys(context.Background(), client, "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 25 {
		t.Fatalf("expected 25 keys across all pages, got %d", len(keys))
	}
	if *requests != 3 {
		t.Fatalf("expected 3 requests (10 + 10 + 5) with page size %d, got %d", keysListPageSize, *requests)
	}

	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		id, _ := k["id"].(string)
		if id == "" {
			t.Fatalf("key missing id: %+v", k)
		}
		seen[id] = true
	}
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("key-%d", i)
		if !seen[id] {
			t.Errorf("missing %s in accumulated results", id)
		}
	}
}

// Test_CM_FetchAllKeys_ExactMultipleOfPageSize verifies the boundary case
// where the total key count is an exact multiple of the page size (an empty
// trailing page signals completion instead of a short one).
func Test_CM_FetchAllKeys_ExactMultipleOfPageSize(t *testing.T) {
	srv, requests := newTestKeysServer(t, 20)
	defer srv.Close()

	client := newTestClient(srv.URL)
	keys, err := fetchAllKeys(context.Background(), client, "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 20 {
		t.Fatalf("expected 20 keys, got %d", len(keys))
	}
	if *requests != 3 {
		t.Fatalf("expected 3 requests (10 + 10 + empty trailing page), got %d", *requests)
	}
}

// Test_CM_FetchAllKeys_Empty verifies a CM with zero keys returns an empty,
// non-error result after a single request.
func Test_CM_FetchAllKeys_Empty(t *testing.T) {
	srv, requests := newTestKeysServer(t, 0)
	defer srv.Close()

	client := newTestClient(srv.URL)
	keys, err := fetchAllKeys(context.Background(), client, "test-uuid")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(keys))
	}
	if *requests != 1 {
		t.Fatalf("expected 1 request, got %d", *requests)
	}
}

// Test_CM_FetchAllKeys_ServerError verifies an API error on any page is
// propagated rather than silently truncating results.
func Test_CM_FetchAllKeys_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer srv.Close()

	client := newTestClient(srv.URL)
	_, err := fetchAllKeys(context.Background(), client, "test-uuid")
	if err == nil {
		t.Fatal("expected an error from a failing server, got nil")
	}
}
