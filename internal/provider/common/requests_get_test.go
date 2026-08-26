package common

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestGetAllWithTotal_PaginationTruncation(t *testing.T) {
	tests := []struct {
		name          string
		responseBody  string
		wantResources string
		wantTotal     int64
		wantErr       bool
	}{
		{
			name:          "Valid paginated response with truncation",
			responseBody:  `{"resources":[{"id":"u1"},{"id":"u2"}],"total":5}`,
			wantResources: `[{"id":"u1"},{"id":"u2"}]`,
			wantTotal:     5,
		},
		{
			name:          "Valid unpaginated response (missing total)",
			responseBody:  `{"resources":[{"id":"u1"}]}`,
			wantResources: `[{"id":"u1"}]`,
			wantTotal:     0,
		},
		{
			name:          "Empty resources response",
			responseBody:  `{"resources":[],"total":0}`,
			wantResources: `[]`,
			wantTotal:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, tt.responseBody)
			}))
			defer srv.Close()

			client := &Client{
				CipherTrustURL: srv.URL,
				HTTPClient:     srv.Client(),
				Log:            hclog.NewNullLogger(),
			}

			resources, total, err := client.GetAllWithTotal(context.Background(), "test-uuid", "v1/users")
			if (err != nil) != tt.wantErr {
				t.Fatalf("unexpected error state: %v", err)
			}
			if err == nil {
				if resources != tt.wantResources {
					t.Errorf("expected resources %q, got %q", tt.wantResources, resources)
				}
				if total != tt.wantTotal {
					t.Errorf("expected total %d, got %d", tt.wantTotal, total)
				}
			}
		})
	}
}

// TestGetAllPagedWithLimit covers the TFIN-584 fix: CTE list data sources
// can now bound their result set via caller-supplied skip/limit instead of
// always retrieving everything. This serves a small fixed-size backing list
// (5 items) and exercises: limit unset (fetch-everything, backward
// compatible with pre-fix behavior), limit smaller than the total (result
// trimmed to exactly limit, total still reported so callers can warn), skip
// offsetting into the list, and limit larger than what remains.
func TestGetAllPagedWithLimit(t *testing.T) {
	items := make([]map[string]string, 5)
	for i := range items {
		items[i] = map[string]string{"id": fmt.Sprintf("item%d", i)}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		skip, _ := strconv.Atoi(q.Get("skip"))
		limit, _ := strconv.Atoi(q.Get("limit"))
		if skip > len(items) {
			skip = len(items)
		}
		end := skip + limit
		if end > len(items) {
			end = len(items)
		}
		page := items[skip:end]
		body, _ := json.Marshal(map[string]interface{}{
			"resources": page,
			"total":     len(items),
		})
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(body); err != nil {
			t.Errorf("failed to write response body: %v", err)
		}
	}))
	defer srv.Close()

	client := &Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Log:            hclog.NewNullLogger(),
	}

	tests := []struct {
		name      string
		skip      int64
		limit     int64
		wantCount int
		wantTotal int64
	}{
		{name: "limit unset fetches everything", skip: 0, limit: 0, wantCount: 5, wantTotal: 5},
		{name: "limit smaller than total trims result", skip: 0, limit: 2, wantCount: 2, wantTotal: 5},
		{name: "skip offsets into the list", skip: 3, limit: 0, wantCount: 2, wantTotal: 5},
		{name: "limit larger than remaining returns all remaining", skip: 0, limit: 10, wantCount: 5, wantTotal: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonStr, total, err := client.GetAllPagedWithLimit(context.Background(), "test-uuid", "v1/cte/list", tt.skip, tt.limit)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var got []map[string]string
			if err := json.Unmarshal([]byte(jsonStr), &got); err != nil {
				t.Fatalf("failed to unmarshal result: %v", err)
			}
			if len(got) != tt.wantCount {
				t.Errorf("expected %d resources, got %d (%s)", tt.wantCount, len(got), jsonStr)
			}
			if total != tt.wantTotal {
				t.Errorf("expected total %d, got %d", tt.wantTotal, total)
			}
		})
	}
}
