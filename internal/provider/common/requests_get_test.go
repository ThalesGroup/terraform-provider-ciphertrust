// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package common

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestGetAllWithTotal_PaginationTruncation(t *testing.T) {
	tests := []struct {
		name         string
		responseBody string
		wantResources string
		wantTotal    int64
		wantErr      bool
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
