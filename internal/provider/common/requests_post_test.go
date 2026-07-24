// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package common

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
)

func TestPostData_IdentifierValidation(t *testing.T) {
	tests := []struct {
		name         string
		responseBody string
		targetID     string
		wantErr      string
		wantVal      string
	}{
		{
			name:         "Valid response with expected ID",
			responseBody: `{"id":"k1","name":"key"}`,
			targetID:     "id",
			wantVal:      "k1",
		},
		{
			name:         "Missing ID field",
			responseBody: `{"name":"key"}`,
			targetID:     "id",
			wantErr:      "is missing from the API response payload",
		},
		{
			name:         "Empty ID value",
			responseBody: `{"id":"","name":"key"}`,
			targetID:     "id",
			wantErr:      "has an empty string value",
		},
		{
			name:         "Renamed identifier field",
			responseBody: `{"resource_id":"k1"}`,
			targetID:     "id",
			wantErr:      "is missing from the API response payload",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusCreated)
				fmt.Fprint(w, tt.responseBody)
			}))
			defer srv.Close()

			client := &Client{
				CipherTrustURL: srv.URL,
				HTTPClient:     srv.Client(),
				Log:            hclog.NewNullLogger(),
			}

			val, err := client.PostData(context.Background(), "test-uuid", "v1/keys", []byte(`{}`), tt.targetID)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if val != tt.wantVal {
					t.Errorf("expected value %q, got %q", tt.wantVal, val)
				}
			}
		})
	}
}
