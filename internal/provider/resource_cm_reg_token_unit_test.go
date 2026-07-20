// Copyright (c) Thales Group
// SPDX-License-Identifier: MIT

package provider

import (
	"encoding/json"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cm"
)

func TestUnit_CMRegTokenJSON_OmitUnconfiguredPointers(t *testing.T) {
	// Create a payload with only some values set
	var payload cm.CMRegTokenJSON
	caID := "test-ca-id"
	payload.CAID = &caID

	// Marshal payload to JSON
	bytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	// Unmarshal into a generic map to check keys
	var result map[string]interface{}
	if err := json.Unmarshal(bytes, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	// Assert ca_id is present and other optional fields are omitted
	if val, ok := result["ca_id"]; !ok || val != "test-ca-id" {
		t.Errorf("expected ca_id to be 'test-ca-id', got %v", val)
	}

	unconfiguredFields := []string{
		"max_clients",
		"cert_duration",
		"client_management_profile_id",
		"lifetime",
		"name_prefix",
		"labels",
	}

	for _, field := range unconfiguredFields {
		if _, ok := result[field]; ok {
			t.Errorf("expected optional unconfigured field %q to be omitted from JSON, but it was found in: %s", field, string(bytes))
		}
	}
}
