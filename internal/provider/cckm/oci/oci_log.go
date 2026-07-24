package cckm

import "encoding/json"

// redactOCIResponse returns a safe-to-log version of an OCI API response with sensitive fields replaced.
func redactOCIResponse(response string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		// If we cannot parse the response, return it as-is - a malformed response
		// is itself useful diagnostic information.
		return response
	}

	for _, field := range []string{
		"vault_id", "tenancy",
		// vault responses carry these at the top level (not nested in oci_params)
		"wrappingkey_id", "compartment_id", "freeform_tags", "defined_tags",
	} {
		if _, ok := data[field]; ok {
			data[field] = "redacted"
		}
	}

	if ociParams, ok := data["oci_params"].(map[string]interface{}); ok {
		for _, field := range []string{
			"compartment_id", "current_key_version", "key_id",
			"freeform_tags", "defined_tags",
		} {
			if _, ok := ociParams[field]; ok {
				ociParams[field] = "redacted"
			}
		}
	}

	if ociVersionParams, ok := data["oci_key_version_params"].(map[string]interface{}); ok {
		for _, field := range []string{
			"compartment_id", "key_id", "vault_id", "version_id",
			"freeform_tags", "defined_tags",
		} {
			if _, ok := ociVersionParams[field]; ok {
				ociVersionParams[field] = "redacted"
			}
		}
	}

	b, err := json.Marshal(data)
	if err != nil {
		return response
	}
	return string(b)
}
