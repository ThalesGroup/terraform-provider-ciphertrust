package connections

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// sensitiveAttrsForResource returns a map of attribute name → Sensitive flag for
// all top-level StringAttributes in the given resource's schema.
func sensitiveAttrsForResource(t *testing.T, r resource.Resource) map[string]bool {
	t.Helper()
	schResp := &resource.SchemaResponse{}
	type schemaer interface {
		Schema(context.Context, resource.SchemaRequest, *resource.SchemaResponse)
	}
	s, ok := r.(schemaer)
	if !ok {
		t.Fatalf("resource does not implement Schema()")
	}
	s.Schema(context.Background(), resource.SchemaRequest{}, schResp)
	result := make(map[string]bool)
	for name, attr := range schResp.Schema.Attributes {
		if sa, ok := attr.(schema.StringAttribute); ok {
			result[name] = sa.Sensitive
		}
	}
	return result
}

// TestAWSConnectionSensitiveFields verifies that access_key_id and secret_access_key
// are marked Sensitive: true in the ciphertrust_aws_connection schema.
func TestAWSConnectionSensitiveFields(t *testing.T) {
	attrs := sensitiveAttrsForResource(t, NewResourceCCKMAWSConnection())
	for _, field := range []string{"access_key_id", "secret_access_key"} {
		sensitive, exists := attrs[field]
		if !exists {
			t.Errorf("ciphertrust_aws_connection: attribute %q not found in schema", field)
			continue
		}
		if !sensitive {
			t.Errorf("ciphertrust_aws_connection: attribute %q must have Sensitive: true to prevent credential exposure in state/plan output", field)
		}
	}
}

// TestAzureConnectionSensitiveFields verifies that client_secret is marked
// Sensitive: true in the ciphertrust_azure_connection schema.
func TestAzureConnectionSensitiveFields(t *testing.T) {
	attrs := sensitiveAttrsForResource(t, NewResourceAzureConnection())
	for _, field := range []string{"client_secret"} {
		sensitive, exists := attrs[field]
		if !exists {
			t.Errorf("ciphertrust_azure_connection: attribute %q not found in schema", field)
			continue
		}
		if !sensitive {
			t.Errorf("ciphertrust_azure_connection: attribute %q must have Sensitive: true to prevent credential exposure in state/plan output", field)
		}
	}
}

// TestOCIConnectionSensitiveFields verifies that key_file and key_file_pass_phrase
// are marked Sensitive: true in the ciphertrust_oci_connection schema.
func TestOCIConnectionSensitiveFields(t *testing.T) {
	attrs := sensitiveAttrsForResource(t, NewResourceCCKMOCIConnection())
	for _, field := range []string{"key_file", "key_file_pass_phrase"} {
		sensitive, exists := attrs[field]
		if !exists {
			t.Errorf("ciphertrust_oci_connection: attribute %q not found in schema", field)
			continue
		}
		if !sensitive {
			t.Errorf("ciphertrust_oci_connection: attribute %q must have Sensitive: true to prevent credential exposure in state/plan output", field)
		}
	}
}
