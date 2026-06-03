package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// algorithmValidators extracts the validators declared on the "algorithm"
// attribute of the ciphertrust_cm_key resource schema.
func algorithmValidators(t *testing.T) []validator.String {
	t.Helper()

	r := NewResourceCMKey()
	schemaResp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, schemaResp)

	attr, ok := schemaResp.Schema.Attributes["algorithm"]
	if !ok {
		t.Fatal("ciphertrust_cm_key schema is missing the \"algorithm\" attribute")
	}

	strAttr, ok := attr.(schema.StringAttribute)
	if !ok {
		t.Fatalf("\"algorithm\" attribute is %T, expected schema.StringAttribute", attr)
	}

	return strAttr.Validators
}

// validateAlgorithm runs every validator declared on the "algorithm" attribute
// against the supplied value and reports whether any of them raised an error.
func validateAlgorithm(t *testing.T, value string) bool {
	t.Helper()

	validators := algorithmValidators(t)
	if len(validators) == 0 {
		t.Fatal("expected at least one validator on the \"algorithm\" attribute")
	}

	for _, v := range validators {
		req := validator.StringRequest{ConfigValue: types.StringValue(value)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			return true
		}
	}

	return false
}

// TestResourceCMKeyAlgorithmValidator verifies that the algorithm attribute
// accepts the new "ml-dsa" post-quantum value (TFIN-285) alongside the existing
// supported algorithms, and rejects unsupported values.
func TestResourceCMKeyAlgorithmValidator(t *testing.T) {
	validCases := []string{
		"aes",
		"rsa",
		"ec",
		"hmac-sha1",
		"hmac-sha256",
		"hmac-sha384",
		"hmac-sha512",
		"ml-dsa", // TFIN-285: post-quantum Module-Lattice Digital Signature Algorithm
	}

	for _, algo := range validCases {
		t.Run("valid/"+algo, func(t *testing.T) {
			if validateAlgorithm(t, algo) {
				t.Errorf("algorithm %q was rejected by the validator, expected it to be accepted", algo)
			}
		})
	}

	invalidCases := []string{
		"ml-dsax",
		"mldsa",
		"",
	}

	for _, algo := range invalidCases {
		t.Run("invalid/"+algo, func(t *testing.T) {
			if !validateAlgorithm(t, algo) {
				t.Errorf("algorithm %q was accepted by the validator, expected it to be rejected", algo)
			}
		})
	}
}
