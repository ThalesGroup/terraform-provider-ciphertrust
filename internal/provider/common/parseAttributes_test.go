package common

import (
	"context"
	"testing"
)

// Test_CM_ParseArray_MissingFieldIsEmptyNotNull verifies that ParseArray treats a
// field CM omits entirely (its API drops empty arrays like "products" rather than
// returning []) as an empty list, not null — a null there mismatches the planned
// value for an explicitly configured empty list and Terraform errors with
// "Provider produced inconsistent result after apply".
func Test_CM_ParseArray_MissingFieldIsEmptyNotNull(t *testing.T) {
	t.Run("field absent from response resolves to an empty, non-null list", func(t *testing.T) {
		response := `{"id":"conn-id","name":"conn-name"}`
		got := ParseArray(response, "products")

		if got.IsNull() {
			t.Fatal("expected an empty list, got null")
		}
		if len(got.Elements()) != 0 {
			t.Errorf("expected 0 elements, got %d", len(got.Elements()))
		}
	})

	t.Run("field present as an empty array resolves to an empty, non-null list", func(t *testing.T) {
		response := `{"id":"conn-id","products":[]}`
		got := ParseArray(response, "products")

		if got.IsNull() {
			t.Fatal("expected an empty list, got null")
		}
		if len(got.Elements()) != 0 {
			t.Errorf("expected 0 elements, got %d", len(got.Elements()))
		}
	})

	t.Run("field present as an explicit JSON null still resolves to null", func(t *testing.T) {
		response := `{"id":"conn-id","products":null}`
		got := ParseArray(response, "products")

		if !got.IsNull() {
			t.Errorf("expected null, got %v", got)
		}
	})

	t.Run("field present with values is parsed in order", func(t *testing.T) {
		response := `{"id":"conn-id","products":["cckm","ddc"]}`
		got := ParseArray(response, "products")

		var values []string
		if diags := got.ElementsAs(context.Background(), &values, false); diags.HasError() {
			t.Fatalf("unexpected diagnostics: %v", diags)
		}
		if len(values) != 2 || values[0] != "cckm" || values[1] != "ddc" {
			t.Errorf("got %v, want [cckm ddc]", values)
		}
	})
}
