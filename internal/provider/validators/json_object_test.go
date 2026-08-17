package validators_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
)

func TestJSONObject(t *testing.T) {
	v := validators.JSONObject()

	accepted := []string{
		`{"key": "value"}`,
		`{"nested": {"a": 1}}`,
		`{}`,
		`{"arr": [1, 2, 3]}`,
		``,    // empty string — no content to validate
		`   `, // whitespace only — treated as empty
	}
	for _, val := range accepted {
		req := validator.StringRequest{ConfigValue: types.StringValue(val)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("JSONObject() rejected valid value %q: %s", val, resp.Diagnostics[0].Detail())
		}
	}

	rejected := []string{
		`not-json`,
		`not-valid-json{`,
		`[1, 2, 3]`,  // valid JSON but not an object
		`"a string"`, // valid JSON but not an object
		`123`,        // valid JSON but not an object
	}
	for _, val := range rejected {
		req := validator.StringRequest{ConfigValue: types.StringValue(val)}
		resp := &validator.StringResponse{}
		v.ValidateString(context.Background(), req, resp)
		if !resp.Diagnostics.HasError() {
			t.Errorf("JSONObject() accepted invalid value %q but should have rejected it", val)
		}
	}
}
