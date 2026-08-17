package validators

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type jsonObjectValidator struct{}

// JSONObject returns a validator that requires the attribute value to be a valid
// JSON object (i.e. parseable as map[string]interface{}). Empty and null values
// are accepted without error.
func JSONObject() validator.String {
	return jsonObjectValidator{}
}

func (v jsonObjectValidator) Description(_ context.Context) string {
	return "value must be a valid JSON object"
}

func (v jsonObjectValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v jsonObjectValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	val := strings.TrimSpace(req.ConfigValue.ValueString())
	if val == "" {
		return
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(val), &m); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid JSON Object",
			fmt.Sprintf("The value must be a valid JSON object (e.g. {\"key\": \"value\"}): %s", err),
		)
	}
}
