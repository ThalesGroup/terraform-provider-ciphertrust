package validators

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type rfc3339Validator struct{}

// RFC3339 returns a validator that requires the attribute value to be a date and time
// in RFC3339 format, for example 2030-07-03T14:24:00Z. Null and unknown values are
// accepted without error.
func RFC3339() validator.String {
	return rfc3339Validator{}
}

func (v rfc3339Validator) Description(_ context.Context) string {
	return "value must be a date and time in RFC3339 format, for example 2030-07-03T14:24:00Z"
}

func (v rfc3339Validator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v rfc3339Validator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if _, err := time.Parse(time.RFC3339, req.ConfigValue.ValueString()); err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid date",
			fmt.Sprintf("The value must be a date and time in RFC3339 format, for example 2030-07-03T14:24:00Z: %s", err),
		)
	}
}
