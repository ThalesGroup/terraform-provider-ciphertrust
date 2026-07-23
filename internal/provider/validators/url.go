package validators

import (
	"context"
	"fmt"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// URL returns a String validator that checks the configured value is a
// well-formed absolute URL (scheme + host), e.g. "http://proxy.example.com:8080".
func URL() validator.String {
	return urlValidator{}
}

type urlValidator struct{}

func (v urlValidator) Description(_ context.Context) string {
	return "value must be a well-formed URL with a scheme and host (e.g. http://host:port)"
}

func (v urlValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v urlValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid URL",
			fmt.Sprintf("value must be a well-formed URL with a scheme and host (e.g. http://host:port), got: %q", value),
		)
	}
}
