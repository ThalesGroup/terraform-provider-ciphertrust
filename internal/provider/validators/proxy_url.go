package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// ProxyURL returns a String validator that accepts proxy address formats that
// CipherTrust Manager's REST API accepts, including:
//
//   - Full URL:            http://user:pass@host:port
//   - Schemeless+creds:   user:pass@host:port       (CM documented "Scenario 3")
//   - Host:port:           host:port
//   - Bare hostname:       hostname
//
// The validator only rejects values that are clearly malformed (empty after
// trimming, or containing whitespace), mirroring the CM API contract rather
// than enforcing strict RFC URL semantics.
func ProxyURL() validator.String {
	return proxyURLValidator{}
}

type proxyURLValidator struct{}

func (v proxyURLValidator) Description(_ context.Context) string {
	return "value must be a proxy address accepted by CipherTrust Manager: " +
		"a full URL (e.g. http://host:port), a schemeless address (e.g. host:port " +
		"or user:pass@host:port), or a bare hostname"
}

func (v proxyURLValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v proxyURLValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()

	// Reject empty or whitespace-only values.
	if strings.TrimSpace(value) == "" {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Proxy Address",
			fmt.Sprintf("proxy address must not be empty, got: %q", value),
		)
		return
	}

	// Reject values containing whitespace — a proxy address should never have spaces.
	if strings.ContainsAny(value, " \t\n\r") {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"Invalid Proxy Address",
			fmt.Sprintf("proxy address must not contain whitespace, got: %q", value),
		)
		return
	}
}
