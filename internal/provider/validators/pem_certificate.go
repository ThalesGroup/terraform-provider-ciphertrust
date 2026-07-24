package validators

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// PEMCertificate returns a String validator that checks the configured value
// decodes as at least one well-formed PEM block of type CERTIFICATE.
func PEMCertificate() validator.String {
	return pemCertificateValidator{}
}

type pemCertificateValidator struct{}

func (v pemCertificateValidator) Description(_ context.Context) string {
	return "value must be a well-formed PEM-encoded certificate (-----BEGIN CERTIFICATE-----)"
}

func (v pemCertificateValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v pemCertificateValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()

	rest := []byte(value)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "CERTIFICATE") {
			return
		}
	}

	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid PEM Certificate",
		fmt.Sprintf("value must be a well-formed PEM-encoded certificate (-----BEGIN CERTIFICATE-----), got: %q", value),
	)
}
