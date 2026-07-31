package validators

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// PEMCertificate returns a String validator that checks the configured value
// decodes as at least one well-formed PEM block of type CERTIFICATE whose body is a
// valid X.509 (ASN.1 DER) certificate — not just a well-formed PEM envelope.
func PEMCertificate() validator.String {
	return pemCertificateValidator{}
}

type pemCertificateValidator struct{}

func (v pemCertificateValidator) Description(_ context.Context) string {
	return "value must be a well-formed PEM-encoded X.509 certificate (-----BEGIN CERTIFICATE-----)"
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
		if !strings.Contains(block.Type, "CERTIFICATE") {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err == nil {
			return
		}
	}

	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid PEM Certificate",
		fmt.Sprintf("value must be a well-formed PEM-encoded X.509 certificate (-----BEGIN CERTIFICATE-----) whose body decodes as valid ASN.1 DER, got: %q", value),
	)
}
