package validators_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// selfSignedCertPEM generates a throwaway self-signed X.509 certificate and returns
// its PEM encoding, for use as a known-good input to the validator under test.
func selfSignedCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func runPEMCertificateValidator(value string) validator.StringResponse {
	req := validator.StringRequest{
		Path:        path.Root("certificate"),
		ConfigValue: types.StringValue(value),
	}
	resp := &validator.StringResponse{}
	validators.PEMCertificate().ValidateString(context.Background(), req, resp)
	return *resp
}

// Test_CM_PEMCertificateValidator verifies the validator requires a real X.509
// certificate body, not just a well-formed PEM envelope — closing the gap where a
// PEM-shaped-but-fake value passed plan-time validation cleanly.
func Test_CM_PEMCertificateValidator(t *testing.T) {
	t.Run("a real self-signed certificate is accepted", func(t *testing.T) {
		if resp := runPEMCertificateValidator(selfSignedCertPEM(t)); resp.Diagnostics.HasError() {
			t.Errorf("unexpected error for a real certificate: %v", resp.Diagnostics)
		}
	})

	t.Run("a well-formed PEM envelope with a fake (non-X.509) body is rejected", func(t *testing.T) {
		fake := "-----BEGIN CERTIFICATE-----\nTm90QVJlYWxDZXJ0Qm9keUp1c3RHYXJiYWdlQmFzZTY0IQ==\n-----END CERTIFICATE-----"
		resp := runPEMCertificateValidator(fake)
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error for a PEM-shaped but non-X.509 body")
		}
	})

	t.Run("no PEM markers at all is rejected", func(t *testing.T) {
		resp := runPEMCertificateValidator("not-a-real-pem-cert-value")
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error for a value with no PEM markers")
		}
	})

	t.Run("null config value is not validated", func(t *testing.T) {
		req := validator.StringRequest{Path: path.Root("certificate"), ConfigValue: types.StringNull()}
		resp := &validator.StringResponse{}
		validators.PEMCertificate().ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error for a null config value: %v", resp.Diagnostics)
		}
	})

	t.Run("unknown config value is not validated", func(t *testing.T) {
		req := validator.StringRequest{Path: path.Root("certificate"), ConfigValue: types.StringUnknown()}
		resp := &validator.StringResponse{}
		validators.PEMCertificate().ValidateString(context.Background(), req, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected error for an unknown config value: %v", resp.Diagnostics)
		}
	})
}
