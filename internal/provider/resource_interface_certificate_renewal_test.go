package provider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// generateSelfSignedLeafCertPEM builds a self-signed EC server-leaf certificate
// (CA:false, serverAuth EKU, single DNS SAN) and its private key, returned as a
// single PEM string with the certificate followed by the key — the format CM's
// renewal-certificate endpoint expects for format="PEM".
func generateSelfSignedLeafCertPEM(t *testing.T, cn string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate EC key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{Country: []string{"US"}, Province: []string{"TX"}, Organization: []string{"Thales"}, CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{cn},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create self-signed certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal EC private key: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEM) + string(keyPEM)
}

// Test_CM_InterfaceCertificateRenewal_Basic verifies that
// ciphertrust_interface_certificate_renewal stages and applies a self-signed
// certificate on an existing interface, and that changing trigger causes a
// resource replacement that performs a second renewal.
func Test_CM_InterfaceCertificateRenewal_Basic(t *testing.T) {
	RequireCM(t)

	interfaceConfig := providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9883
  interface_type = "nae"
}
`

	renewalConfig := `
resource "ciphertrust_interface_certificate_renewal" "renew" {
  interface_name = ciphertrust_interface.test.name
  generate        = true
  trigger        = "%s"
}
`

	renewalResource := "ciphertrust_interface_certificate_renewal.renew"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9883) },
				Config:    interfaceConfig,
				Check: checkStep(t, "create interface",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
				),
			},
			{
				// Step 1: first renewal.
				Config: interfaceConfig + fmt.Sprintf(renewalConfig, "renewal-1"),
				Check: checkStep(t, "first renewal",
					resource.TestCheckResourceAttrSet(renewalResource, "id"),
					resource.TestCheckResourceAttrSet(renewalResource, "applied_certificate"),
					resource.TestCheckResourceAttr(renewalResource, "trigger", "renewal-1"),
				),
			},
			{
				// Step 2: change trigger — forces replacement and a second renewal.
				Config: interfaceConfig + fmt.Sprintf(renewalConfig, "renewal-2"),
				Check: checkStep(t, "second renewal",
					resource.TestCheckResourceAttrSet(renewalResource, "id"),
					resource.TestCheckResourceAttrSet(renewalResource, "applied_certificate"),
					resource.TestCheckResourceAttr(renewalResource, "trigger", "renewal-2"),
				),
			},
		},
	})
}

// Test_CM_InterfaceCertificateRenewal_ImmutableInterfaceName verifies that
// interface_name cannot be changed after creation.
func Test_CM_InterfaceCertificateRenewal_ImmutableInterfaceName(t *testing.T) {
	RequireCM(t)

	baseConfig := providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9884
  interface_type = "nae"
}
resource "ciphertrust_interface" "other" {
  port           = 9885
  interface_type = "nae"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() {
					interfaceSweep(9884)
					interfaceSweep(9885)
				},
				Config: baseConfig + `
resource "ciphertrust_interface_certificate_renewal" "renew" {
  interface_name = ciphertrust_interface.test.name
  generate        = true
  trigger        = "renewal-1"
}
`,
				Check: checkStep(t, "create renewal",
					resource.TestCheckResourceAttrSet("ciphertrust_interface_certificate_renewal.renew", "id"),
				),
			},
			{
				// Attempting to point the resource at a different interface must be rejected at plan time.
				PlanOnly: true,
				Config: baseConfig + `
resource "ciphertrust_interface_certificate_renewal" "renew" {
  interface_name = ciphertrust_interface.other.name
  generate        = true
  trigger        = "renewal-1"
}
`,
				ExpectError: regexp.MustCompile(`(?i)cannot be changed`),
			},
		},
	})
}

// Test_CM_InterfaceCertificateRenewal_ImportPEM verifies that a certificate can be
// staged and applied by importing PEM certificate+key data (as opposed to
// generate=true self-signing), exercising the certificate/format/skip_validation
// branch of Create.
func Test_CM_InterfaceCertificateRenewal_ImportPEM(t *testing.T) {
	RequireCM(t)

	certPEM := generateSelfSignedLeafCertPEM(t, "nae-all-9886-imported-test")

	interfaceConfig := providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9886
  interface_type = "nae"
}
`

	renewalConfig := fmt.Sprintf(`
resource "ciphertrust_interface_certificate_renewal" "renew" {
  interface_name  = ciphertrust_interface.test.name
  certificate     = %q
  format          = "PEM"
  skip_validation = true
  trigger         = "import-1"
}
`, certPEM)

	renewalResource := "ciphertrust_interface_certificate_renewal.renew"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9886) },
				Config:    interfaceConfig,
				Check: checkStep(t, "create interface",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
				),
			},
			{
				Config: interfaceConfig + renewalConfig,
				Check: checkStep(t, "import PEM certificate",
					resource.TestCheckResourceAttrSet(renewalResource, "id"),
					resource.TestCheckResourceAttrSet(renewalResource, "applied_certificate"),
					resource.TestCheckResourceAttr(renewalResource, "format", "PEM"),
					resource.TestCheckResourceAttr(renewalResource, "trigger", "import-1"),
				),
			},
		},
	})
}
