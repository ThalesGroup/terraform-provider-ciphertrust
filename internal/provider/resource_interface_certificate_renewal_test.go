package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
