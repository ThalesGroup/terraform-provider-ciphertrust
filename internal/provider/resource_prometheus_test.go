package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestAccCipherTrust_Prometheus_ImmutableFields verifies ciphertrust_cm_prometheus behaviour:
// - Step 1: resource is created with enabled=true.
// - Step 2: changing enabled (the only user-configurable field) is accepted — it is mutable,
//   so no immutability error is expected.
//
// Note: ciphertrust_cm_prometheus has only two attributes — token (Computed) and enabled
// (Required). There are no non-'enabled' Required/Optional fields, so no ImmutableX()
// modifiers apply to this resource. The test verifies the mutable field works correctly.
func TestAccCipherTrust_Prometheus_ImmutableFields(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the resource with enabled=true.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_prometheus.test", "token"),
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
				),
			},
			// Step 2: Change enabled — this is the only mutable field; no immutability error.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = false
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
