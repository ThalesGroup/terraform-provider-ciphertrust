package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceCMPrometheus(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = true
}
`,
				// Step 2: Check if the resource's 'enabled' attribute is set correctly after apply
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.cm_prometheus", "enabled", "true"),
				),
			},
		},
	})
	// create a new resource with prometheus disable
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = false
}
`,
				// Step 2: Check if the resource's 'enabled' attribute is set correctly after apply
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.cm_prometheus", "enabled", "false"),
				),
			},
		},
	})
}

// Test_CM_CipherTrust_CMPrometheus_TokenSensitive verifies token is stored in state after
// create, is Sensitive (UseStateForUnknown prevents perpetual known-after-apply), is
// preserved in state when disabled, and is refreshed when re-enabled.
func Test_CM_CipherTrust_CMPrometheus_TokenSensitive(t *testing.T) {
	RequireCM(t)
	var capturedToken string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with enabled=true; verify token is stored.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_prometheus.test", "token"),
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
					func(s *terraform.State) error {
						capturedToken = s.RootModule().Resources["ciphertrust_cm_prometheus.test"].Primary.Attributes["token"]
						return nil
					},
				),
			},
			// Step 2: Plan stability — UseStateForUnknown() must prevent perpetual (known after apply).
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 3: Disable Prometheus; token must be preserved via Update() three-branch resolution.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = false
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "false"),
					// Use a closure so capturedToken is read lazily after Step 1 has run.
					func(s *terraform.State) error {
						return resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "token", capturedToken)(s)
					},
				),
			},
			// Step 4: Re-enable; token should be refreshed.
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
			// Step 5: Plan stability after re-enable.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 6: Cleanup — disable again to confirm full cycle completes without error.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = false
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "false"),
				),
			},
		},
	})
}
