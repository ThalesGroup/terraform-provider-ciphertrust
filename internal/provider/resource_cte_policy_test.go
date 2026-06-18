package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `

resource "ciphertrust_cte_policy" "cte_policy" {
  name = "TestPolicy"
  policy_type = "Standard"
  never_deny = false
  security_rules = [
    {
      effect="permit"
	  action="all_ops"
      partial_match=false
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy.cte_policy", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "ciphertrust_cte_policy" "cte_policy" {
  name = "TestPolicy"
  policy_type = "Standard"
  security_rules = [
    {
      effect="permit"
	  action="read"
      partial_match=false
    },
  ]
  description="updated via TF"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy.cte_policy", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
