package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicy(t *testing.T) {
	name := "TestPolicy-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`

resource "ciphertrust_cte_policy" "cte_policy" {
  name = %q
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
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy.cte_policy", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "cte_policy" {
  name = %q
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
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy.cte_policy", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
