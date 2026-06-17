package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicyKeyRule(t *testing.T) {
	name := "test-policy-keyrule-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			//Step-1 Create standard policy and add key rule
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "policy" {
  name        = %q
  policy_type = "Standard"
  description = "Initial policy"

  security_rules = [{
    effect = "permit,audit"
    action = "all_ops"
  }]
}

resource "ciphertrust_cte_policy_key_rule" "keyrule" {
  policy_id = ciphertrust_cte_policy.policy.id

  rule = {
    key_id   = "clear_key"
  }
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy_key_rule.keyrule", "rule.id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
