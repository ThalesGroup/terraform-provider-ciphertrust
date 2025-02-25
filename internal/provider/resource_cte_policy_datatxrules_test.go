package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicyDataTXRule(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
// resource "ciphertrust_cte_policy_data_tx_rule" "dataTxRule" {
// 	policy_id = ciphertrust_cte_policy.cte_policy.id
// 	rule = {
// 		key_id="TestKey"
// 		key_type="name"
// 		resource_set_id=ciphertrust_cte_resource_set.resource_set.id
// 	}
// }
`,
				Check: resource.ComposeAggregateTestCheckFunc(
				//resource.TestCheckResourceAttrSet("ciphertrust_cte_policy_data_tx_rule.dataTxRule", "id"),
				),
			},
			// ImportState testing
			//{
			//	ResourceName:      "ciphertrust_cm_reg_token.reg_token",
			//	ImportState:       true,
			//	ImportStateVerify: true,
			//	ImportStateVerifyIgnore: []string{"last_updated"},
			//},
			// Update and Read testing
			{
				Config: providerConfig + `
// resource "ciphertrust_cte_policy_data_tx_rule" "dataTxRule" {
// 	policy_id = ciphertrust_cte_policy.cte_policy.id
// 	rule = {
// 		key_id="TestKey"
// 		key_type="name"
// 		resource_set_id=ciphertrust_cte_resource_set.resource_set.id
// 	}
// 	order_number=1
// }
`,
				Check: resource.ComposeAggregateTestCheckFunc(
				//resource.TestCheckResourceAttrSet("ciphertrust_cte_policy_data_tx_rule.dataTxRule", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
