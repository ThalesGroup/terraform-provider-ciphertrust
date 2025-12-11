package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicyDataTXRule(t *testing.T) {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	bootstrap := "no"

	if address == "" || username == "" || password == "" {
		t.Fatal("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, and CIPHERTRUST_PASSWORD must be set for testing")
	}

	providerConfig := fmt.Sprintf(providerConfig, address, username, password, bootstrap)

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
