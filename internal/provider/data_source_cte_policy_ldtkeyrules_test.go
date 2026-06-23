package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCiphertrustCTEPolicyLDTKeyRulesDataSource(t *testing.T) {
	RequireCM(t)

	policyName := "tf-policy-ldt-" + uuid.New().String()[:8]
	keyName := "tf-key-ldt-" + uuid.New().String()[:8]

	testConfig := fmt.Sprintf(`
		resource "ciphertrust_cm_key" "ldt_key" {
			name         = "%s"
			algorithm    = "aes"
			key_size     = 256
			usage_mask   = 76
			undeletable  = false
			unexportable = false
			xts          = false
			meta = {
				permissions = {
					decrypt_with_key     = ["CTE Clients"]
					encrypt_with_key     = ["CTE Clients"]
					export_key           = ["CTE Clients"]
					read_key             = ["CTE Clients"]
				}
				cte = {
					persistent_on_client = true
					encryption_mode      = "CBC"
					cte_versioned        = true
				}
			}
		}

		resource "ciphertrust_cte_policy" "test_policy" {
			name        = "%s"
			description = "Created for CTE policy ldt key rules data source test"
			policy_type = "LDT"
			security_rules = [
				{
					action = "read"
					effect = "permit"
				}
			]
			ldt_key_rules = [
				{
					current_key = {
						key_id = "clear_key"
					}
					transformation_key = {
						key_id = ciphertrust_cm_key.ldt_key.name
					}
				}
			]
		}

		data "ciphertrust_cte_policy_ldt_key_rules" "ds" {
			depends_on = [ciphertrust_cte_policy.test_policy]
			policy     = ciphertrust_cte_policy.test_policy.id
		}
	`, keyName, policyName)

	datasourceName := "data.ciphertrust_cte_policy_ldt_key_rules.ds"
	resourceName := "ciphertrust_cte_policy.test_policy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + testConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(datasourceName, "rules.#", "1"),
					resource.TestCheckResourceAttrSet(datasourceName, "rules.0.id"),
					resource.TestCheckResourceAttr(datasourceName, "rules.0.current_key_id", "clear_key"),
					resource.TestCheckResourceAttr(datasourceName, "rules.0.transformation_key_id", keyName),
					resource.TestCheckResourceAttrPair(datasourceName, "rules.0.policy_id", resourceName, "id"),
				),
			},
		},
	})
}
