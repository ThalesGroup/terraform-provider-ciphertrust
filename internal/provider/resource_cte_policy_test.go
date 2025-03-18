package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEPolicy(t *testing.T) {
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
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = "TestResourceSet"
  resources = [
    {
      directory="/tmp"
      file="*"
	  hdfs=false
	  include_subfolders=false
    }
  ]
  type="Directory"
}

resource "ciphertrust_cm_key" "cte_key" {
  name="TestKey"
  algorithm="aes"
  size=256
  usage_mask=4194303
  unexportable=false
  undeletable=false
  xts=true
  meta={
    permissions={
	  decrypt_with_key=["CTE Clients"]
	  encrypt_with_key=["CTE Clients"]
	  export_key=["CTE Clients"]
	  mac_verify_with_key=["CTE Clients"]
	  mac_with_key=["CTE Clients"]
	  read_key=["CTE Clients"]
	  sign_verify_with_key=["CTE Clients"]
	  sign_with_key=["CTE Clients"]
	  use_key=["CTE Clients"]
	}
	cte={
	  persistent_on_client=true
	  cte_versioned=false
	  encryption_mode="CBC_CS1"
	}
  }
}

resource "ciphertrust_cte_policy" "cte_policy" {
  name = "TestPolicy"
  policy_type = "Standard"
  never_deny = false
  security_rules = [
    {
      effect="permit"
	  action="all_ops"
      partial_match=false
      resource_set_id=ciphertrust_cte_resource_set.resource_set.id
      exclude_resource_set=true
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_policy.cte_policy", "id"),
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
resource "ciphertrust_cte_policy" "cte_policy" {
  name = "TestPolicy"
  policy_type = "Standard"
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
