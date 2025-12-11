package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEUserSet(t *testing.T) {
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
resource "ciphertrust_cte_user_set" "user_set" {
  name = "testUserSet1"
  users = [
    {
      uname="user1"
      gid=0
      uid=0
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_user_set.user_set", "id"),
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
resource "ciphertrust_cte_user_set" "user_set" {
  name = "testUserSet1"
  description = "Updated via TF"
  users = [
    {
      uname="user1"
      gid=0
      uid=0
    },
	{
      uname="user2"
      gid=0
      uid=0
    }
  ]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_user_set.user_set", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
