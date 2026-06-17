package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCTEUserSet(t *testing.T) {
	name := "testUserSet1-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_user_set" "user_set" {
  name = %q
  users = [
    {
      uname="user1"
      gid=0
      uid=0
    }
  ]
}
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_user_set.user_set", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_user_set" "user_set" {
  name = %q
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
`, name),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cte_user_set.user_set", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
