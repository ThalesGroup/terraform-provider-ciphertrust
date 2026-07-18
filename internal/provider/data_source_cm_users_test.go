package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccCMUsersListConfig() string {
	return providerConfig + `
data "ciphertrust_cm_users_list" "all" {
  filters = { username = "admin" }
}
`
}

func Test_CM_DataSourceCMUsersList_PasswordSensitive(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMUsersListConfig(),
				Check: checkStep(t, "password attribute present",
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_users_list.all", "users.#", "1"),
					// CM does not return plaintext passwords; value is expected to be empty.
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_users_list.all", "users.0.password", ""),
				),
			},
		},
	})
}
