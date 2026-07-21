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

func Test_CM_DataSourceCMUsersList_PaginationAndStability(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Query users list with pagination limit = 1
			{
				Config: providerConfig + `
data "ciphertrust_cm_users_list" "paginated" {
  limit = 1
  skip  = 0
}
`,
				Check: checkStep(t, "Pagination limits applied successfully",
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_users_list.paginated", "id"),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.paginated", "limit", "1"),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.paginated", "skip", "0"),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.paginated", "users.#", "1"),
				),
			},
			// Step 2: Verify zero state accumulation / no-drift plan stability on re-apply
			{
				Config: providerConfig + `
data "ciphertrust_cm_users_list" "paginated" {
  limit = 1
  skip  = 0
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
