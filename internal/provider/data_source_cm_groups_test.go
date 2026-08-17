package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccCMGroupsListFilterConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name = %q
}

data "ciphertrust_cm_groups_list" "filtered" {
  filters    = { name = %q }
  depends_on = [ciphertrust_groups.test]
}
`, name, name)
}

func Test_CM_DataSourceCMGroupsList_FiltersHonored(t *testing.T) {
	RequireCM(t)
	name := "tfin419g-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMGroupsListFilterConfig(name),
				Check: checkStep(t, "filters honored",
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_groups_list.filtered", "groups.#", "1"),
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_groups_list.filtered", "groups.0.name", name),
				),
			},
		},
	})
}

// Test_CM_GroupsList_Pagination asserts that retrieving the groups list data source
// without manual page filters triggers auto-pagination and correctly lists resources.
func Test_CM_GroupsList_Pagination(t *testing.T) {
	RequireCM(t)
	name := "tf-grouppag-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name = %q
}

data "ciphertrust_cm_groups_list" "all" {
  depends_on = [ciphertrust_groups.test]
}
`, name),
				Check: checkStep(t, "pagination auto-listing",
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_groups_list.all", "groups.0.name"),
				),
			},
		},
	})
}

// Test_CM_GroupsList_BogusFilterKeyRejectedAtPlan verifies that an unrecognised
// filter key is rejected at plan time (TFIN-581 Bug 1). No live CM needed.
func Test_CM_GroupsList_BogusFilterKeyRejectedAtPlan(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_groups_list" "probe" {
  filters = { "totally_bogus_filter_key" = "xyz" }
}
`,
				ExpectError: regexp.MustCompile(`(?i)value must be one of`),
			},
		},
	})
}

// Test_CM_GroupsList_ZeroMatchReturnsEmptyList verifies that a filter matching
// zero groups returns an empty list [] rather than null (TFIN-581 Bug 2).
func Test_CM_GroupsList_ZeroMatchReturnsEmptyList(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_groups_list" "probe" {
  filters = { "name" = "zzz_nonexistent_group_tfin581_probe" }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Length 0 confirms no groups matched.
					resource.TestCheckResourceAttr("data.ciphertrust_cm_groups_list.probe", "groups.#", "0"),
					// Explicitly verify the attribute is an empty list (not null).
					// TestCheckResourceAttr with "groups.#" = "0" only passes when the
					// attribute is a non-null empty list — a null attribute has no "#"
					// meta-key and the check would fail with "attribute not found".
					resource.TestCheckNoResourceAttr("data.ciphertrust_cm_groups_list.probe", "groups.0"),
				),
			},
		},
	})
}
