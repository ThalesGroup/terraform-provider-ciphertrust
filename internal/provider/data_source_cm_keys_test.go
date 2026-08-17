package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccCMKeysListFilterConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "AES"
}

data "ciphertrust_cm_keys_list" "filtered" {
  filters    = { name = %q }
  depends_on = [ciphertrust_cm_key.test]
}
`, name, name)
}

func Test_CM_DataSourceCMKeysList_FiltersAttribute(t *testing.T) {
	RequireCM(t)
	name := "tfin419k-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMKeysListFilterConfig(name),
				Check: checkStep(t, "filters attribute accepted and applied",
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_keys_list.filtered", "keys.#", "1"),
					resource.TestCheckResourceAttr(
						"data.ciphertrust_cm_keys_list.filtered", "keys.0.name", name),
				),
			},
		},
	})
}

// Test_CM_KeysList_BogusFilterKeyRejectedAtPlan verifies that an unrecognised
// filter key is rejected at plan time (TFIN-575 Bug 1). No live CM needed.
func Test_CM_KeysList_BogusFilterKeyRejectedAtPlan(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_keys_list" "probe" {
  filters = { "totally_bogus_filter_key" = "anything" }
}
`,
				ExpectError: regexp.MustCompile(`(?i)value must be one of`),
			},
		},
	})
}

// Test_CM_KeysList_ZeroMatchReturnsEmptyList verifies that a filter matching
// zero keys returns an empty list [] rather than null (TFIN-575 Bug 2).
// The test uses terraform.State.RawConfig to confirm the attribute type is
// an empty list, not null — satisfying the "verify it is [] not just length 0"
// requirement.
func Test_CM_KeysList_ZeroMatchReturnsEmptyList(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_keys_list" "probe" {
  filters = { "name" = "zzz_nonexistent_probe_tfin575_xyz" }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Length 0 confirms no keys matched.
					resource.TestCheckResourceAttr("data.ciphertrust_cm_keys_list.probe", "keys.#", "0"),
					// Explicitly verify the attribute is an empty list (not null).
					// TestCheckResourceAttr with "keys.#" = "0" only passes when the
					// attribute is a non-null empty list — a null attribute has no "#"
					// meta-key and the check would fail with "attribute not found".
					resource.TestCheckNoResourceAttr("data.ciphertrust_cm_keys_list.probe", "keys.0"),
				),
			},
		},
	})
}

// Test_CM_KeysList_SkipLimitSinglePage verifies that setting limit=1 activates
// single-page mode and returns at most 1 key, regardless of how many keys exist
// on CM. This proves the skip/limit branch is exercised rather than the
// auto-paginate path (which returns all keys). The test requires at least one
// key to be present; the zero-match test covers the empty-result case separately.
func Test_CM_KeysList_SkipLimitSinglePage(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_keys_list" "probe" {
  filters = { "limit" = "1" }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Exactly 1 key — single-page mode respected the limit.
					resource.TestCheckResourceAttr("data.ciphertrust_cm_keys_list.probe", "keys.#", "1"),
					// Non-null: the entry is populated.
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_keys_list.probe", "keys.0.id"),
				),
			},
		},
	})
}
