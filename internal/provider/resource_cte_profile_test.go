package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteProfileConfig renders a ciphertrust_cte_profile. When updated is true the
// mutable settings are changed so the update step can read them back.
func cteProfileConfig(name string, updated bool) string {
	if updated {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_profile" "profile" {
  name            = %q
  description     = "Updated profile"
  concise_logging = false
  connect_timeout = 20

  cache_settings = {
    max_files = 800
    max_space = 300
  }

  file_settings = {
    allow_purge    = false
    file_threshold = "ERROR"
    max_file_size  = 200000
    max_old_files  = 10
  }

  duplicate_settings = {
    suppress_interval  = 10
    suppress_threshold = 5
  }
}
`, name)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_profile" "profile" {
  name            = %q
  description     = "Initial profile"
  concise_logging = true
  connect_timeout = 10

  cache_settings = {
    max_files = 500
    max_space = 200
  }

  file_settings = {
    allow_purge    = true
    file_threshold = "ERROR"
    max_file_size  = 100000
    max_old_files  = 5
  }
}
`, name)
}

func TestCTEProfileResource(t *testing.T) {
	name := "tf-profile-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_profile.profile"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteProfileConfig(name, false),
				Check: checkStep(t, "profile: create",
					resource.TestCheckResourceAttrSet(rn, "id"),
					resource.TestCheckResourceAttr(rn, "name", name),
					resource.TestCheckResourceAttr(rn, "description", "Initial profile"),
					resource.TestCheckResourceAttr(rn, "connect_timeout", "10"),
				),
			},
			{
				Config: cteProfileConfig(name, true),
				Check: checkStep(t, "profile: update",
					resource.TestCheckResourceAttr(rn, "description", "Updated profile"),
					resource.TestCheckResourceAttr(rn, "connect_timeout", "20"),
					resource.TestCheckResourceAttr(rn, "concise_logging", "false"),
				),
			},
			{
				ResourceName:     rn,
				ImportState:      true,
				ImportStateCheck: importStateCheckAttrsSet("id", "name"),
			},
		},
	})
}

// TestCTEProfileResource_nameImmutable verifies that changing name after
// creation produces a plan-time immutable error from ImmutableString rather
// than a destroy+create, since the profile's id is referenced elsewhere
// (via profile_id on ciphertrust_cte_client/ciphertrust_cte_client_group)
// and must not be reminted on rename (TFIN-499).
func TestCTEProfileResource_nameImmutable(t *testing.T) {
	name := "tf-profile-imm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_profile.profile"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteProfileConfig(name, false),
				Check: checkStep(t, "profile immutable name: create",
					resource.TestCheckResourceAttr(rn, "name", name),
				),
			},
			{
				Config:      cteProfileConfig(name+"-renamed", false),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// TestCTEProfileResource_drift mutates the description out-of-band and asserts the
// next plan is non-empty.
func TestCTEProfileResource_drift(t *testing.T) {
	name := "tf-profile-drift-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_profile.profile"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteProfileConfig(name, false),
				Check: checkStep(t, "profile drift: create",
					resource.TestCheckResourceAttr(rn, "description", "Initial profile"),
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_PROFILE, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteProfileConfig(name, false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCTEProfileResource_removingDescriptionConverges verifies that removing
// description from config and applying converges to no changes (TFIN-500).
func TestCTEProfileResource_removingDescriptionConverges(t *testing.T) {
	name := "tf-profile-rem-desc-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_profile.profile"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with description
			{
				Config: cteProfileConfig(name, false),
				Check: checkStep(t, "profile: create with description",
					resource.TestCheckResourceAttr(rn, "description", "Initial profile"),
				),
			},
			// Remove description from config
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_profile" "profile" {
  name = %q
}
`, name),
				Check: checkStep(t, "profile: remove description",
					resource.TestCheckNoResourceAttr(rn, "description"),
				),
			},
			// Plan again should show no changes (fixes TFIN-500)
			{
				Config:             providerConfig + fmt.Sprintf(`resource "ciphertrust_cte_profile" "profile" { name = %q }`, name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
