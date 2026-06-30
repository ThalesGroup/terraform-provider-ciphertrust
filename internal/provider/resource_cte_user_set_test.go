package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteUserSetConfig renders a ciphertrust_cte_user_set. When secondUser is true a
// second user is appended, which lets the update step assert a list-length change.
func cteUserSetConfig(name, description string, secondUser bool) string {
	users := `
    {
      uname = "user1"
      gid   = 0
      uid   = 0
    }`
	if secondUser {
		users += `,
    {
      uname = "user2"
      gid   = 0
      uid   = 0
    }`
	}
	desc := ""
	if description != "" {
		desc = fmt.Sprintf("  description = %q\n", description)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_user_set" "user_set" {
  name = %q
%s  users = [%s
  ]
}
`, name, desc, users)
}

// TestResourceCTEUserSet exercises Create -> Read -> Update -> Delete with
// assertions on the computed fields, then verifies a clean plan (no drift) on
// re-apply and a successful import.
func TestResourceCTEUserSet(t *testing.T) {
	name := "tf-userset-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create + Read.
			{
				Config: cteUserSetConfig(name, "Created via TF", false),
				Check: checkStep(t, "user_set: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cte_user_set.user_set", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_user_set.user_set", "uri"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_user_set.user_set", "account"),
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "description", "Created via TF"),
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "users.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "users.0.uname", "user1"),
				),
			},
			// Plan stability: re-applying the same config yields no diff.
			{
				Config:             cteUserSetConfig(name, "Created via TF", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Update: change description and add a second user; read them back.
			{
				Config: cteUserSetConfig(name, "Updated via TF", true),
				Check: checkStep(t, "user_set: update",
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "description", "Updated via TF"),
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "users.#", "2"),
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "users.1.uname", "user2"),
				),
			},
			// Plan stability after update.
			{
				Config:             cteUserSetConfig(name, "Updated via TF", true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Import: passthrough by id.
			{
				ResourceName:      "ciphertrust_cte_user_set.user_set",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestResourceCTEUserSet_nameImmutable verifies the provider rejects a name change
// after creation (Update returns an immutable-field error).
func TestResourceCTEUserSet_nameImmutable(t *testing.T) {
	name := "tf-userset-imm-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteUserSetConfig(name, "Original", false),
				Check: checkStep(t, "user_set immutable: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "name", name),
				),
			},
			{
				Config:      cteUserSetConfig(name+"-renamed", "Original", false),
				ExpectError: regexp.MustCompile(`(?i)cannot change user set name|immutable`),
			},
		},
	})
}

// TestResourceCTEUserSet_drift is the drift-detection test for the "set" category:
// it mutates the description out-of-band and asserts the next plan is non-empty.
func TestResourceCTEUserSet_drift(t *testing.T) {
	name := "tf-userset-drift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteUserSetConfig(name, "Drift original", false),
				Check: checkStep(t, "user_set drift: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_user_set.user_set", "description", "Drift original"),
					cteCaptureID("ciphertrust_cte_user_set.user_set", &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_USER_SET, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteUserSetConfig(name, "Drift original", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
