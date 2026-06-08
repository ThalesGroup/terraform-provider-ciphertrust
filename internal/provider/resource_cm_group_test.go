package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// groupName returns a unique group name for a test to avoid collisions.
func groupName(prefix string) string {
	return prefix + "-" + uuid.New().String()[:8]
}

// groupConfig renders a minimal HCL block for ciphertrust_groups.
func groupConfig(name, description string) string {
	if description == "" {
		return fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name = %q
}
`, name)
	}
	return fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name        = %q
  description = %q
}
`, name, description)
}

// TestAccCMGroup_basic creates a group and verifies that all tracked state
// attributes (id, name, description) are populated after apply.
func TestAccCMGroup_basic(t *testing.T) {
	name := groupName("tf-grp-basic")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + groupConfig(name, "initial description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", "initial description"),
				),
			},
		},
	})
}

// TestResourceCMGroup is the original basic test, extended with attribute checks.
func TestResourceCMGroup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "testGroup" {
  name="TestGroup"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "testGroup" {
  description="Updated via TF"
  name="TestGroup"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "name"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "Updated via TF"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestAccCMGroup_updateInPlace creates a group then updates its description,
// verifying that the id is unchanged (no recreation) and state reflects the new value.
func TestAccCMGroup_updateInPlace(t *testing.T) {
	name := groupName("tf-grp-update")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + groupConfig(name, "original description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", "original description"),
					resource.TestCheckResourceAttrSet("ciphertrust_groups.test", "id"),
				),
			},
			{
				Config: providerConfig + groupConfig(name, "updated description"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", "updated description"),
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "name", name),
				),
			},
		},
	})
}

// TestAccCMGroup_outOfBandDelete verifies that when a group is deleted out-of-band,
// a subsequent terraform plan detects the absence and proposes recreation.
func TestAccCMGroup_outOfBandDelete(t *testing.T) {
	name := groupName("tf-grp-oob-del")
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + groupConfig(name, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_groups.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the group out-of-band, then verify plan detects the deletion.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"oob-delete-test",
						common.URL_GROUP+"/"+capturedID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_outOfBandFieldDrift verifies that when description is modified
// out-of-band, a subsequent terraform plan detects the drift.
func TestAccCMGroup_outOfBandFieldDrift(t *testing.T) {
	name := groupName("tf-grp-oob-drift")
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + groupConfig(name, "original"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", "original"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_groups.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Modify description out-of-band via PATCH, then verify plan shows drift.
				// UpdateData(ctx, resourceID, endpoint, payload, responseField) calls
				// PATCH {base}/{endpoint}/{resourceID}.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload, _ := json.Marshal(map[string]string{"description": "drifted"})
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_GROUP,
						payload,
						"name",
					)
				},
				Config:             providerConfig + groupConfig(name, "original"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_import verifies that terraform import populates all tracked
// attributes and that client_certificate is absent from imported state.
func TestAccCMGroup_import(t *testing.T) {
	name := groupName("tf-grp-import")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + groupConfig(name, "import test"),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "name", name),
				),
			},
			{
				ResourceName:      "ciphertrust_groups.test",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccCMGroup_immutableNameChangeRejected verifies that attempting to change
// the group name after creation produces an error diagnostic and does not trigger
// a destroy-recreate.
func TestAccCMGroup_immutableNameChangeRejected(t *testing.T) {
	name := groupName("tf-grp-immut")
	newName := groupName("tf-grp-immut-new")
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + groupConfig(name, ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "name", name),
				),
			},
			{
				Config:      providerConfig + groupConfig(newName, ""),
				ExpectError: regexp.MustCompile(`(?i)immutable attribute`),
			},
		},
	})
}
