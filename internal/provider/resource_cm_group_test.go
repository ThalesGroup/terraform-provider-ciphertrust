package provider

import (
	"context"
	"encoding/json"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMGroup(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and verify all schema attributes are populated by Read
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroup"
  description = "initial description"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "name", "TestGroup"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "initial description"),
				),
			},
			// Update description and confirm state is consistent after Read
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroup"
  description = "Updated via TF"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "name", "TestGroup"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "Updated via TF"),
				),
			},
		},
	})
}

// TestAccCMGroup_import verifies that terraform import populates id and name.
func TestAccCMGroup_import(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "importGroup" {
  name        = "ImportTestGroup"
  description = "group for import test"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.importGroup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_groups.importGroup", "name", "ImportTestGroup"),
				),
			},
			// Import by ID (which equals name for CM groups)
			{
				ResourceName:      "ciphertrust_groups.importGroup",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestAccCMGroup_update verifies description update produces a plan diff, applies
// successfully, and a subsequent plan shows no further changes.
func TestAccCMGroup_update(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "updateGroup" {
  name        = "UpdateTestGroup"
  description = "initial"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.updateGroup", "description", "initial"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "updateGroup" {
  name        = "UpdateTestGroup"
  description = "updated"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.updateGroup", "description", "updated"),
				),
			},
			// Confirm no drift after update: Read returns the new value, plan is empty
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "updateGroup" {
  name        = "UpdateTestGroup"
  description = "updated"
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCMGroup_readDrift_404 verifies that if the group is deleted out-of-band,
// the next terraform plan proposes to recreate it (Read removes it from state on 404).
// Requires CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, CIPHERTRUST_PASSWORD env vars.
func TestAccCMGroup_readDrift_404(t *testing.T) {
	var groupID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create the group and capture its ID (which equals name)
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "driftGroup" {
  name = "DriftTestGroup404"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.driftGroup", "id"),
					resource.TestCheckResourceAttrWith("ciphertrust_groups.driftGroup", "id", func(v string) error {
						groupID = v
						return nil
					}),
				),
			},
			// Step 2: delete group out-of-band, refresh state.
			// Read() gets 404 → removes resource from state → plan shows "create" (non-empty).
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"drift-test-delete",
						common.URL_GROUP+"/"+groupID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_readFieldDrift verifies that if description is changed out-of-band,
// the next terraform plan shows a diff on description.
// Requires CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, CIPHERTRUST_PASSWORD env vars.
func TestAccCMGroup_readFieldDrift(t *testing.T) {
	var groupID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "fieldDrift" {
  name        = "FieldDriftGroup"
  description = "original"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.fieldDrift", "description", "original"),
					resource.TestCheckResourceAttrWith("ciphertrust_groups.fieldDrift", "id", func(v string) error {
						groupID = v
						return nil
					}),
				),
			},
			// Step 2: change description out-of-band, refresh state.
			// Read() fetches new value → state has "changed" but config wants "original" → non-empty plan.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					body, _ := json.Marshal(map[string]string{"description": "changed-out-of-band"})
					_, _ = client.UpdateData(
						context.Background(),
						groupID,
						common.URL_GROUP,
						body,
						"name",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
