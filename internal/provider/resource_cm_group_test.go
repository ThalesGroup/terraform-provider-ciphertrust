package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

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
				),
			},
			//ImportState testing
			/*{
				ResourceName:            "ciphertrust_cm_key.cte_key",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"last_updated"},
			},*/
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
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestAccCMGroup_ReadHydration verifies that Read() correctly hydrates description
// and app_metadata from the CM API response into Terraform state.
// A no-drift plan after create confirms that Read() matches what was written.
func TestAccCMGroup_ReadHydration(t *testing.T) {
	groupName := fmt.Sprintf("tftest-hydration-%s", uuid.New().String()[:8])
	resourceAddr := "ciphertrust_groups.test"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name        = %q
  description = "hydration-test-description"
  app_metadata = jsonencode({"env": "test"})
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create group and verify description and app_metadata are in state.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddr, "name", groupName),
					resource.TestCheckResourceAttr(resourceAddr, "description", "hydration-test-description"),
					resource.TestCheckResourceAttrSet(resourceAddr, "app_metadata"),
				),
			},
			{
				// Step 2: re-plan; no drift means Read() correctly hydrated state.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCMGroup_Disappears verifies that when a group is deleted out-of-band,
// Read() detects the 404, removes the resource from state, and Terraform proposes re-creation.
func TestAccCMGroup_Disappears(t *testing.T) {
	groupName := fmt.Sprintf("tftest-disappears-%s", uuid.New().String()[:8])
	resourceAddr := "ciphertrust_groups.test"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name = %q
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the group.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddr, "name", groupName),
				),
			},
			{
				// Step 2: no drift immediately after create.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: delete the group out-of-band, then refresh.
				// Read() should detect 404, call RemoveResource, and the plan
				// proposes re-creation (resource is in config but gone from state).
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"disappears-test",
						common.URL_GROUP+"/"+groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_DriftDetection verifies that when a group's description is modified
// out-of-band, Read() reflects the drifted value in state, and Terraform plans a correction.
func TestAccCMGroup_DriftDetection(t *testing.T) {
	groupName := fmt.Sprintf("tftest-drift-%s", uuid.New().String()[:8])
	resourceAddr := "ciphertrust_groups.test"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name        = %q
  description = "original-description"
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create group with original description.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddr, "description", "original-description"),
				),
			},
			{
				// Step 2: no drift immediately after create.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: change description out-of-band, then refresh state.
				// Read() should hydrate the drifted value so state reflects "drifted-description".
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					updatePayload, _ := json.Marshal(map[string]string{"description": "drifted-description"})
					_, _ = client.UpdateData(
						context.Background(),
						groupName,
						common.URL_GROUP,
						updatePayload,
						"name",
					)
				},
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddr, "description", "drifted-description"),
				),
			},
			{
				// Step 4: re-plan with original config; Terraform detects drift and proposes
				// to restore description to "original-description".
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 5: apply the original config to restore clean state for teardown.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceAddr, "description", "original-description"),
				),
			},
		},
	})
}
