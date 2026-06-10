package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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

// TestAccCMGroup_Read_DriftDetected verifies that an out-of-band change to the
// group description is detected on the next plan (non-empty plan), confirming
// that Read() hydrates state from the API correctly.
func TestAccCMGroup_Read_DriftDetected(t *testing.T) {
	const groupName = "TFTestDriftGroup"
	const groupResource = "ciphertrust_groups.drift_group"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "drift_group" {
  name        = %q
  description = "Initial description"
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create group with known description; verify state is populated.
				Config: config,
				Check: checkStep(t, "create group",
					resource.TestCheckResourceAttr(groupResource, "name", groupName),
					resource.TestCheckResourceAttr(groupResource, "description", "Initial description"),
					func(s *terraform.State) error {
						_, err := getResourceAttr(groupResource, "id")(s)
						return err
					},
				),
			},
			{
				// Step 2: steady-state — no out-of-band change; plan must be empty.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: mutate description out-of-band in PreConfig, then refresh.
				// Read() must detect the drift and produce a non-empty plan.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload, _ := json.Marshal(map[string]interface{}{
						"description": "Out-of-band modification",
					})
					_, _ = client.UpdateData(
						context.Background(),
						groupName,
						common.URL_CM_GROUPS,
						payload,
						groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_Read_NotFound_RemovesFromState verifies that when a group is
// deleted out-of-band, Read() detects the 404 and removes the resource from
// state, causing Terraform to plan for re-creation.
func TestAccCMGroup_Read_NotFound_RemovesFromState(t *testing.T) {
	const groupName = "TFTestNotFoundGroup"
	const groupResource = "ciphertrust_groups.not_found_group"

	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "not_found_group" {
  name = %q
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the group; verify it exists in state.
				Config: config,
				Check: checkStep(t, "create group",
					resource.TestCheckResourceAttr(groupResource, "name", groupName),
					func(s *terraform.State) error {
						_, err := getResourceAttr(groupResource, "id")(s)
						return err
					},
				),
			},
			{
				// Step 2: steady-state — no out-of-band change; plan must be empty.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Step 3: delete the group out-of-band in PreConfig, then refresh.
				// Read() must detect the 404, call RemoveResource, and Terraform
				// must plan for re-creation (non-empty plan).
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"test-delete-not-found",
						common.URL_CM_GROUPS+"/"+groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
