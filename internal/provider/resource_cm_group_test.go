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
			// Verify Read() does not corrupt state after a clean apply.
			{
				RefreshState: true,
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
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestAccCMGroup_outOfBandDelete verifies that when a group is deleted outside
// Terraform, the next refresh removes the resource from state so that a
// subsequent plan proposes recreation.
func TestAccCMGroup_outOfBandDelete(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	groupName := "tf-oob-del-" + uuid.New().String()[:8]
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name = %q
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the group via Terraform.
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.test", "id"),
				),
			},
			{
				// Step 2: delete the group out-of-band, then refresh.
				// Read() must detect the 404 and call RemoveResource, yielding a
				// non-empty plan (recreate).
				PreConfig: func() {
					_, _ = client.DeleteByURL(
						context.Background(),
						"oob-delete-"+groupName,
						common.URL_GROUP+"/"+groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_driftDetected verifies that when a group's description is
// changed outside Terraform, the next refresh picks up the new value and the
// plan shows a diff against the configuration.
func TestAccCMGroup_driftDetected(t *testing.T) {
	_, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
	}

	groupName := "tf-drift-" + uuid.New().String()[:8]
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name        = %q
  description = "tf-managed description"
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the group with a known description.
				Config: config,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", "tf-managed description"),
				),
			},
			{
				// Step 2: modify description out-of-band, then refresh.
				// Read() must return the new description in state, causing the plan
				// to show a diff against the configuration value.
				PreConfig: func() {
					c, ok := createCMClient()
					if !ok {
						return
					}
					payload, _ := json.Marshal(map[string]string{"description": "out-of-band change"})
					_, _ = c.UpdateData(context.Background(), groupName, common.URL_GROUP, payload, "name")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", "out-of-band change"),
				),
			},
		},
	})
}
