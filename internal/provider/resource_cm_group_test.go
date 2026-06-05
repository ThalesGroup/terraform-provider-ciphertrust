package provider

import (
	"context"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

// cmGroupOOBConfig is a minimal group used by the out-of-band reconciliation
// tests (TFIN-293). A group is identified by its name.
const cmGroupOOBName = "TestGroupOOB"
const cmGroupOOBConfig = `
resource "ciphertrust_groups" "oob_group" {
  name        = "` + cmGroupOOBName + `"
  description = "managed via tf"
}
`

// TestResourceCMGroupOutOfBandDelete verifies that after a group is deleted out
// of band, Read() drops it from state and the next plan proposes to recreate it
// (TFIN-293).
func TestResourceCMGroupOutOfBandDelete(t *testing.T) {
	const groupResource = "ciphertrust_groups.oob_group"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cmGroupOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "name", cmGroupOOBName),
				),
			},
			{
				// Delete the group out of band, then refresh: Read must remove it
				// from state and propose recreate.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"tfin293-group-oob-delete",
						common.URL_GROUP+"/"+cmGroupOOBName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Recovery: re-apply to recreate the group so teardown is clean.
				Config: providerConfig + cmGroupOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "name", cmGroupOOBName),
				),
			},
		},
	})
}

// TestResourceCMGroupOutOfBandDrift verifies that an out-of-band modification of
// a managed attribute (description) is surfaced as a plan diff after refresh
// (TFIN-293).
func TestResourceCMGroupOutOfBandDrift(t *testing.T) {
	const groupResource = "ciphertrust_groups.oob_group"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cmGroupOOBConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "description", "managed via tf"),
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(
						context.Background(),
						cmGroupOOBName,
						common.URL_GROUP,
						[]byte(`{"description":"drifted out of band"}`),
						"name",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
