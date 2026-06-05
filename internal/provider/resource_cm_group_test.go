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

// TestAccCipherTrustCMGroup_readPopulatesState verifies that Read() reconciles
// state from CipherTrust Manager rather than echoing prior state: after apply, a
// RefreshState-only step re-reads the group from CM and the refreshed attributes
// (id, name, description) remain populated in state.
func TestAccCipherTrustCMGroup_readPopulatesState(t *testing.T) {
	const groupResource = "ciphertrust_groups.readGroup"
	config := providerConfig + `
resource "ciphertrust_groups" "readGroup" {
  name        = "TFIN293ReadGroup"
  description = "read populates state"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "name", "TFIN293ReadGroup"),
					resource.TestCheckResourceAttr(groupResource, "description", "read populates state"),
				),
			},
			{
				// Refresh-only: Read() must repopulate state from the CM GET.
				RefreshState: true,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(groupResource, "id"),
					resource.TestCheckResourceAttr(groupResource, "name", "TFIN293ReadGroup"),
					resource.TestCheckResourceAttr(groupResource, "description", "read populates state"),
				),
			},
		},
	})
}

// TestAccCipherTrustCMGroup_outOfBandDelete verifies that an out-of-band deletion
// on CipherTrust Manager is detected by Read(): the 404 drops the resource from
// state (RemoveResource), so the next plan is non-empty and schedules re-creation.
func TestAccCipherTrustCMGroup_outOfBandDelete(t *testing.T) {
	const groupName = "TFIN293DeleteGroup"
	config := providerConfig + `
resource "ciphertrust_groups" "deleteGroup" {
  name = "` + groupName + `"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.TestCheckResourceAttr(
					"ciphertrust_groups.deleteGroup", "name", groupName),
			},
			{
				// Delete the group on CM out of band, then refresh.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"tfin293-oob-delete",
						common.URL_GROUP+"/"+groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMGroup_outOfBandDrift verifies attribute-level drift
// detection: mutating description directly on CM produces a non-empty plan on the
// next refresh because Read() overwrites state with the drifted value.
func TestAccCipherTrustCMGroup_outOfBandDrift(t *testing.T) {
	const groupName = "TFIN293DriftGroup"
	config := providerConfig + `
resource "ciphertrust_groups" "driftGroup" {
  name        = "` + groupName + `"
  description = "original"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.TestCheckResourceAttr(
					"ciphertrust_groups.driftGroup", "description", "original"),
			},
			{
				// Mutate description on CM out of band; the plan must show a diff
				// returning it to the configured value.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(
						context.Background(),
						groupName,
						common.URL_GROUP,
						[]byte(`{"description":"drifted"}`),
						"name",
					)
				},
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMGroup_import verifies that Read() reconstructs full state
// from scratch on import: importing by group name and verifying state round-trips
// to an empty diff.
func TestAccCipherTrustCMGroup_import(t *testing.T) {
	const groupName = "TFIN293ImportGroup"
	config := providerConfig + `
resource "ciphertrust_groups" "importGroup" {
  name        = "` + groupName + `"
  description = "import round-trip"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.TestCheckResourceAttr(
					"ciphertrust_groups.importGroup", "name", groupName),
			},
			{
				ResourceName:      "ciphertrust_groups.importGroup",
				ImportState:       true,
				ImportStateId:     groupName,
				ImportStateVerify: true,
			},
		},
	})
}
