package provider

import (
	"context"
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

// TestAccCMGroup_ReadNotFound verifies that when a group is deleted out-of-band,
// a subsequent refresh removes it from state and a plan shows it as to-be-created.
func TestAccCMGroup_ReadNotFound(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("CM credentials not set; skipping")
	}
	groupName := "tf-grp-" + uuid.New().String()[:8]
	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name = %q
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create the group via Terraform.
			{
				Config: cfg,
				Check:  resource.TestCheckResourceAttr("ciphertrust_groups.test", "name", groupName),
			},
			// Step 2: delete the group out-of-band, then refresh — Read() must remove it from state.
			{
				PreConfig: func() {
					_, _ = client.DeleteByURL(
						context.Background(),
						"delete-group-recovery-test",
						common.URL_GROUP+"/"+groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_ReadAttributeDrift verifies that Read() detects and records
// attribute drift when a group's description is changed out-of-band.
func TestAccCMGroup_ReadAttributeDrift(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("CM credentials not set; skipping")
	}
	groupName := "tf-grp-" + uuid.New().String()[:8]
	origDesc := "original description"
	driftDesc := "drifted description"

	cfgOrig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "test" {
  name        = %q
  description = %q
}
`, groupName, origDesc)

	cfgOrig2 := cfgOrig // same config for step 3 to assert plan diff

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create the group with a known description.
			{
				Config: cfgOrig,
				Check:  resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", origDesc),
			},
			// Step 2: update description out-of-band, then refresh — Read() must record the drift.
			{
				PreConfig: func() {
					payload := []byte(fmt.Sprintf(`{"description":%q}`, driftDesc))
					_, _ = client.UpdateData(
						context.Background(),
						groupName,
						common.URL_GROUP,
						payload,
						"name",
					)
				},
				RefreshState: true,
				Check: resource.TestCheckResourceAttr("ciphertrust_groups.test", "description", driftDesc),
			},
			// Step 3: apply original config — plan must show a change to description.
			{
				Config:             cfgOrig2,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
