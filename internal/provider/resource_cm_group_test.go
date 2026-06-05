package provider

import (
	"context"
	"fmt"
	"os"
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

// TestAccCipherTrustCMGroup_outOfBandDelete verifies that after a ciphertrust_groups
// resource is deleted out-of-band on CipherTrust Manager, a refresh detects the
// deletion and the next plan proposes recreation (TFIN-293). CM groups are keyed
// by name, so the resource id is the group name.
func TestAccCipherTrustCMGroup_outOfBandDelete(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping out-of-band test")
	}

	groupResource := "ciphertrust_groups.oob_group"
	groupName := "tf-oob-grp-" + uuid.New().String()[:8]
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "oob_group" {
  name = "%s"
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the group.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "name", groupName),
				),
			},
			{
				// Step 2: delete the group out-of-band, then refresh. Read() must
				// detect the 404, drop the group from state, producing a non-empty
				// plan (group is in config but gone from state -> recreate).
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"cm-group-oob-delete-test",
						common.URL_GROUP+"/"+groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: re-apply to recover the group.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "name", groupName),
				),
			},
		},
	})
}
