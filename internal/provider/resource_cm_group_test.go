package provider

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
)

// TestAccCMGroup_basic creates a group and verifies that a subsequent
// refresh produces no diff, confirming Read() round-trips all schema
// attributes correctly.
func TestAccCMGroup_basic(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping CM group acceptance test")
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroup"
  description = "basic test group"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "name"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "basic test group"),
				),
			},
			// RefreshState confirms Read() produces no diff after initial create.
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroup"
  description = "basic test group"
}
`,
				RefreshState: true,
			},
			// Update and Read testing
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "testGroup" {
  description = "Updated via TF"
  name        = "TestGroup"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "name"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "Updated via TF"),
				),
			},
		},
	})
}

// TestAccCMGroup_outOfBandDelete creates a group via Terraform, deletes it
// out-of-band, then asserts that a state refresh shows the resource as
// deleted and proposes re-create.
func TestAccCMGroup_outOfBandDelete(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping CM group out-of-band delete test")
	}
	groupName := "tf-del-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "oob_del" {
  name = "` + groupName + `"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.oob_del", "name", groupName),
				),
			},
			{
				// Delete the group out-of-band, then refresh — provider must detect
				// the 404 and remove the resource from state, causing a non-empty plan.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						"oob-delete-test",
						common.URL_GROUP+"/"+groupName,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMGroup_attributeDrift creates a group with a description, updates
// the description out-of-band, then asserts that a state refresh detects
// the drift and shows a non-empty plan.
func TestAccCMGroup_attributeDrift(t *testing.T) {
	if os.Getenv("CIPHERTRUST_ADDRESS") == "" {
		t.Skip("CIPHERTRUST_ADDRESS not set; skipping CM group attribute drift test")
	}
	groupName := "tf-drift-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_groups" "drift" {
  name        = "` + groupName + `"
  description = "original description"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.drift", "description", "original description"),
				),
			},
			{
				// Update description out-of-band, then refresh — provider must detect
				// the drift and report a non-empty plan.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload, _ := json.Marshal(map[string]string{"description": "changed-out-of-band"})
					_, _ = client.UpdateData(
						context.Background(),
						groupName,
						common.URL_GROUP,
						payload,
						"name",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
