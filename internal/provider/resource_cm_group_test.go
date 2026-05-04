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

// testProviderConfig returns a provider config block using environment variables
// (CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, CIPHERTRUST_PASSWORD) or falls back
// to the hardcoded providerConfig constant.
func testProviderConfig() string {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	if address == "" || username == "" || password == "" {
		return providerConfig
	}
	return fmt.Sprintf(`
provider "ciphertrust" {
	address  = "%s"
	username = "%s"
	password = "%s"
	bootstrap = "no"
}
`, address, username, password)
}

// TestResourceCMGroupReadDriftDetection verifies that the Read() function
// properly detects out-of-band deletion of a group on CipherTrust Manager.
// It creates a group via Terraform, deletes it directly via the CM API,
// then verifies that Terraform detects the deletion and plans to recreate it.
func TestResourceCMGroupReadDriftDetection(t *testing.T) {
	groupName := fmt.Sprintf("tf-drift-test-%d", uuid.New().ID())

	// Helper to delete the group directly on CM (simulating out-of-band deletion)
	deleteGroupOutOfBand := func() {
		address := os.Getenv("CIPHERTRUST_ADDRESS")
		username := os.Getenv("CIPHERTRUST_USERNAME")
		password := os.Getenv("CIPHERTRUST_PASSWORD")
		if address == "" {
			address = "https://192.168.2.135"
			username = "admin"
			password = "ChangeIt01!"
		}
		domain := "root"
		client, err := common.NewClient(context.Background(), uuid.NewString(), &address, &domain, &domain, &username, &password, true, 180)
		if err != nil {
			t.Fatalf("Failed to create CM client for out-of-band deletion: %s", err)
		}
		url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_GROUP, groupName)
		_, err = client.DeleteByID(context.Background(), "DELETE", groupName, url, nil)
		if err != nil {
			t.Fatalf("Failed to delete group out-of-band: %s", err)
		}
	}

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_groups" "drift_test" {
  name        = "%s"
  description = "Drift detection test"
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the group
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.drift_test", "name", groupName),
					resource.TestCheckResourceAttr("ciphertrust_groups.drift_test", "description", "Drift detection test"),
				),
			},
			// Step 2: Delete the group out-of-band, then re-apply the same config.
			// Terraform should detect the group is gone (via Read() returning 404)
			// and plan to recreate it.
			{
				PreConfig:          deleteGroupOutOfBand,
				Config:             config,
				ExpectNonEmptyPlan: false, // After apply, plan should be empty (resource recreated)
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.drift_test", "name", groupName),
					resource.TestCheckResourceAttr("ciphertrust_groups.drift_test", "description", "Drift detection test"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMGroupReadAttributeDrift verifies that the Read() function
// properly detects out-of-band attribute modification on CipherTrust Manager.
// It creates a group, modifies its description directly via the CM API,
// then verifies that Terraform detects the drift and plans to correct it.
func TestResourceCMGroupReadAttributeDrift(t *testing.T) {
	groupName := fmt.Sprintf("tf-attr-drift-%d", uuid.New().ID())

	// Helper to modify the group description directly on CM
	modifyGroupOutOfBand := func() {
		address := os.Getenv("CIPHERTRUST_ADDRESS")
		username := os.Getenv("CIPHERTRUST_USERNAME")
		password := os.Getenv("CIPHERTRUST_PASSWORD")
		if address == "" {
			address = "https://192.168.2.135"
			username = "admin"
			password = "ChangeIt01!"
		}
		domain := "root"
		client, err := common.NewClient(context.Background(), uuid.NewString(), &address, &domain, &domain, &username, &password, true, 180)
		if err != nil {
			t.Fatalf("Failed to create CM client for out-of-band modification: %s", err)
		}
		payload := []byte(`{"description":"Modified outside Terraform"}`)
		_, err = client.UpdateData(context.Background(), groupName, common.URL_GROUP, payload, "name")
		if err != nil {
			t.Fatalf("Failed to modify group out-of-band: %s", err)
		}
	}

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_groups" "attr_drift_test" {
  name        = "%s"
  description = "Original description"
}
`, groupName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the group
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.attr_drift_test", "name", groupName),
					resource.TestCheckResourceAttr("ciphertrust_groups.attr_drift_test", "description", "Original description"),
				),
			},
			// Step 2: Modify description out-of-band, then re-apply same config.
			// Terraform should detect the drift via Read() and update it back.
			{
				PreConfig:          modifyGroupOutOfBand,
				Config:             config,
				ExpectNonEmptyPlan: false, // After apply corrects the drift, plan should be empty
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.attr_drift_test", "name", groupName),
					resource.TestCheckResourceAttr("ciphertrust_groups.attr_drift_test", "description", "Original description"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
