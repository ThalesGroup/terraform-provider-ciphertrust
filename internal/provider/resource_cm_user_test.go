package provider

import (
	"context"
	"fmt"
	"testing"
	"time"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMUser(t *testing.T) {
	username := fmt.Sprintf("testuser%d", time.Now().Unix())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "testUser" {
  name     = "%s"
  email    = "%s@local"
  username = "%s"
  password = "CHange01!@"
}
`, username, username, username),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_user.testUser", "id"),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "testUser" {
  name     = "john"
  email    = "john@local"
  username = "%s"
  password = "UPdate02!@"
}
`, username),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_user.testUser", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMUserUpdateWithoutName verifies that a user can be updated
// without providing the optional "name" field. This guards against a regression
// where the provider would send an empty name to the API, causing a 422 error.
func TestResourceCMUserUpdateWithoutName(t *testing.T) {
	username := fmt.Sprintf("testuser_noname%d", time.Now().Unix())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create user with only required fields (no name)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "testUserNoName" {
  username = "%s"
  password = "CHange01!@"
}
`, username),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_user.testUserNoName", "id"),
				),
			},
			// Step 2: Update by adding email without providing name
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "testUserNoName" {
  username = "%s"
  password = "CHange01!@"
  email    = "noname@local"
}
`, username),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_user.testUserNoName", "id"),
					resource.TestCheckResourceAttr("ciphertrust_user.testUserNoName", "email", "noname@local"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestCMUserOutOfBandDeletion verifies that when a user is deleted directly on
// CipherTrust Manager (out-of-band), the next terraform plan/refresh removes it
// from state gracefully instead of returning a hard error.
func TestCMUserOutOfBandDeletion(t *testing.T) {
	username := fmt.Sprintf("tf-oob-%d", time.Now().Unix())

	deleteOutOfBand := func(resourceName string) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			rs, ok := s.RootModule().Resources[resourceName]
			if !ok {
				return fmt.Errorf("resource %s not found in state", resourceName)
			}
			id := rs.Primary.ID
			client, ok := createCMClient()
			if !ok {
				t.Skip("Skipping out-of-band deletion test: CM client could not be created (check CIPHERTRUST_* env vars)")
			}
			endpoint := common.URL_USER_MANAGEMENT + "/" + id
			if _, err := client.DeleteByURL(context.Background(), id, endpoint); err != nil {
				return fmt.Errorf("out-of-band delete failed: %s", err)
			}
			return nil
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the user, then delete it from CM directly.
			// ExpectNonEmptyPlan: true suppresses the post-step consistency
			// check failure that occurs because the OOB delete causes the
			// resource to disappear from state during the refresh check.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "test_oob" {
  username = "%s"
  password = "CHange01!@"
}
`, username),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_user.test_oob", "id"),
					deleteOutOfBand("ciphertrust_user.test_oob"),
				),
				ExpectNonEmptyPlan: true,
			},
			// Step 2: Refresh — Read() detects 404, removes from state, no error.
			// ExpectNonEmptyPlan: true because after removal the plan shows +create.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			// Step 3: Plan — user gone from state, Terraform proposes + create.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "test_oob" {
  username = "%s"
  password = "CHange01!@"
}
`, username),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
