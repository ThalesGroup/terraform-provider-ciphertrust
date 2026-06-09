package cm_test

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	provider "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const groupResource = "ciphertrust_groups.testGroup"

const cmGroupProviderConfig = `
provider "ciphertrust" {
	address      = "https://192.168.2.135"
	username     = "admin"
	password     = "ChangeIt01!"
	bootstrap    = "no"
	domain       = "root"
	auth_domain  = "root"
}
`

var testAccCMGroupProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"ciphertrust": providerserver.NewProtocol6WithError(provider.New("ciphertrust")()),
}

// createCMGroupClient constructs a common.Client from standard CIPHERTRUST_* environment
// variables. Returns (client, true) on success or (nil, false) when vars are missing.
func createCMGroupClient() (*common.Client, bool) {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	if address == "" || username == "" || password == "" {
		fmt.Println("createCMGroupClient: CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME and CIPHERTRUST_PASSWORD must be set")
		return nil, false
	}
	var domain string
	authDomain := os.Getenv("CIPHERTRUST_AUTH_DOMAIN")
	if os.Getenv("CTAAS") != "true" {
		domain = os.Getenv("CIPHERTRUST_DOMAIN")
	}
	client, err := common.NewClient(context.Background(), uuid.NewString(), &address, &authDomain, &domain, &username, &password, true, 180)
	if err != nil {
		fmt.Printf("createCMGroupClient: failed to create client: %s\n", err.Error())
		return nil, false
	}
	return client, true
}

// getCMGroupResourceAttr returns an ImportStateIdFunc that reads the named attribute
// from resourceName in the current Terraform state.
func getCMGroupResourceAttr(resourceName, attrName string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("not found: %s", resourceName)
		}
		val, ok := rs.Primary.Attributes[attrName]
		if !ok {
			return "", fmt.Errorf("attribute %q not found in state for %s", attrName, resourceName)
		}
		return val, nil
	}
}

func TestResourceCMGroup_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccCMGroupProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroup"
  description = "Created via TF"
  app_metadata = {
    env = "test"
  }
  client_metadata = {
    tier = "free"
  }
  user_metadata = {
    owner = "tftest"
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(groupResource, "id"),
					resource.TestCheckResourceAttr(groupResource, "name", "TestGroup"),
					resource.TestCheckResourceAttr(groupResource, "description", "Created via TF"),
					resource.TestCheckResourceAttr(groupResource, "app_metadata.env", "test"),
					resource.TestCheckResourceAttr(groupResource, "client_metadata.tier", "free"),
					resource.TestCheckResourceAttr(groupResource, "user_metadata.owner", "tftest"),
				),
			},
			// Idempotency check — identical config must plan with no changes.
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroup"
  description = "Created via TF"
  app_metadata = {
    env = "test"
  }
  client_metadata = {
    tier = "free"
  }
  user_metadata = {
    owner = "tftest"
  }
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestResourceCMGroup_update_in_place(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccCMGroupProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroupUpdate"
  description = "initial"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "description", "initial"),
				),
			},
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroupUpdate"
  description = "updated"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "description", "updated"),
				),
			},
			// Idempotency: no further changes after update.
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroupUpdate"
  description = "updated"
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestResourceCMGroup_import(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccCMGroupProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name        = "TestGroupImport"
  description = "import test"
  app_metadata = {
    key = "value"
  }
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(groupResource, "id"),
					resource.TestCheckResourceAttr(groupResource, "name", "TestGroupImport"),
					resource.TestCheckResourceAttr(groupResource, "description", "import test"),
					resource.TestCheckResourceAttr(groupResource, "app_metadata.key", "value"),
				),
			},
			{
				ResourceName:      groupResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: getCMGroupResourceAttr(groupResource, "id"),
			},
		},
	})
}

func TestResourceCMGroup_drift_field_change(t *testing.T) {
	var capturedGroupID string
	groupName := "TestGroupDriftField"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccCMGroupProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupProviderConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "testGroup" {
  name        = %q
  description = "original"
}
`, groupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(groupResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[groupResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", groupResource)
						}
						capturedGroupID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band: modify description via CM API directly, bypassing Terraform.
				PreConfig: func() {
					if capturedGroupID == "" {
						return
					}
					client, ok := createCMGroupClient()
					if !ok {
						return
					}
					_, _ = client.UpdateDataV2(
						context.Background(),
						capturedGroupID,
						common.URL_GROUP,
						[]byte(`{"description":"out-of-band modified"}`),
					)
				},
				Config: cmGroupProviderConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "testGroup" {
  name        = %q
  description = "original"
}
`, groupName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestResourceCMGroup_drift_deletion(t *testing.T) {
	var capturedGroupID string
	groupName := "TestGroupDriftDelete"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccCMGroupProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupProviderConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "testGroup" {
  name = %q
}
`, groupName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(groupResource, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[groupResource]
						if !ok {
							return fmt.Errorf("resource %s not found in state", groupResource)
						}
						capturedGroupID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band: delete the group directly via CM API, bypassing Terraform.
				// The next plan must detect the deletion and propose recreation.
				PreConfig: func() {
					if capturedGroupID == "" {
						return
					}
					client, ok := createCMGroupClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.New().String(),
						common.URL_GROUP+"/"+capturedGroupID,
					)
				},
				Config: cmGroupProviderConfig + fmt.Sprintf(`
resource "ciphertrust_groups" "testGroup" {
  name = %q
}
`, groupName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestResourceCMGroup_users_membership(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccCMGroupProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create group with two pre-existing test users; verify both appear in state.
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name  = "TestGroupUsers"
  users = ["user1", "user2"]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(groupResource, "id"),
					resource.TestCheckResourceAttr(groupResource, "users.#", "2"),
					resource.TestCheckResourceAttr(groupResource, "users.0", "user1"),
					resource.TestCheckResourceAttr(groupResource, "users.1", "user2"),
				),
			},
			// Step 2: remove one user; verify state reflects reduced membership.
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name  = "TestGroupUsers"
  users = ["user1"]
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(groupResource, "users.#", "1"),
					resource.TestCheckResourceAttr(groupResource, "users.0", "user1"),
				),
			},
			// Step 3: idempotency — no further changes.
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name  = "TestGroupUsers"
  users = ["user1"]
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestResourceCMGroup_read_nonexistent_id verifies Read() handles a non-existent group ID.
// Importing with a random UUID triggers Read() which receives a 404, calls RemoveResource,
// and the framework surfaces an error because the import produced no state.
func TestResourceCMGroup_read_nonexistent_id(t *testing.T) {
	nonExistentID := uuid.New().String()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccCMGroupProviderFactories,
		Steps: []resource.TestStep{
			// First create a real group so the resource type is known to the framework.
			{
				Config: cmGroupProviderConfig + `
resource "ciphertrust_groups" "testGroup" {
  name = "TestGroupNonExistent"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(groupResource, "id"),
				),
			},
			// Import with a non-existent UUID; Read() should detect 404, remove from state.
			// The framework surfaces an error because the import produced no state.
			{
				ResourceName:  groupResource,
				ImportState:   true,
				ImportStateId: nonExistentID,
				ExpectError:   regexp.MustCompile(`.`),
			},
		},
	})
}
