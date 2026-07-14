package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceCMUser(t *testing.T) {
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

// Test_CM_AccCMUser_NameNicknameDrift verifies OOB changes to name are detected as drift and
// that no spurious drift is introduced by the gjson-based Read fix; nickname OOB mutations
// can't be exercised directly since CM auto-sets nickname to username via PATCH.
func Test_CM_AccCMUser_NameNicknameDrift(t *testing.T) {
	RequireCM(t)

	username := fmt.Sprintf("testdrift%d", time.Now().Unix())
	var capturedUserID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "driftUser" {
  username = "%s"
  password = "CHAnge012!@#"
  name     = "Alice Example"
}
`, username)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: baseline apply with explicit name; capture user ID.
			// Also verifies nickname is stored as the API-returned username value
			// (not empty string), validating the gjson nickname fix.
			{
				Config: cfg,
				Check: checkStep(t, "Step 1: baseline create with name",
					resource.TestCheckResourceAttrSet("ciphertrust_user.driftUser", "id"),
					resource.TestCheckResourceAttr("ciphertrust_user.driftUser", "name", "Alice Example"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.driftUser", "nickname"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_user.driftUser"]
						if !ok {
							return fmt.Errorf("ciphertrust_user.driftUser not found in state")
						}
						capturedUserID = rs.Primary.ID
						nick := rs.Primary.Attributes["nickname"]
						uname := rs.Primary.Attributes["username"]
						if nick == "" {
							return fmt.Errorf("nickname is empty string in state; gjson fix should store %q", uname)
						}
						return nil
					},
				),
			},
			// Step 2: no perpetual drift immediately after apply.
			// Validates that storing nickname=username does not produce a spurious diff.
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 3: OOB change of name — plan must detect drift.
			{
				Config: cfg,
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("createCMClient failed — skipping OOB mutation")
					}
					payload, err := json.Marshal(map[string]interface{}{"name": "OOB Changed Name"})
					if err != nil {
						t.Fatalf("Step 3 PreConfig: marshal failed: %v", err)
					}
					if _, err := client.UpdateData(context.Background(), capturedUserID, common.URL_USER_MANAGEMENT, payload, "user_id"); err != nil {
						t.Fatalf("Step 3 PreConfig: UpdateData failed: %v", err)
					}
				},
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Step 4: apply to resync state after OOB name change.
			{
				Config: cfg,
			},
		},
	})
}

// Test_CM_ResourceCMUserUpdateWithoutName verifies that a user can be updated
// without providing the optional "name" field. This guards against a regression
// where the provider would send an empty name to the API, causing a 422 error.
func Test_CM_ResourceCMUserUpdateWithoutName(t *testing.T) {
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

// Test_CM_CipherTrust_CMUser_ImmutableFields verifies that username and is_domain_user
// cannot be changed after resource creation.
func Test_CM_CipherTrust_CMUser_ImmutableFields(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create baseline — username="alice-immut-test", is_domain_user omitted (default=false via schema Default)
			{
				Config: cmUserConfig("alice-immut-test"),
			},
			// Scenario A: username immutability
			{
				Config:      cmUserConfig("bob-immut-test"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
			// Scenario B: is_domain_user immutability
			// State holds is_domain_user=false (from Default); attempting to change to true fires ImmutableBool.
			{
				Config:      cmUserConfigDomain("alice-immut-test", true),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

func cmUserConfig(username string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "test" {
  username = %q
  password = "CHAnge012!@#"
}`, username)
}

func cmUserConfigDomain(username string, isDomainUser bool) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "test" {
  username       = %q
  password       = "CHAnge012!@#"
  is_domain_user = %t
}`, username, isDomainUser)
}

// checkUsersListContains verifies that the given username appears in the users list
// returned by a ciphertrust_cm_users_list data source. It scans all users.N.username
// attributes without assuming a specific index.
func checkUsersListContains(resourceName, username string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found", resourceName)
		}
		countStr := rs.Primary.Attributes["users.#"]
		var count int
		fmt.Sscanf(countStr, "%d", &count)
		for i := 0; i < count; i++ {
			if rs.Primary.Attributes[fmt.Sprintf("users.%d.username", i)] == username {
				return nil
			}
		}
		return fmt.Errorf("username %q not found in %s users list", username, resourceName)
	}
}

// Test_CM_CMUser_Idempotency verifies that a second plan after apply produces no diff,
// confirming that all Computed fields (id, user_id, email, name) are stable after create.
func Test_CM_CMUser_Idempotency(t *testing.T) {
	RequireCM(t)
	pw := os.Getenv("TF_ACC_CM_TEST_USER_PASSWORD")
	if pw == "" {
		t.Skip("TF_ACC_CM_TEST_USER_PASSWORD not set")
	}
	t.Setenv("TF_VAR_test_user_pw", pw)

	username := fmt.Sprintf("tf-idem-user-%d", time.Now().Unix())
	cfg := providerConfig + fmt.Sprintf(`
variable "test_user_pw" {
  type      = string
  sensitive = true
}
resource "ciphertrust_user" "test" {
  username = %q
  password = var.test_user_pw
  email    = "idem@example.com"
  name     = "Idempotency User"
}
`, username)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Step 1: create user",
					resource.TestCheckResourceAttrSet("ciphertrust_user.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test", "user_id"),
				),
			},
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMUser_EmailDrift verifies that an out-of-band email change is detected
// as drift on the next terraform plan, confirming the gjson email fix in Read().
func Test_CM_AccCMUser_EmailDrift(t *testing.T) {
	RequireCM(t)
	pw := os.Getenv("TF_ACC_CM_TEST_USER_PASSWORD")
	if pw == "" {
		t.Skip("TF_ACC_CM_TEST_USER_PASSWORD not set")
	}
	t.Setenv("TF_VAR_test_user_pw", pw)

	username := fmt.Sprintf("tf-email-drift-%d", time.Now().Unix())
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
variable "test_user_pw" {
  type      = string
  sensitive = true
}
resource "ciphertrust_user" "test" {
  username = %q
  password = var.test_user_pw
  email    = "original@example.com"
}
`, username)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Step 1: create user with email",
					resource.TestCheckResourceAttr("ciphertrust_user.test", "email", "original@example.com"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_user.test"]
						if !ok {
							return fmt.Errorf("ciphertrust_user.test not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				Config: cfg,
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("createCMClient failed — skipping OOB email mutation")
					}
					payload, err := json.Marshal(map[string]interface{}{"email": "drifted@example.com"})
					if err != nil {
						t.Fatalf("Step 2 PreConfig: marshal failed: %v", err)
					}
					if _, err := client.UpdateData(context.Background(), capturedID, common.URL_USER_MANAGEMENT, payload, "user_id"); err != nil {
						t.Fatalf("Step 2 PreConfig: UpdateData failed: %v", err)
					}
				},
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CMUsersListReadAccuracy verifies that a user created via ciphertrust_user
// appears in the ciphertrust_cm_users_list data source on the same apply.
func Test_CM_CMUsersListReadAccuracy(t *testing.T) {
	RequireCM(t)
	pw := os.Getenv("TF_ACC_CM_TEST_USER_PASSWORD")
	if pw == "" {
		t.Skip("TF_ACC_CM_TEST_USER_PASSWORD not set")
	}
	t.Setenv("TF_VAR_test_user_pw", pw)

	username := fmt.Sprintf("tf-list-acc-%d", time.Now().Unix())
	cfg := providerConfig + fmt.Sprintf(`
variable "test_user_pw" {
  type      = string
  sensitive = true
}
resource "ciphertrust_user" "test" {
  username = %q
  password = var.test_user_pw
  email    = "listtest@example.com"
}
data "ciphertrust_cm_users_list" "all" {
  filters = {
    username = %q
  }
  depends_on = [ciphertrust_user.test]
}
`, username, username)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Step 1: user appears in data source list",
					checkUsersListContains("data.ciphertrust_cm_users_list.all", username),
				),
			},
		},
	})
}

// Test_CM_CMUsersListStaleData verifies that after a user is deleted out-of-band,
// a state refresh reflects the deletion and the plan shows recreation.
func Test_CM_CMUsersListStaleData(t *testing.T) {
	RequireCM(t)
	pw := os.Getenv("TF_ACC_CM_TEST_USER_PASSWORD")
	if pw == "" {
		t.Skip("TF_ACC_CM_TEST_USER_PASSWORD not set")
	}
	t.Setenv("TF_VAR_test_user_pw", pw)

	username := fmt.Sprintf("tf-list-stale-%d", time.Now().Unix())
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
variable "test_user_pw" {
  type      = string
  sensitive = true
}
resource "ciphertrust_user" "test" {
  username = %q
  password = var.test_user_pw
}
data "ciphertrust_cm_users_list" "all" {
  filters = {
    username = %q
  }
  depends_on = [ciphertrust_user.test]
}
`, username, username)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Step 1: create user and capture ID",
					resource.TestCheckResourceAttrSet("ciphertrust_user.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_user.test"]
						if !ok {
							return fmt.Errorf("ciphertrust_user.test not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("createCMClient failed — skipping OOB deletion")
					}
					endpoint := common.URL_USER_MANAGEMENT + "/" + capturedID
					if _, err := client.DeleteByURL(context.Background(), capturedID, endpoint); err != nil {
						t.Fatalf("Step 2 PreConfig: DeleteByURL failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CMUsersListIdempotency verifies that consecutive data-source reads produce
// no plan diff, confirming the data source read path is stable.
func Test_CM_CMUsersListIdempotency(t *testing.T) {
	RequireCM(t)
	pw := os.Getenv("TF_ACC_CM_TEST_USER_PASSWORD")
	if pw == "" {
		t.Skip("TF_ACC_CM_TEST_USER_PASSWORD not set")
	}
	t.Setenv("TF_VAR_test_user_pw", pw)

	username := fmt.Sprintf("tf-list-idem-%d", time.Now().Unix())
	cfg := providerConfig + fmt.Sprintf(`
variable "test_user_pw" {
  type      = string
  sensitive = true
}
resource "ciphertrust_user" "test" {
  username = %q
  password = var.test_user_pw
}
data "ciphertrust_cm_users_list" "all" {
  filters = {
    username = %q
  }
  depends_on = [ciphertrust_user.test]
}
`, username, username)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Step 1: user in filtered list",
					checkUsersListContains("data.ciphertrust_cm_users_list.all", username),
				),
			},
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CMUserOutOfBandDeletion verifies that when a user is deleted directly on
// CipherTrust Manager (out-of-band), the next terraform plan/refresh removes it
// from state gracefully instead of returning a hard error.
func Test_CM_CMUserOutOfBandDeletion(t *testing.T) {
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
