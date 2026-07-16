package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
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
  password = "CHAnge012!@#"
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
  password = "CHAnge012!@#"
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
  password = "CHAnge012!@#"
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
  password = "CHAnge012!@#"
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

// requireCMTestUserPassword reads TF_ACC_CM_TEST_USER_PASSWORD and skips the test
// if the variable is not set.
func requireCMTestUserPassword(t *testing.T) string {
	t.Helper()
	pwd := os.Getenv("TF_ACC_CM_TEST_USER_PASSWORD")
	if pwd == "" {
		t.Skip("TF_ACC_CM_TEST_USER_PASSWORD not set")
	}
	return pwd
}

// cmUserConfigFull returns HCL for a ciphertrust_user resource with username, email,
// and password supplied via TF_VAR_test_user_password (never interpolated into the
// config string to avoid plaintext logging by the testing framework).
func cmUserConfigFull(username, email string) string {
	return providerConfig + fmt.Sprintf(`
variable "test_user_password" { sensitive = true }

resource "ciphertrust_user" "test" {
  username = %q
  email    = %q
  password = var.test_user_password
}`, username, email)
}

// cmUserConfigWithMetadata returns HCL for a ciphertrust_user resource that includes
// user_metadata so the metadata Bug 2/4 fix can be validated.
func cmUserConfigWithMetadata(username, email string) string {
	return providerConfig + fmt.Sprintf(`
variable "test_user_password" { sensitive = true }

resource "ciphertrust_user" "test" {
  username      = %q
  email         = %q
  password      = var.test_user_password
  user_metadata = { "env" = "test" }
}`, username, email)
}

// cmUsersListConfig returns HCL for a ciphertrust_user resource plus a
// ciphertrust_cm_users_list data source scoped to that exact user.
func cmUsersListConfig(username, email string) string {
	return providerConfig + fmt.Sprintf(`
variable "test_user_password" { sensitive = true }

resource "ciphertrust_user" "test" {
  username = %q
  email    = %q
  password = var.test_user_password
}

data "ciphertrust_cm_users_list" "test" {
  depends_on = [ciphertrust_user.test]
  filters    = { username = %q }
}`, username, email, username)
}

// cmUsersListConfigDataSourceOnly returns HCL for just the data source (no user
// resource). Used in stale-data tests so the data source is not deferred during
// planning due to a depends_on on a resource being created.
func cmUsersListConfigDataSourceOnly(username string) string {
	return providerConfig + fmt.Sprintf(`
data "ciphertrust_cm_users_list" "test" {
  filters = { username = %q }
}`, username)
}

// Test_CM_User_Idempotency verifies no spurious drift (null→"" for email,
// null→{} for user_metadata) when user_metadata is not configured.
func Test_CM_User_Idempotency(t *testing.T) {
	RequireCM(t)
	pwd := requireCMTestUserPassword(t)
	t.Setenv("TF_VAR_test_user_password", pwd)

	username := fmt.Sprintf("tf-idem-%d", time.Now().Unix())
	email := username + "@example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: apply; id and user_id must be set.
			{
				Config: cmUserConfigFull(username, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_user.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test", "user_id"),
				),
			},
			// Step 2: second plan must be empty (no null→"" email drift, no null→{} metadata drift).
			{
				Config:             cmUserConfigFull(username, email),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_User_Idempotency_WithMetadata verifies no spurious drift when
// user_metadata is configured — confirms Bug 2 fix prevents empty-map drift.
func Test_CM_User_Idempotency_WithMetadata(t *testing.T) {
	RequireCM(t)
	pwd := requireCMTestUserPassword(t)
	t.Setenv("TF_VAR_test_user_password", pwd)

	username := fmt.Sprintf("tf-meta-%d", time.Now().Unix())
	email := username + "@example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: apply with metadata; verify env key is present.
			{
				Config: cmUserConfigWithMetadata(username, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_user.test", "user_metadata.env", "test"),
				),
			},
			// Step 2: second plan must be empty (no empty-map drift).
			{
				Config:             cmUserConfigWithMetadata(username, email),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_User_DriftDetection creates a user, patches email/name/nickname
// out-of-band, then asserts that Read() surfaces all three as drift.
func Test_CM_User_DriftDetection(t *testing.T) {
	RequireCM(t)
	pwd := requireCMTestUserPassword(t)
	t.Setenv("TF_VAR_test_user_password", pwd)

	username := fmt.Sprintf("tf-drift-%d", time.Now().Unix())
	email := username + "@example.com"

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: apply; capture user ID.
			{
				Config: cmUserConfigFull(username, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_user.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test", "user_id"),
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
			// Step 2: mutate email, name, and nickname out-of-band; RefreshState must
			// detect the drift and produce a non-empty plan.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("createCMClient unavailable — CM must be reachable if RequireCM(t) passed")
					}
					payload, err := json.Marshal(map[string]interface{}{
						"email":    "drifted@example.com",
						"name":     "Drifted Name",
						"nickname": "driftednick",
					})
					if err != nil {
						t.Fatalf("Step 2 PreConfig: marshal failed: %v", err)
					}
					if _, err := client.UpdateData(context.Background(), capturedID, common.URL_USER_MANAGEMENT, payload, "user_id"); err != nil {
						t.Fatalf("Step 2 PreConfig: UpdateData failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CMUsersListReadAccuracy validates that the ciphertrust_cm_users_list
// data source returns the created user (Step 1) and that consecutive reads
// produce no plan diff (Step 2).
func Test_CM_CMUsersListReadAccuracy(t *testing.T) {
	RequireCM(t)
	pwd := requireCMTestUserPassword(t)
	t.Setenv("TF_VAR_test_user_password", pwd)

	username := fmt.Sprintf("tf-dsl-%d", time.Now().Unix())
	email := username + "@example.com"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: read accuracy — data source must surface the created user.
			{
				Config: cmUsersListConfig(username, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.test", "users.#", "1"),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.test", "users.0.username", username),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.test", "users.0.email", email),
				),
			},
			// Step 2: idempotency — consecutive read must produce no plan diff.
			{
				Config:             cmUsersListConfig(username, email),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CMUsersListStaleData creates a user, deletes it out-of-band, and
// verifies that the data source reflects the deletion; then recreates the user
// and asserts the data source returns one result again.
func Test_CM_CMUsersListStaleData(t *testing.T) {
	RequireCM(t)
	pwd := requireCMTestUserPassword(t)
	t.Setenv("TF_VAR_test_user_password", pwd)

	username := fmt.Sprintf("tf-stale-%d", time.Now().Unix())
	email := username + "@example.com"

	var capturedUserID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: apply and verify data source returns one user; capture the user ID.
			{
				Config: cmUsersListConfig(username, email),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.test", "users.#", "1"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_user.test"]
						if !ok {
							return fmt.Errorf("ciphertrust_user.test not found in state")
						}
						capturedUserID = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: delete the user out-of-band; refresh state so ciphertrust_user.test
			// leaves state (Read() hits 404 → RemoveResource). ExpectNonEmptyPlan: true
			// because after removal the plan proposes re-creating the user.
			// NOTE: RefreshState steps must NOT have a Config field.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("createCMClient unavailable — CM must be reachable if RequireCM(t) passed")
					}
					deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_USER_MANAGEMENT, capturedUserID)
					if _, err := client.DeleteByID(context.Background(), "DELETE", capturedUserID, deleteURL, nil); err != nil {
						t.Fatalf("Step 2 PreConfig: DeleteByID failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			// Step 3: verify data source reflects deletion — returns 0 users.
			// Uses the full config so the plan proposes re-creating ciphertrust_user.test
			// (ExpectNonEmptyPlan: true). The data source is deferred due to depends_on
			// on the resource being created, so its prior state value (users.# = "0",
			// set during Step 2's refresh) is preserved in the planned state.
			{
				Config:             cmUsersListConfig(username, email),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
				Check:              resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.test", "users.#", "0"),
			},
			// Step 4: full apply recreates the user; data source returns 1 again.
			{
				Config: cmUsersListConfig(username, email),
				Check:  resource.TestCheckResourceAttr("data.ciphertrust_cm_users_list.test", "users.#", "1"),
			},
		},
	})
}

func testAccCMUserUseStateForUnknownCheckDestroy(userID *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		client, ok := createCMClient()
		if !ok {
			return fmt.Errorf("could not create CM client for CheckDestroy")
		}
		_, err := client.GetById(context.Background(), "", *userID, common.URL_USER_MANAGEMENT)
		if err != nil && strings.Contains(err.Error(), "status: 404") {
			return nil
		}
		if err != nil {
			return fmt.Errorf("unexpected error checking user destruction: %w", err)
		}
		return fmt.Errorf("user %s still exists in CM after destroy", *userID)
	}
}

// TestAccCMUser_UseStateForUnknown verifies that email, name, and nickname
// remain stable known values in the plan (not "(known after apply)") when another
// attribute has a pending change, confirming UseStateForUnknown() is effective.
func TestAccCMUser_UseStateForUnknown(t *testing.T) {
	RequireCM(t)

	username := fmt.Sprintf("tf-usfu-%d", time.Now().Unix())
	var capturedUserID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy:             testAccCMUserUseStateForUnknownCheckDestroy(&capturedUserID),
		Steps: []resource.TestStep{
			// Step 1: Create with username/password only; CM auto-populates email/name/nickname.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "test_user" {
  username = %q
  password = "CHAnge012!@#"
}`, username),
				Check: checkStep(t, "Step 1: create, CM auto-populates email/name/nickname",
					resource.TestCheckResourceAttrSet("ciphertrust_user.test_user", "email"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test_user", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test_user", "nickname"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_user.test_user"]
						if !ok {
							return fmt.Errorf("ciphertrust_user.test_user not found in state")
						}
						capturedUserID = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: Apply prevent_ui_login=true (unrelated change). PreApply checks verify
			// that email/name/nickname are known values in the plan — not "(known after apply)".
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "test_user" {
  username         = %q
  password         = "CHAnge012!@#"
  prevent_ui_login = true
}`, username),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(
							"ciphertrust_user.test_user",
							tfjsonpath.New("email"),
							knownvalue.StringRegexp(regexp.MustCompile(`.+`)),
						),
						plancheck.ExpectKnownValue(
							"ciphertrust_user.test_user",
							tfjsonpath.New("name"),
							knownvalue.StringRegexp(regexp.MustCompile(`.+`)),
						),
						plancheck.ExpectKnownValue(
							"ciphertrust_user.test_user",
							tfjsonpath.New("nickname"),
							knownvalue.StringRegexp(regexp.MustCompile(`.+`)),
						),
					},
				},
				Check: checkStep(t, "Step 2: apply prevent_ui_login=true; email/name/nickname still set",
					resource.TestCheckResourceAttr("ciphertrust_user.test_user", "prevent_ui_login", "true"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test_user", "email"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test_user", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_user.test_user", "nickname"),
				),
			},
			// Step 3: Idempotency — no drift after apply.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_user" "test_user" {
  username         = %q
  password         = "CHAnge012!@#"
  prevent_ui_login = true
}`, username),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 4: OOB name change; RefreshState confirms Read() updates state correctly,
			// verifying UseStateForUnknown() does not suppress Read()-based drift detection.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("Step 4 PreConfig: createCMClient failed — skipping OOB mutation")
						return
					}
					payload, err := json.Marshal(map[string]interface{}{"name": "changed-out-of-band"})
					if err != nil {
						t.Logf("Step 4 PreConfig: marshal failed: %v", err)
						return
					}
					if _, err := client.UpdateData(context.Background(), capturedUserID, common.URL_USER_MANAGEMENT, payload, "user_id"); err != nil {
						t.Logf("Step 4 PreConfig: UpdateData failed: %v", err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
				Check: checkStep(t, "Step 4: refreshed state reflects OOB name change",
					resource.TestCheckResourceAttr("ciphertrust_user.test_user", "name", "changed-out-of-band"),
				),
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
  password = "CHAnge012!@#"
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
  password = "CHAnge012!@#"
}
`, username),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
