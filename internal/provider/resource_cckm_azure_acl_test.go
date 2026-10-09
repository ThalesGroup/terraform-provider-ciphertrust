package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const (
	azureAclVaultResourceName = "ciphertrust_azure_vault.standard_vault"
	azureAclVaultDataSource   = "data.ciphertrust_azure_vault_list.vault_ds"
	azureAclUser1Resource     = "ciphertrust_azure_acl.user1_acl"
	azureAclUser2Resource     = "ciphertrust_azure_acl.user2_acl"
	azureAclGroup1Resource    = "ciphertrust_azure_acl.group1_acl"
	azureAclGroup2Resource    = "ciphertrust_azure_acl.group2_acl"
)

// azureAclSpec describes one ciphertrust_azure_acl resource in a generated test configuration.
type azureAclSpec struct {
	name        string   // Terraform resource name, for example "user1_acl"
	subjectAttr string   // "user_id" or "group"
	subjectRef  string   // Terraform reference to the user or group id
	actions     []string // actions to grant
}

// azureAclTestConfig builds a configuration containing the base Azure config, two CipherTrust
// Manager users, two groups, the given ACL resources and a vault list data source that depends
// on every ACL resource. All ACL resources share one vault so that Terraform applies them
// concurrently, which exercises the provider's per-vault ACL locking.
func azureAclTestConfig(base, user1, user2, group1, group2 string, specs []azureAclSpec) string {
	var sb strings.Builder
	sb.WriteString(base)
	for _, u := range []struct{ res, name string }{{"user1", user1}, {"user2", user2}} {
		sb.WriteString(fmt.Sprintf(`
		resource "ciphertrust_user" "%s" {
			username = "%s"
			password = "LongPassword1234++"
		}`, u.res, u.name))
	}
	for _, g := range []struct{ res, name string }{{"group1", group1}, {"group2", group2}} {
		sb.WriteString(fmt.Sprintf(`
		resource "ciphertrust_groups" "%s" {
			name = "%s"
		}`, g.res, g.name))
	}
	deps := make([]string, 0, len(specs))
	for _, s := range specs {
		quoted := make([]string, 0, len(s.actions))
		for _, a := range s.actions {
			quoted = append(quoted, `"`+a+`"`)
		}
		sb.WriteString(fmt.Sprintf(`
		resource "ciphertrust_azure_acl" "%s" {
			vault_id = %s
			%s = %s
			actions  = [%s]
		}`, s.name, azureAclVaultResourceName+".id", s.subjectAttr, s.subjectRef, strings.Join(quoted, ", ")))
		deps = append(deps, "ciphertrust_azure_acl."+s.name)
	}
	dependsOn := ""
	if len(deps) > 0 {
		dependsOn = "depends_on = [" + strings.Join(deps, ", ") + "]"
	}
	sb.WriteString(fmt.Sprintf(`
		data "ciphertrust_azure_vault_list" "vault_ds" {
			%s
			filters = {
				name = ciphertrust_azure_vault.standard_vault.cckm_vault_name
			}
		}`, dependsOn))
	return sb.String()
}

// azureIsViewAction reports whether an action is a view-type permission. View permissions are
// accepted as extras because CipherTrust Manager requires them alongside other actions.
func azureIsViewAction(action string) bool {
	return strings.Contains(action, "view")
}

// checkAzureAclActions returns a TestCheckFunc that fetches the live vault ACL for the given
// subject (user_id or group name) and asserts two conditions:
//  1. Every action in expectedActions is present in the actual action list.
//  2. No non-view actions appear in the actual list that are absent from expectedActions.
func checkAzureAclActions(vaultID, subject *string, expectedActions []string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		actual := azureGetSubjectActions(*vaultID, *subject, false)
		if actual == nil {
			return fmt.Errorf("checkAzureAclActions: could not retrieve actions for subject %s on vault %s", *subject, *vaultID)
		}
		actualSet := make(map[string]bool, len(actual))
		for _, a := range actual {
			actualSet[a] = true
		}
		expectedSet := make(map[string]bool, len(expectedActions))
		for _, e := range expectedActions {
			expectedSet[e] = true
			if !actualSet[e] {
				return fmt.Errorf("checkAzureAclActions: expected action %q not found in actual %v", e, actual)
			}
		}
		for _, a := range actual {
			if azureIsViewAction(a) {
				continue
			}
			if !expectedSet[a] {
				return fmt.Errorf("checkAzureAclActions: unexpected non-view action %q found in actual %v (expected %v)", a, actual, expectedActions)
			}
		}
		return nil
	}
}

// checkAzureAclSubjectAbsent returns a TestCheckFunc that verifies the given subject (user_id
// or group name) no longer appears in the live vault acls array.
func checkAzureAclSubjectAbsent(vaultID, subject *string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		actual := azureGetSubjectActions(*vaultID, *subject, true)
		if actual != nil {
			return fmt.Errorf("checkAzureAclSubjectAbsent: subject %s is still present in vault %s acls with actions %v", *subject, *vaultID, actual)
		}
		return nil
	}
}

// azureGetSubjectActions fetches the vault and returns the current actions for the given subject
// from the acls array. Subject may be a user_id (for example "local|<uuid>") or a group name.
// Returns nil if the client is unavailable, the GET fails, or the subject is not found.
func azureGetSubjectActions(vaultID, subject string, expectNotFound bool) []string {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("azureGetSubjectActions: createCMClient failed")
		return nil
	}
	resp, err := client.GetById(context.Background(), "oob-get-vault-"+vaultID, vaultID, common.URL_AZURE+"/vaults")
	if err != nil {
		fmt.Printf("azureGetSubjectActions: GET vault failed: %v\n", err)
		return nil
	}
	var vaultResp struct {
		Acls []struct {
			UserID  string   `json:"user_id"`
			Group   string   `json:"group"`
			Actions []string `json:"actions"`
		} `json:"acls"`
	}
	if err := json.Unmarshal([]byte(resp), &vaultResp); err != nil {
		fmt.Printf("azureGetSubjectActions: parse failed: %v\n", err)
		return nil
	}
	for _, acl := range vaultResp.Acls {
		if acl.UserID == subject || acl.Group == subject {
			fmt.Printf("azureGetSubjectActions: found subject %s with actions %v\n", subject, acl.Actions)
			return acl.Actions
		}
	}
	if expectNotFound {
		fmt.Printf("azureGetSubjectActions: subject %s correctly not found in vault %s acls\n", subject, vaultID)
	} else {
		fmt.Printf("azureGetSubjectActions: subject %s unexpectedly not found in vault %s acls\n", subject, vaultID)
	}
	return nil
}

// azureAclOOBUpdate calls the update-acls API out-of-band for a vault user ACL entry.
// permit=true grants the given actions; permit=false revokes them (removing the user from the ACL).
func azureAclOOBUpdate(vaultID, userID string, permit bool, actions []string) {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("azureAclOOBUpdate: createCMClient failed, skipping OOB update")
		return
	}
	type aclEntry struct {
		UserID  string   `json:"user_id"`
		Permit  bool     `json:"permit"`
		Actions []string `json:"actions"`
	}
	type payload struct {
		Acls []aclEntry `json:"acls"`
	}
	body, err := json.Marshal(payload{Acls: []aclEntry{{UserID: userID, Permit: permit, Actions: actions}}})
	if err != nil {
		fmt.Printf("azureAclOOBUpdate: marshal failed: %v\n", err)
		return
	}
	_, err = client.PostDataV2(context.Background(), "oob-acl-update-"+vaultID, common.URL_AZURE+"/vaults/"+vaultID+"/update-acls", body)
	if err != nil {
		fmt.Printf("azureAclOOBUpdate: API call failed: %v\n", err)
		return
	}
	fmt.Printf("azureAclOOBUpdate: updated ACL for user %s on vault %s (permit=%v, actions=%v)\n", userID, vaultID, permit, actions)
}

// TestCckmAzureAclUsersAndGroups exercises ciphertrust_azure_acl with two users and two groups on
// one vault. CipherTrust Manager has no synchronization for ACL updates, so the four ACL resources
// are created, updated and destroyed concurrently to exercise the provider's locking.
func TestCckmAzureAclUsersAndGroups(t *testing.T) {

	baseConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureAclUsersAndGroups")
	}

	user1Name := "tf-" + uuid.New().String()[:8]
	user2Name := "tf-" + uuid.New().String()[:8]
	group1Name := "tf-" + uuid.New().String()[:8]
	group2Name := "tf-" + uuid.New().String()[:8]
	fakeVaultID := uuid.New().String()

	// Every config below is a format string. Arguments, in order:
	//   %[1]s base Azure config (connection, subscription data source, standard vault)
	//   %[2]s user1 name, %[3]s user2 name, %[4]s group1 name, %[5]s group2 name
	//   %[6]s fake vault id (only used by modifyPlanConfig)
	// Each subject gets the view action it requires plus other actions: user1 uses keys
	// (view), user2 uses secrets (secretview), group1 uses certificates (certificateview)
	// and group2 uses key templates (viewkeytemplate).

	createConfigFmt := `
		%[1]s
		resource "ciphertrust_user" "user1" {
			username = "%[2]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_user" "user2" {
			username = "%[3]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group1" {
			name = "%[4]s"
		}
		resource "ciphertrust_groups" "group2" {
			name = "%[5]s"
		}
		resource "ciphertrust_azure_acl" "user1_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			user_id  = ciphertrust_user.user1.id
			actions  = ["view", "keycreate", "keyupdate"]
		}
		resource "ciphertrust_azure_acl" "user2_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			user_id  = ciphertrust_user.user2.id
			actions  = ["secretview", "secretcreate"]
		}
		resource "ciphertrust_azure_acl" "group1_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			group    = ciphertrust_groups.group1.id
			actions  = ["certificateview", "certificatecreate"]
		}
		resource "ciphertrust_azure_acl" "group2_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			group    = ciphertrust_groups.group2.id
			actions  = ["viewkeytemplate", "createkeytemplate"]
		}
		data "ciphertrust_azure_vault_list" "vault_ds" {
			depends_on = [
				ciphertrust_azure_acl.user1_acl,
				ciphertrust_azure_acl.user2_acl,
				ciphertrust_azure_acl.group1_acl,
				ciphertrust_azure_acl.group2_acl,
			]
			filters = {
				name = ciphertrust_azure_vault.standard_vault.cckm_vault_name
			}
		}`

	addActionsConfigFmt := `
		%[1]s
		resource "ciphertrust_user" "user1" {
			username = "%[2]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_user" "user2" {
			username = "%[3]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group1" {
			name = "%[4]s"
		}
		resource "ciphertrust_groups" "group2" {
			name = "%[5]s"
		}
		resource "ciphertrust_azure_acl" "user1_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			user_id  = ciphertrust_user.user1.id
			actions  = ["view", "keycreate", "keyupdate", "keydelete"]
		}
		resource "ciphertrust_azure_acl" "user2_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			user_id  = ciphertrust_user.user2.id
			actions  = ["secretview", "secretcreate", "secretdelete"]
		}
		resource "ciphertrust_azure_acl" "group1_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			group    = ciphertrust_groups.group1.id
			actions  = ["certificateview", "certificatecreate", "certificatedelete"]
		}
		resource "ciphertrust_azure_acl" "group2_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			group    = ciphertrust_groups.group2.id
			actions  = ["viewkeytemplate", "createkeytemplate", "updatekeytemplate"]
		}
		data "ciphertrust_azure_vault_list" "vault_ds" {
			depends_on = [
				ciphertrust_azure_acl.user1_acl,
				ciphertrust_azure_acl.user2_acl,
				ciphertrust_azure_acl.group1_acl,
				ciphertrust_azure_acl.group2_acl,
			]
			filters = {
				name = ciphertrust_azure_vault.standard_vault.cckm_vault_name
			}
		}`
	createConfig := fmt.Sprintf(createConfigFmt, baseConfig, user1Name, user2Name, group1Name, group2Name, fakeVaultID)
	addActionsConfig := fmt.Sprintf(addActionsConfigFmt, baseConfig, user1Name, user2Name, group1Name, group2Name, fakeVaultID)
	// user1 is reduced to view only, group2 is removed, user2 and group1 are unchanged.
	// user1 is reduced to view only, group2_acl is removed, user2 and group1 are unchanged.
	removeActionsConfigFmt := `
		%[1]s
		resource "ciphertrust_user" "user1" {
			username = "%[2]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_user" "user2" {
			username = "%[3]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group1" {
			name = "%[4]s"
		}
		resource "ciphertrust_groups" "group2" {
			name = "%[5]s"
		}
		resource "ciphertrust_azure_acl" "user1_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			user_id  = ciphertrust_user.user1.id
			actions  = ["view"]
		}
		resource "ciphertrust_azure_acl" "user2_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			user_id  = ciphertrust_user.user2.id
			actions  = ["secretview", "secretcreate", "secretdelete"]
		}
		resource "ciphertrust_azure_acl" "group1_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			group    = ciphertrust_groups.group1.id
			actions  = ["certificateview", "certificatecreate", "certificatedelete"]
		}
		data "ciphertrust_azure_vault_list" "vault_ds" {
			depends_on = [
				ciphertrust_azure_acl.user1_acl,
				ciphertrust_azure_acl.user2_acl,
				ciphertrust_azure_acl.group1_acl,
			]
			filters = {
				name = ciphertrust_azure_vault.standard_vault.cckm_vault_name
			}
		}`

	// actions = [] must be rejected at plan time.
	emptyActionsConfigFmt := `
		%[1]s
		resource "ciphertrust_user" "user1" {
			username = "%[2]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_azure_acl" "user1_acl" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			user_id  = ciphertrust_user.user1.id
			actions  = []
		}`

	// vault_id is changed to a different value, which must be rejected at plan time.
	modifyPlanConfigFmt := `
		%[1]s
		resource "ciphertrust_user" "user1" {
			username = "%[2]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_azure_acl" "user1_acl" {
			vault_id = "%[6]s"
			user_id  = ciphertrust_user.user1.id
			actions  = ["view"]
		}`

	// All ACL resources are removed. Users and groups stay so the subjects can be checked.
	deleteAclsConfigFmt := `
		%[1]s
		resource "ciphertrust_user" "user1" {
			username = "%[2]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_user" "user2" {
			username = "%[3]s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group1" {
			name = "%[4]s"
		}
		resource "ciphertrust_groups" "group2" {
			name = "%[5]s"
		}
		data "ciphertrust_azure_vault_list" "vault_ds" {
			filters = {
				name = ciphertrust_azure_vault.standard_vault.cckm_vault_name
			}
		}`

	removeActionsConfig := fmt.Sprintf(removeActionsConfigFmt, baseConfig, user1Name, user2Name, group1Name, group2Name, fakeVaultID)
	emptyActionsConfig := fmt.Sprintf(emptyActionsConfigFmt, baseConfig, user1Name, user2Name, group1Name, group2Name, fakeVaultID)
	modifyPlanConfig := fmt.Sprintf(modifyPlanConfigFmt, baseConfig, user1Name, user2Name, group1Name, group2Name, fakeVaultID)
	deleteAclsConfig := fmt.Sprintf(deleteAclsConfigFmt, baseConfig, user1Name, user2Name, group1Name, group2Name, fakeVaultID)

	var capturedVaultID, capturedUser1ID, capturedUser2ID, capturedGroup1ID, capturedGroup2ID string

	captureIDs := resource.ComposeTestCheckFunc(
		resource.TestCheckResourceAttrWith(azureAclVaultResourceName, "id", func(val string) error {
			capturedVaultID = val
			return nil
		}),
		resource.TestCheckResourceAttrWith("ciphertrust_user.user1", "id", func(val string) error {
			capturedUser1ID = val
			return nil
		}),
		resource.TestCheckResourceAttrWith("ciphertrust_user.user2", "id", func(val string) error {
			capturedUser2ID = val
			return nil
		}),
		resource.TestCheckResourceAttrWith("ciphertrust_groups.group1", "id", func(val string) error {
			capturedGroup1ID = val
			return nil
		}),
		resource.TestCheckResourceAttrWith("ciphertrust_groups.group2", "id", func(val string) error {
			capturedGroup2ID = val
			return nil
		}),
	)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create four ACLs concurrently on one vault.
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    createConfig,
				Check: resource.ComposeTestCheckFunc(
					captureIDs,
					resource.TestCheckResourceAttrSet(azureAclUser1Resource, "id"),
					resource.TestCheckResourceAttrPair(azureAclUser1Resource, "vault_id", azureAclVaultResourceName, "id"),
					resource.TestCheckResourceAttrPair(azureAclUser1Resource, "user_id", "ciphertrust_user.user1", "id"),
					resource.TestCheckResourceAttr(azureAclUser1Resource, "actions.#", "3"),
					resource.TestCheckResourceAttr(azureAclUser2Resource, "actions.#", "2"),
					resource.TestCheckResourceAttrPair(azureAclGroup1Resource, "group", "ciphertrust_groups.group1", "id"),
					resource.TestCheckResourceAttr(azureAclGroup1Resource, "actions.#", "2"),
					resource.TestCheckResourceAttr(azureAclGroup2Resource, "actions.#", "2"),
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.#", "1"),
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.0.acls.#", "4"),
					checkAzureAclActions(&capturedVaultID, &capturedUser1ID, []string{"view", "keycreate", "keyupdate"}),
					checkAzureAclActions(&capturedVaultID, &capturedUser2ID, []string{"secretview", "secretcreate"}),
					checkAzureAclActions(&capturedVaultID, &capturedGroup1ID, []string{"certificateview", "certificatecreate"}),
					checkAzureAclActions(&capturedVaultID, &capturedGroup2ID, []string{"viewkeytemplate", "createkeytemplate"}),
				),
			},
			{
				PreConfig:    func() { logTestStep(t.Name(), "Step 2 - RefreshState") },
				RefreshState: true,
			},
			{
				PreConfig:         func() { logTestStep(t.Name(), "Step 3 - ImportState user1_acl") },
				ResourceName:      azureAclUser1Resource,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				PreConfig:         func() { logTestStep(t.Name(), "Step 4 - ImportState group1_acl") },
				ResourceName:      azureAclGroup1Resource,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Step 5: add actions to all four ACLs concurrently.
				PreConfig: func() { logTestStep(t.Name(), "Step 5") },
				Config:    addActionsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(azureAclUser1Resource, "actions.#", "4"),
					resource.TestCheckResourceAttr(azureAclUser2Resource, "actions.#", "3"),
					resource.TestCheckResourceAttr(azureAclGroup1Resource, "actions.#", "3"),
					resource.TestCheckResourceAttr(azureAclGroup2Resource, "actions.#", "3"),
					resource.TestCheckResourceAttr(azureAclVaultResourceName, "acls.#", "4"),
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.0.acls.#", "4"),
					checkAzureAclActions(&capturedVaultID, &capturedUser1ID, []string{"view", "keycreate", "keyupdate", "keydelete"}),
					checkAzureAclActions(&capturedVaultID, &capturedUser2ID, []string{"secretview", "secretcreate", "secretdelete"}),
					checkAzureAclActions(&capturedVaultID, &capturedGroup1ID, []string{"certificateview", "certificatecreate", "certificatedelete"}),
					checkAzureAclActions(&capturedVaultID, &capturedGroup2ID, []string{"viewkeytemplate", "createkeytemplate", "updatekeytemplate"}),
				),
			},
			{
				// Step 6: group2_acl is destroyed while user1_acl is reduced to view only. The
				// datasource can read before the concurrent Delete completes, so vaults.0.acls.#
				// is not asserted here. Step 7 re-reads once the operations have settled.
				PreConfig: func() { logTestStep(t.Name(), "Step 6") },
				Config:    removeActionsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(azureAclUser1Resource, "actions.#", "1"),
					checkAzureAclActions(&capturedVaultID, &capturedUser1ID, []string{"view"}),
					checkAzureAclActions(&capturedVaultID, &capturedUser2ID, []string{"secretview", "secretcreate", "secretdelete"}),
					checkAzureAclActions(&capturedVaultID, &capturedGroup1ID, []string{"certificateview", "certificatecreate", "certificatedelete"}),
					checkAzureAclSubjectAbsent(&capturedVaultID, &capturedGroup2ID),
				),
			},
			{
				// Step 7: stable-state check - three ACL entries remain.
				PreConfig: func() { logTestStep(t.Name(), "Step 7") },
				Config:    removeActionsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(azureAclVaultResourceName, "acls.#", "3"),
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.0.acls.#", "3"),
				),
			},
			{
				// Step 8: actions = [] is rejected at plan time by the schema validator.
				PreConfig:   func() { logTestStep(t.Name(), "Step 8 - PlanOnly empty actions") },
				Config:      emptyActionsConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`at least 1`),
			},
			{
				// Step 9: changing vault_id on an existing ACL is rejected at plan time.
				PreConfig:   func() { logTestStep(t.Name(), "Step 9 - PlanOnly modifyPlan") },
				Config:      modifyPlanConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Step 10: destroy all ACL resources and confirm via the live API.
				PreConfig: func() { logTestStep(t.Name(), "Step 10") },
				Config:    deleteAclsConfig,
				Check: resource.ComposeTestCheckFunc(
					testVerifyResourceDeleted(azureAclUser1Resource),
					testVerifyResourceDeleted(azureAclUser2Resource),
					testVerifyResourceDeleted(azureAclGroup1Resource),
					checkAzureAclSubjectAbsent(&capturedVaultID, &capturedUser1ID),
					checkAzureAclSubjectAbsent(&capturedVaultID, &capturedUser2ID),
					checkAzureAclSubjectAbsent(&capturedVaultID, &capturedGroup1ID),
				),
			},
			{
				// Step 11: stable-state check - the vault has no ACLs.
				PreConfig: func() { logTestStep(t.Name(), "Step 11") },
				Config:    deleteAclsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(azureAclVaultResourceName, "acls.#", "0"),
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.0.acls.#", "0"),
				),
			},
			{
				// Step 12: re-create the ACLs.
				PreConfig: func() { logTestStep(t.Name(), "Step 12") },
				Config:    createConfig,
				Check: resource.ComposeTestCheckFunc(
					captureIDs,
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.0.acls.#", "4"),
					checkAzureAclActions(&capturedVaultID, &capturedUser1ID, []string{"view", "keycreate", "keyupdate"}),
					checkAzureAclActions(&capturedVaultID, &capturedGroup2ID, []string{"viewkeytemplate", "createkeytemplate"}),
				),
			},
		},
	})
}

// TestCckmAzureAclOOB verifies out-of-band detection for ciphertrust_azure_acl:
//  1. OOB modification: the ACL actions are changed outside Terraform; RefreshState detects
//     drift (non-empty plan) and a subsequent apply restores the configured actions.
//  2. OOB deletion: the user is removed from the vault ACL outside Terraform; RefreshState
//     returns an error diagnostic and the state is preserved.
func TestCckmAzureAclOOB(t *testing.T) {

	baseConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureAclOOB")
	}

	oobConfig := azureAclTestConfig(baseConfig,
		"tf-"+uuid.New().String()[:8], "tf-"+uuid.New().String()[:8],
		"tf-"+uuid.New().String()[:8], "tf-"+uuid.New().String()[:8],
		[]azureAclSpec{{
			name:        "user1_acl",
			subjectAttr: "user_id",
			subjectRef:  "ciphertrust_user.user1.id",
			actions:     []string{"view", "keycreate", "keydelete"},
		}})

	var capturedVaultID, capturedUserID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the ACL and capture vault_id and user_id for OOB calls.
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    oobConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(azureAclUser1Resource, "id"),
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.0.acls.#", "1"),
					resource.TestCheckResourceAttrWith(azureAclVaultResourceName, "id", func(val string) error {
						capturedVaultID = val
						return nil
					}),
					resource.TestCheckResourceAttrWith("ciphertrust_user.user1", "id", func(val string) error {
						capturedUserID = val
						return nil
					}),
					checkAzureAclActions(&capturedVaultID, &capturedUserID, []string{"view", "keycreate", "keydelete"}),
				),
			},
			{
				// Step 2: OOB modify - reduce the user's actions to view only. RefreshState
				// detects drift from the configured actions.
				PreConfig: func() {
					logTestStep(t.Name(), "Step 2")
					azureAclOOBUpdate(capturedVaultID, capturedUserID, true, []string{"view"})
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: apply the original config to restore the configured actions.
				PreConfig: func() { logTestStep(t.Name(), "Step 3") },
				Config:    oobConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(azureAclVaultDataSource, "vaults.0.acls.#", "1"),
					checkAzureAclActions(&capturedVaultID, &capturedUserID, []string{"view", "keycreate", "keydelete"}),
				),
			},
			{
				// Step 4: OOB delete - revoke all of the user's actions. RefreshState must
				// surface an error because the user is no longer in the vault acls array.
				PreConfig: func() {
					logTestStep(t.Name(), "Step 4")
					allActions := azureGetSubjectActions(capturedVaultID, capturedUserID, false)
					azureAclOOBUpdate(capturedVaultID, capturedUserID, false, allActions)
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`Azure vault ACL was not found`),
			},
		},
	})
}
