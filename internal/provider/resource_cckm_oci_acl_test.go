package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// checkOCIAclActions returns a TestCheckFunc that fetches the live vault ACL for the given
// subject (user_id or group name) and asserts two conditions:
//  1. Every action in expectedActions is present in the actual action list.
//  2. No non-view actions appear in the actual list that are absent from expectedActions.
//     View-prefixed actions are accepted as extras (e.g. "view", "viewhyokkey").
func checkOCIAclActions(vaultID, subject *string, expectedActions []string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		actual := ociGetSubjectActions(*vaultID, *subject, false)
		if actual == nil {
			return fmt.Errorf("checkOCIAclActions: could not retrieve actions for subject %s on vault %s", *subject, *vaultID)
		}
		actualSet := make(map[string]bool, len(actual))
		for _, a := range actual {
			actualSet[a] = true
		}
		for _, exp := range expectedActions {
			if !actualSet[exp] {
				return fmt.Errorf("checkOCIAclActions: expected action %q not found in actual %v", exp, actual)
			}
		}
		expectedSet := make(map[string]bool, len(expectedActions))
		for _, e := range expectedActions {
			expectedSet[e] = true
		}
		for _, a := range actual {
			if strings.HasPrefix(a, "view") {
				continue
			}
			if !expectedSet[a] {
				return fmt.Errorf("checkOCIAclActions: unexpected non-view action %q found in actual %v (expected %v)", a, actual, expectedActions)
			}
		}
		return nil
	}
}

// checkOCIAclSubjectAbsent returns a TestCheckFunc that verifies the given subject (user_id
// or group name) no longer appears in the live vault acls array.
func checkOCIAclSubjectAbsent(vaultID, subject *string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		actual := ociGetSubjectActions(*vaultID, *subject, true)
		if actual != nil {
			return fmt.Errorf("checkOCIAclSubjectAbsent: subject %s is still present in vault %s acls with actions %v", *subject, *vaultID, actual)
		}
		return nil
	}
}

// ociGetSubjectActions fetches the vault and returns the current actions for the given subject
// from the acls array. Subject may be a user_id (e.g. "local|<uuid>") or a group name.
// expectNotFound controls whether a missing subject is logged as "correctly" or "unexpectedly"
// not found. Returns nil if the client is unavailable, the GET fails, or the subject is not found.
func ociGetSubjectActions(vaultID, subject string, expectNotFound bool) []string {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("ociGetSubjectActions: createCMClient failed")
		return nil
	}
	resp, err := client.GetById(context.Background(), "oob-get-vault-"+vaultID, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		fmt.Printf("ociGetSubjectActions: GET vault failed: %v\n", err)
		return nil
	}
	fmt.Printf("ociGetSubjectActions: vault acls JSON: %s\n", resp)
	var vaultResp struct {
		Acls []struct {
			UserID  string   `json:"user_id"`
			Group   string   `json:"group"`
			Actions []string `json:"actions"`
		} `json:"acls"`
	}
	if err := json.Unmarshal([]byte(resp), &vaultResp); err != nil {
		fmt.Printf("ociGetSubjectActions: parse failed: %v\n", err)
		return nil
	}
	for _, acl := range vaultResp.Acls {
		if acl.UserID == subject || acl.Group == subject {
			fmt.Printf("ociGetSubjectActions: found subject %s with actions %v\n", subject, acl.Actions)
			return acl.Actions
		}
	}
	if expectNotFound {
		fmt.Printf("ociGetSubjectActions: subject %s correctly not found in vault %s acls\n", subject, vaultID)
	} else {
		fmt.Printf("ociGetSubjectActions: subject %s unexpectedly not found in vault %s acls\n", subject, vaultID)
	}
	return nil
}

// ociAclOOBUpdate calls the update-acls API out-of-band for a vault user ACL entry.
// permit=true grants the given actions; permit=false revokes them (removing the user from the ACL).
func ociAclOOBUpdate(vaultID, userID string, permit bool, actions []string) {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("ociAclOOBUpdate: createCMClient failed, skipping OOB update")
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
		fmt.Printf("ociAclOOBUpdate: marshal failed: %v\n", err)
		return
	}
	resp, err := client.PostDataV2(context.Background(), "oob-acl-update-"+vaultID, common.URL_OCI+"/vaults/"+vaultID+"/update-acls", body)
	if err != nil {
		fmt.Printf("ociAclOOBUpdate: API call failed: %v\n", err)
	} else {
		fmt.Printf("ociAclOOBUpdate: updated ACL for user %s on vault %s (permit=%v, actions=%v)\n", userID, vaultID, permit, actions)
		fmt.Printf("ociAclOOBUpdate: response JSON: %s\n", resp)
	}
}

func initCckmOciAclTest() (string, bool) {
	ociKeyFile := os.Getenv("CCKM_OCI_KEY_FILE")
	ociPubKeyFP := os.Getenv("CCKM_OCI_FINGERPRINT")
	ociRegion := os.Getenv("CCKM_OCI_REGION")
	ociTenancyOCID := os.Getenv("CCKM_OCI_CONN_TENANCY")
	ociUserOCID := os.Getenv("CCKM_OCI_USER")
	if ociKeyFile == "" || ociPubKeyFP == "" || ociRegion == "" || ociTenancyOCID == "" || ociUserOCID == "" {
		return "", false
	}
	connectionName := "tf-" + uuid.New().String()[:8]
	vaultConfig := fmt.Sprintf(`
		resource "ciphertrust_oci_connection" "connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}
		data "ciphertrust_get_oci_regions" "regions" {
			connection_id = ciphertrust_oci_connection.connection.name
		}
		data "ciphertrust_get_oci_compartments" "compartments" {
			connection_id = ciphertrust_oci_connection.connection.id
		}
		data "ciphertrust_get_oci_vaults" "vaults" {
			connection_id  = ciphertrust_oci_connection.connection.id
			compartment_id = tolist(data.ciphertrust_get_oci_compartments.compartments.compartments)[0].id
			region         = data.ciphertrust_get_oci_regions.regions.oci_regions.0
		}
		resource "ciphertrust_oci_vault" "vault" {
			region        = data.ciphertrust_get_oci_regions.regions.oci_regions.0
			connection_id = ciphertrust_oci_connection.connection.id
			vault_id      = tolist(data.ciphertrust_get_oci_vaults.vaults.vaults)[0].vault_id
		}`,
		ociKeyFile, connectionName, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	return vaultConfig, true
}

func TestCckmOCIAclUsersAndGroups(t *testing.T) {

	createVaultConfigStr, ok := initCckmOciAclTest()
	if !ok {
		t.Skip("Failed to set OCI connection variables")
	}

	createACLsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = ["view", "keycreate"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_groups.group.id
			actions  = ["view", "keyupdate", "keydelete"]
		}
		data "ciphertrust_oci_vault_list" "vault_ds" {
			depends_on = [ciphertrust_oci_acl.user_acl, ciphertrust_oci_acl.group_acl]
			filters = {
				display_name = ciphertrust_oci_vault.vault.name
			}
		}`

	addAclActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = ["view", "keycreate", "keydelete"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_groups.group.id
			actions  = ["view", "keycreate", "keyupdate", "keydelete"]
		}
		data "ciphertrust_oci_vault_list" "vault_ds" {
			depends_on = [ciphertrust_oci_acl.user_acl, ciphertrust_oci_acl.group_acl]
			filters = {
				display_name = ciphertrust_oci_vault.vault.name
			}
		}`

	removeAclActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = ["view"]
		}
		data "ciphertrust_oci_vault_list" "vault_ds" {
			depends_on = [ciphertrust_oci_acl.user_acl]
			filters = {
				display_name = ciphertrust_oci_vault.vault.name
			}
		}`

	modifyPlanAclConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_groups" "group" {
			name = "%s"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = %s
			user_id  = ciphertrust_user.user.id
			actions  = ["view"]
		}
		resource "ciphertrust_oci_acl" "group_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			group    = ciphertrust_groups.group.id
			actions  = ["view", "keycreate", "keydelete"]
		}`

	emptyActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = []
		}`

	dataSourceConfig := `
		data "ciphertrust_oci_vault_list" "vault_ds" {
			filters = {
				display_name = ciphertrust_oci_vault.vault.name
			}
		}`

	userName := "tf-" + uuid.New().String()[:8]
	groupName := "tf-" + uuid.New().String()[:8]
	fakeVaultID := `"` + uuid.New().String() + `"`
	createAclsActionsConfigStr := fmt.Sprintf(createACLsConfig, createVaultConfigStr, userName, groupName)
	addAclActionsConfigStr := fmt.Sprintf(addAclActionsConfig, createVaultConfigStr, userName, groupName)
	removeAclActionsConfigStr := fmt.Sprintf(removeAclActionsConfig, createVaultConfigStr, userName, groupName)
	emptyActionsConfigStr := fmt.Sprintf(emptyActionsConfig, createVaultConfigStr, userName)
	modifyPlanConfigStr := fmt.Sprintf(modifyPlanAclConfig, createVaultConfigStr, userName, groupName, fakeVaultID)
	deleteAclsConfigStr := createVaultConfigStr
	applyConfigStr := createVaultConfigStr + dataSourceConfig
	userACLResourceName := "ciphertrust_oci_acl.user_acl"
	groupACLResourceName := "ciphertrust_oci_acl.group_acl"
	vaultResourceName := "ciphertrust_oci_vault.vault"
	vaultDatasourceName := "data.ciphertrust_oci_vault_list.vault_ds"

	var capturedVaultID string
	var capturedUserID string
	var capturedGroupID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create user and group ACLs; capture IDs for live API checks.
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttrPair(userACLResourceName, "vault_id", vaultResourceName, "id"),
					resource.TestCheckResourceAttrPair(userACLResourceName, "user_id", "ciphertrust_user.user", "id"),
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "2"),
					resource.TestCheckResourceAttrSet(groupACLResourceName, "id"),
					resource.TestCheckResourceAttrPair(groupACLResourceName, "vault_id", vaultResourceName, "id"),
					resource.TestCheckResourceAttrPair(groupACLResourceName, "group", "ciphertrust_groups.group", "id"),
					resource.TestCheckResourceAttr(groupACLResourceName, "actions.#", "3"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "2"),
					resource.TestCheckResourceAttrWith("ciphertrust_oci_vault.vault", "id", func(val string) error {
						capturedVaultID = val
						return nil
					}),
					resource.TestCheckResourceAttrWith("ciphertrust_user.user", "id", func(val string) error {
						capturedUserID = val
						fmt.Printf("step 1: captured user ID: %s\n", capturedUserID)
						return nil
					}),
					resource.TestCheckResourceAttrWith("ciphertrust_groups.group", "id", func(val string) error {
						capturedGroupID = val
						fmt.Printf("step 1: captured group ID: %s\n", capturedGroupID)
						return nil
					}),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{"keycreate"}),
					checkOCIAclActions(&capturedVaultID, &capturedGroupID, []string{"keyupdate", "keydelete"}),
				),
			},
			{
				PreConfig:    func() { logTestStep(t.Name(), "Step 2 - RefreshState") },
				RefreshState: true,
			},
			{
				PreConfig:         func() { logTestStep(t.Name(), "Step 3 - ImportState user_acl") },
				ResourceName:      userACLResourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				PreConfig:         func() { logTestStep(t.Name(), "Step 4 - ImportState group_acl") },
				ResourceName:      groupACLResourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Step 5: add actions to both user and group ACLs.
				PreConfig: func() { logTestStep(t.Name(), "Step 5") },
				Config:    addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "3"),
					resource.TestCheckResourceAttr(groupACLResourceName, "actions.#", "4"),
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "2"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "2"),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{"keycreate", "keydelete"}),
					checkOCIAclActions(&capturedVaultID, &capturedGroupID, []string{"keycreate", "keyupdate", "keydelete"}),
				),
			},
			{
				// Step 6: group_acl is destroyed (group removed from vault ACL); user_acl
				// actions are reduced to view-only.
				// vaults.0.acls.# is not asserted here: the datasource can read before the
				// concurrent group_acl Delete's update-acls call completes (the mutex
				// serializes ACL writes but not the datasource GET). Live API checks
				// confirm the correct final state instead.
				PreConfig: func() { logTestStep(t.Name(), "Step 6") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(userACLResourceName, "actions.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{}),
					checkOCIAclSubjectAbsent(&capturedVaultID, &capturedGroupID),
				),
			},
			{
				// Step 7: stable-state check - all concurrent operations from step 6 have
				// settled. Re-read the vault resource and datasource to confirm Terraform
				// state shows exactly 1 ACL entry (user only, group removed).
				PreConfig: func() { logTestStep(t.Name(), "Step 7") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "1"),
					resource.TestCheckResourceAttrSet(vaultDatasourceName, "vaults.0.acls.0.user_id"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.0.group", ""),
				),
			},
			{
				// Verify that actions = [] is rejected at plan time by the schema validator.
				PreConfig:   func() { logTestStep(t.Name(), "Step 8 - PlanOnly empty actions") },
				Config:      emptyActionsConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`at least 1`),
			},
			{
				// Verify ModifyPlan fires an error when vault_id is changed on an existing ACL.
				PreConfig:   func() { logTestStep(t.Name(), "Step 9 - PlanOnly modifyPlan") },
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Step 10: destroy both ACL resources (first pass). Verify via live API that
				// both user and group have been fully removed from the vault acls array.
				PreConfig: func() { logTestStep(t.Name(), "Step 10") },
				Config:    deleteAclsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					testVerifyResourceDeleted(userACLResourceName),
					testVerifyResourceDeleted(groupACLResourceName),
					checkOCIAclSubjectAbsent(&capturedVaultID, &capturedUserID),
					checkOCIAclSubjectAbsent(&capturedVaultID, &capturedGroupID),
				),
			},
			{
				// Step 11: re-create ACLs (second pass). Recapture user ID from the ACL
				// resource's user_id attribute (ciphertrust_user may get a new ID).
				PreConfig: func() { logTestStep(t.Name(), "Step 11") },
				Config:    createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "2"),
					resource.TestCheckResourceAttrWith(userACLResourceName, "user_id", func(val string) error {
						capturedUserID = val
						fmt.Printf("step 11: captured user ID: %s\n", capturedUserID)
						return nil
					}),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{"keycreate"}),
					checkOCIAclActions(&capturedVaultID, &capturedGroupID, []string{"keyupdate", "keydelete"}),
				),
			},
			{
				// Step 12: add actions to both ACLs (second pass).
				PreConfig: func() { logTestStep(t.Name(), "Step 12") },
				Config:    addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "2"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "2"),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{"keycreate", "keydelete"}),
					checkOCIAclActions(&capturedVaultID, &capturedGroupID, []string{"keycreate", "keyupdate", "keydelete"}),
				),
			},
			{
				// Step 13: group_acl destroyed; user reduced to view-only (second pass).
				// Live API checks verify group is absent and user has no non-view actions.
				// vaults.0.acls.# is not asserted due to the same datasource timing race.
				// Step 14 re-reads after operations settle to verify the count.
				PreConfig: func() { logTestStep(t.Name(), "Step 13") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{}),
					checkOCIAclSubjectAbsent(&capturedVaultID, &capturedGroupID),
				),
			},
			{
				// Step 14: stable-state check (second pass) - confirm Terraform state shows
				// exactly 1 ACL entry (user only, group removed).
				PreConfig: func() { logTestStep(t.Name(), "Step 14") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "1"),
					resource.TestCheckResourceAttrSet(vaultDatasourceName, "vaults.0.acls.0.user_id"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.0.group", ""),
				),
			},
			{
				// Step 15 (final): destroy user_acl and CM user/group resources. The vault
				// resource Read and user_acl Delete run concurrently during the apply, so
				// the vault resource's acls.# in state may still show 1 if Read completed
				// before Delete. The live API check runs after the full apply finishes and
				// confirms the user is correctly absent.
				PreConfig: func() { logTestStep(t.Name(), "Step 15") },
				Config:    applyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					checkOCIAclSubjectAbsent(&capturedVaultID, &capturedUserID),
				),
			},
			{
				// Step 16: stable-final check - user_acl is long gone; re-read vault and
				// datasource to confirm Terraform state shows 0 ACL entries.
				PreConfig: func() { logTestStep(t.Name(), "Step 16") },
				Config:    applyConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(vaultResourceName, "acls.#", "0"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.#", "1"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "0"),
				),
			},
		},
	})
}

// TestCckmOCIAclOOB verifies out-of-band detection for ciphertrust_oci_acl:
//  1. OOB modification: an admin changes the ACL actions outside Terraform;
//     RefreshState detects drift (non-empty plan) and a subsequent apply restores
//     the configured actions.
//  2. OOB deletion: an admin removes the user from the vault ACL entirely outside
//     Terraform; RefreshState returns an error diagnostic so the operator is
//     clearly informed and state is preserved.
func TestCckmOCIAclOOB(t *testing.T) {

	createVaultConfigStr, ok := initCckmOciAclTest()
	if !ok {
		t.Skip("Failed to set OCI connection variables")
	}

	oobAclConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_oci_acl" "user_acl" {
			vault_id = ciphertrust_oci_vault.vault.id
			user_id  = ciphertrust_user.user.id
			actions  = ["view", "keycreate", "keydelete"]
		}
		data "ciphertrust_oci_vault_list" "vault_ds" {
			depends_on = [ciphertrust_oci_acl.user_acl]
			filters = {
				display_name = ciphertrust_oci_vault.vault.name
			}
		}`

	oobUserName := "tf-" + uuid.New().String()[:8]
	oobConfigStr := fmt.Sprintf(oobAclConfig, createVaultConfigStr, oobUserName)
	userACLResourceName := "ciphertrust_oci_acl.user_acl"
	vaultDatasourceName := "data.ciphertrust_oci_vault_list.vault_ds"

	var capturedVaultID string
	var capturedUserID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the ACL. Capture vault_id and user_id for OOB calls.
				Config: oobConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "1"),
					resource.TestCheckResourceAttrWith("ciphertrust_oci_vault.vault", "id", func(val string) error {
						capturedVaultID = val
						return nil
					}),
					resource.TestCheckResourceAttrWith("ciphertrust_user.user", "id", func(val string) error {
						capturedUserID = val
						return nil
					}),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{"keycreate", "keydelete"}),
				),
			},
			{
				// Step 2: OOB modify - change the user's ACL actions to "view" only.
				// RefreshState detects drift: state now reflects the OOB-altered actions,
				// which differ from the configured ["view", "keycreate", "keydelete"].
				PreConfig: func() {
					logTestStep(t.Name(), "Step 2")
					ociAclOOBUpdate(capturedVaultID, capturedUserID, true, []string{"view"})
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: apply the original config to restore the configured actions.
				// Verify via live API that the actions are correctly restored.
				PreConfig: func() { logTestStep(t.Name(), "Step 3") },
				Config:    oobConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(vaultDatasourceName, "vaults.0.acls.#", "1"),
					checkOCIAclActions(&capturedVaultID, &capturedUserID, []string{"keycreate", "keydelete"}),
				),
			},
			{
				// Step 4: OOB delete - revoke all of the user's current actions to fully
				// remove them from the vault ACL. RefreshState must surface an error
				// diagnostic because the user no longer exists in the acls array.
				PreConfig: func() {
					logTestStep(t.Name(), "Step 4")
					allActions := ociGetSubjectActions(capturedVaultID, capturedUserID, false)
					ociAclOOBUpdate(capturedVaultID, capturedUserID, false, allActions)
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`OCI vault ACL was not found`),
			},
		},
	})
}
