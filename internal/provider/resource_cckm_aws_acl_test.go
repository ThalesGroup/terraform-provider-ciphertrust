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

// checkAWSAclActions returns a TestCheckFunc that fetches the live KMS ACL for the given
// subject (user_id or group name) and asserts two conditions:
//  1. Every action in expectedActions is present in the actual action list.
//  2. No non-view actions appear in the actual list that are absent from expectedActions.
//     View-prefixed actions (viewnative, viewbyok, viewhyokkey, etc.) are always accepted
//     as extras because CCKM auto-adds them whenever any other action is granted.
func checkAWSAclActions(kmsID, subject *string, expectedActions []string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		actual := awsGetSubjectActions(*kmsID, *subject, false)
		if actual == nil {
			return fmt.Errorf("checkAWSAclActions: could not retrieve actions for subject %s on KMS %s", *subject, *kmsID)
		}
		actualSet := make(map[string]bool, len(actual))
		for _, a := range actual {
			actualSet[a] = true
		}
		// All expected actions must be present.
		for _, exp := range expectedActions {
			if !actualSet[exp] {
				return fmt.Errorf("checkAWSAclActions: expected action %q not found in actual %v", exp, actual)
			}
		}
		// No unexpected non-view actions are permitted.
		expectedSet := make(map[string]bool, len(expectedActions))
		for _, e := range expectedActions {
			expectedSet[e] = true
		}
		for _, a := range actual {
			if strings.HasPrefix(a, "view") {
				continue // auto-added view actions are always acceptable
			}
			if !expectedSet[a] {
				return fmt.Errorf("checkAWSAclActions: unexpected non-view action %q found in actual %v (expected %v)", a, actual, expectedActions)
			}
		}
		return nil
	}
}

// checkAWSAclSubjectAbsent returns a TestCheckFunc that verifies the given subject (user_id
// or group name) no longer appears in the live KMS acls array. Use this after destroying a
// ciphertrust_aws_acl resource to confirm the subject has been fully removed from the KMS ACL.
func checkAWSAclSubjectAbsent(kmsID, subject *string) resource.TestCheckFunc {
	return func(_ *terraform.State) error {
		actual := awsGetSubjectActions(*kmsID, *subject, true)
		if actual != nil {
			return fmt.Errorf("checkAWSAclSubjectAbsent: subject %s is still present in KMS %s acls with actions %v", *subject, *kmsID, actual)
		}
		return nil
	}
}

// awsGetSubjectActions fetches the KMS and returns the current actions for the given subject
// from the acls array. Subject may be a user_id (e.g. "local|<uuid>") or a group name.
// Both the user_id and group fields are checked so the same function serves both ACL types.
// expectNotFound controls whether a missing subject is logged as "correctly" or "unexpectedly"
// not found. Returns nil if the client is unavailable, the GET fails, or the subject is
// not found - the caller decides whether nil is a success or failure condition.
func awsGetSubjectActions(kmsID, subject string, expectNotFound bool) []string {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("awsGetSubjectActions: createCMClient failed")
		return nil
	}
	resp, err := client.GetById(context.Background(), "oob-get-kms-"+kmsID, kmsID, common.URL_AWS+"/kms")
	if err != nil {
		fmt.Printf("awsGetSubjectActions: GET KMS failed: %v\n", err)
		return nil
	}
	fmt.Printf("awsGetSubjectActions: KMS acls JSON: %s\n", resp)
	var kmsResp struct {
		Acls []struct {
			UserID  string   `json:"user_id"`
			Group   string   `json:"group"`
			Actions []string `json:"actions"`
		} `json:"acls"`
	}
	if err := json.Unmarshal([]byte(resp), &kmsResp); err != nil {
		fmt.Printf("awsGetSubjectActions: parse failed: %v\n", err)
		return nil
	}
	for _, acl := range kmsResp.Acls {
		if acl.UserID == subject || acl.Group == subject {
			fmt.Printf("awsGetSubjectActions: found subject %s with actions %v\n", subject, acl.Actions)
			return acl.Actions
		}
	}
	if expectNotFound {
		fmt.Printf("awsGetSubjectActions: subject %s correctly not found in KMS %s acls\n", subject, kmsID)
	} else {
		fmt.Printf("awsGetSubjectActions: subject %s unexpectedly not found in KMS %s acls\n", subject, kmsID)
	}
	return nil
}

// awsAclOOBUpdate calls the update-acls API out-of-band for a KMS user ACL entry.
// permit=true grants the given actions; permit=false revokes them (removing the user from the ACL).
// Failures are intentionally ignored - the test steps that follow will surface any real problem.
func awsAclOOBUpdate(kmsID, userID string, permit bool, actions []string) {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("awsAclOOBUpdate: createCMClient failed, skipping OOB update")
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
		fmt.Printf("awsAclOOBUpdate: marshal failed: %v\n", err)
		return
	}
	resp, err := client.PostDataV2(context.Background(), "oob-acl-update-"+kmsID, common.URL_AWS+"/kms/"+kmsID+"/update-acls", body)
	if err != nil {
		fmt.Printf("awsAclOOBUpdate: API call failed: %v\n", err)
	} else {
		fmt.Printf("awsAclOOBUpdate: updated ACL for user %s on KMS %s (permit=%v, actions=%v)\n", userID, kmsID, permit, actions)
		fmt.Printf("awsAclOOBUpdate: response JSON: %s\n", resp)
	}
}

func TestCckmAWSAclUsersAndGroups(t *testing.T) {

	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
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
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = ["keycreate"]
		}
		resource "ciphertrust_aws_acl" "group_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			group   = ciphertrust_groups.group.id
			actions = ["keyupdate", "keydelete"]
		}
		data "ciphertrust_aws_kms_list" "kms_ds" {
			depends_on = [ciphertrust_aws_acl.user_acl, ciphertrust_aws_acl.group_acl]
			filters = {
				name = ciphertrust_aws_kms.kms.name
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
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = ["keycreate", "keydelete"]
		}
		resource "ciphertrust_aws_acl" "group_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			group   = ciphertrust_groups.group.id
			actions = ["keycreate", "keyupdate", "keydelete"]
		}
		data "ciphertrust_aws_kms_list" "kms_ds" {
			depends_on = [ciphertrust_aws_acl.user_acl, ciphertrust_aws_acl.group_acl]
			filters = {
				name = ciphertrust_aws_kms.kms.name
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
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = %s
			user_id = ciphertrust_user.user.id
			actions = ["view"]
		}
		data "ciphertrust_aws_kms_list" "kms_ds" {
			depends_on = [ciphertrust_aws_acl.user_acl]
			filters = {
				name = ciphertrust_aws_kms.kms.name
			}
		}`

	// emptyActionsConfig is used only to verify that actions = [] is rejected at plan time.
	emptyActionsConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = []
		}`

	dataSourceConfig := `
		data "ciphertrust_aws_kms_list" "kms_ds" {
		filters = {
			name = ciphertrust_aws_kms.kms.name
		}
	}`

	userName := "tf-" + uuid.New().String()[:8]
	groupName := "tf-" + uuid.New().String()[:8]
	fakeKmsID := `"` + uuid.New().String() + `"`
	createAclsActionsConfigStr := fmt.Sprintf(createACLsConfig, awsConnectionResource, userName, groupName)
	addAclActionsConfigStr := fmt.Sprintf(addAclActionsConfig, awsConnectionResource, userName, groupName)
	removeAclActionsConfigStr := fmt.Sprintf(removeAclActionsConfig, awsConnectionResource, userName, groupName, "ciphertrust_aws_kms.kms.id")
	emptyActionsConfigStr := fmt.Sprintf(emptyActionsConfig, awsConnectionResource, userName)
	modifyPlanConfigStr := fmt.Sprintf(removeAclActionsConfig, awsConnectionResource, userName, groupName, fakeKmsID)
	deleteAclsConfigStr := awsConnectionResource
	datasourceConfigStr := awsConnectionResource + dataSourceConfig
	userACLResourceName := "ciphertrust_aws_acl.user_acl"
	groupACLResourceName := "ciphertrust_aws_acl.group_acl"
	kmsResourceName := "ciphertrust_aws_kms.kms"
	kmsDatasourceName := "data.ciphertrust_aws_kms_list.kms_ds"

	var capturedKmsID string
	var capturedUserID string
	var capturedGroupID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create user and group ACLs; capture IDs for live API checks.
				PreConfig: func() { logTestStep(t.Name(), "Step 1") },
				Config:    createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
					resource.TestCheckResourceAttrWith("ciphertrust_aws_kms.kms", "id", func(val string) error {
						capturedKmsID = val
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
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{"keycreate"}),
					checkAWSAclActions(&capturedKmsID, &capturedGroupID, []string{"keyupdate", "keydelete"}),
				),
			},
			{
				PreConfig:    func() { logTestStep(t.Name(), "Step 2 - RefreshState") },
				RefreshState: true,
			},
			{
				// Step 3: "actions" cannot be reconstructed from the API (the KMS returns
				// the expanded kms_actions set, not the raw user input), so it is ignored.
				PreConfig:               func() { logTestStep(t.Name(), "Step 3 - ImportState user_acl") },
				ResourceName:            userACLResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"actions"},
			},
			{
				PreConfig:               func() { logTestStep(t.Name(), "Step 4 - ImportState group_acl") },
				ResourceName:            groupACLResourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"actions"},
			},
			{
				// Step 5: add actions to both user and group ACLs.
				PreConfig: func() { logTestStep(t.Name(), "Step 5") },
				Config:    addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "2"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{"keycreate", "keydelete"}),
					checkAWSAclActions(&capturedKmsID, &capturedGroupID, []string{"keycreate", "keyupdate", "keydelete"}),
				),
			},
			{
				// Step 6: group_acl is destroyed (group removed from KMS ACL); user_acl
				// actions are reduced to view-only. CCKM auto-expands "view" to viewnative
				// plus additional view permissions (viewhyokkey, viewkeystore, etc.).
				// kms.0.acls.# is not asserted here: the datasource can read before the
				// concurrent group_acl Delete's update-acls call completes (the mutex
				// serializes ACL writes but not the datasource GET). Live API checks
				// confirm the correct final state instead.
				PreConfig: func() { logTestStep(t.Name(), "Step 6") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{}),
					checkAWSAclSubjectAbsent(&capturedKmsID, &capturedGroupID),
				),
			},
			{
				// Step 7: stable-state check - all concurrent operations from step 6 have
				// settled. Re-read the KMS resource and datasource to confirm Terraform
				// state shows exactly 1 ACL entry (user only, group removed).
				PreConfig: func() { logTestStep(t.Name(), "Step 7") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "1"),
					resource.TestCheckResourceAttrSet(kmsDatasourceName, "kms.0.acls.0.user_id"),
				),
			},
			{
				// Step 8: destroy both ACL resources. Verify via live API that both the
				// user and group have been completely removed from the KMS acls array.
				// The group was already absent after step 6; the user is removed here.
				PreConfig: func() { logTestStep(t.Name(), "Step 8") },
				Config:    deleteAclsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					testVerifyResourceDeleted(userACLResourceName),
					testVerifyResourceDeleted(groupACLResourceName),
					checkAWSAclSubjectAbsent(&capturedKmsID, &capturedUserID),
					checkAWSAclSubjectAbsent(&capturedKmsID, &capturedGroupID),
				),
			},
			{
				// Step 9: re-create ACLs (second pass to cover re-create after delete).
				// ciphertrust_user is recreated with a new ID; recapture from the ACL
				// resource's user_id attribute (more direct than ciphertrust_user.user).
				PreConfig: func() { logTestStep(t.Name(), "Step 9") },
				Config:    createAclsActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
					resource.TestCheckResourceAttrWith(userACLResourceName, "user_id", func(val string) error {
						capturedUserID = val
						fmt.Printf("step 9: captured user ID: %s\n", capturedUserID)
						return nil
					}),
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{"keycreate"}),
					checkAWSAclActions(&capturedKmsID, &capturedGroupID, []string{"keyupdate", "keydelete"}),
				),
			},
			{
				// Step 10: add actions to both ACLs (second pass).
				PreConfig: func() { logTestStep(t.Name(), "Step 10") },
				Config:    addAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "2"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "2"),
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{"keycreate", "keydelete"}),
					checkAWSAclActions(&capturedKmsID, &capturedGroupID, []string{"keycreate", "keyupdate", "keydelete"}),
				),
			},
			{
				// Step 11: group_acl destroyed; user reduced to view-only (second pass).
				// Live API checks verify group is absent and user has no non-view actions.
				// kms.0.acls.# is not asserted here due to the datasource timing race
				// (same as step 6). Step 12 re-reads after operations settle to verify
				// the Terraform state/datasource count.
				PreConfig: func() { logTestStep(t.Name(), "Step 11") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{}),
					checkAWSAclSubjectAbsent(&capturedKmsID, &capturedGroupID),
				),
			},
			{
				// Step 12: stable-state check (second pass) - confirm Terraform state shows
				// exactly 1 ACL entry (user only, group removed).
				PreConfig: func() { logTestStep(t.Name(), "Step 12") },
				Config:    removeAclActionsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsResourceName, "acls.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "1"),
					resource.TestCheckResourceAttrSet(kmsDatasourceName, "kms.0.acls.0.user_id"),
				),
			},
			{
				// Verify that actions = [] is rejected at plan time by the schema validator.
				// An empty action set would remove the user from the KMS ACL entirely;
				// deleting the resource is the correct way to remove all permissions.
				PreConfig:   func() { logTestStep(t.Name(), "Step 13") },
				Config:      emptyActionsConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`at least 1`),
			},
			{
				// Verify ModifyPlan fires an error when kms_id is changed on an existing ACL.
				PreConfig:   func() { logTestStep(t.Name(), "Step 14") },
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// user_acl is destroyed (all user actions revoked) and then the user
				// and group CM resources are deleted. CCKM cleans up residual ACL
				// entries asynchronously via a DB trigger after user/group deletion,
				// so the data source may still show acls.# = 1 immediately after the
				// apply finishes. The CM API confirms acls.# = 0 once the trigger fires.
				// We do not assert acls.# = 0 here due to this timing gap.
				PreConfig: func() { logTestStep(t.Name(), "Step 15") },
				Config:    datasourceConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.#", "1"),
					resource.TestCheckResourceAttrSet(kmsDatasourceName, "kms.0.id"),
				),
			},
		},
	})
}

// TestCckmAWSAclOOB verifies out-of-band detection for ciphertrust_aws_acl:
//  1. OOB modification: an admin changes the ACL actions outside Terraform;
//     RefreshState detects drift (non-empty plan) and a subsequent apply restores
//     the configured actions.
//  2. OOB deletion: an admin removes the user from the KMS ACL entirely outside
//     Terraform; RefreshState returns an error diagnostic so the operator is
//     clearly informed and state is preserved.
func TestCckmAWSAclOOB(t *testing.T) {

	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}

	oobAclConfig := `
		%s
		resource "ciphertrust_user" "user" {
			username = "%s"
			password = "LongPassword1234++"
		}
		resource "ciphertrust_aws_acl" "user_acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			user_id = ciphertrust_user.user.id
			actions = ["keycreate", "keydelete"]
		}
		data "ciphertrust_aws_kms_list" "kms_ds" {
			depends_on = [ciphertrust_aws_acl.user_acl]
			filters = {
				name = ciphertrust_aws_kms.kms.name
			}
		}`

	oobUserName := "tf-" + uuid.New().String()[:8]
	oobConfigStr := fmt.Sprintf(oobAclConfig, awsConnectionResource, oobUserName)
	userACLResourceName := "ciphertrust_aws_acl.user_acl"
	kmsDatasourceName := "data.ciphertrust_aws_kms_list.kms_ds"

	var capturedKmsID string
	var capturedUserID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create the ACL. Capture kms_id and user_id for OOB calls, then
				// verify the live KMS acls contain exactly ["keycreate","keydelete"] plus
				// any auto-added view actions and no other non-view actions.
				Config: oobConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "1"),
					resource.TestCheckResourceAttrWith("ciphertrust_aws_kms.kms", "id", func(val string) error {
						capturedKmsID = val
						return nil
					}),
					resource.TestCheckResourceAttrWith("ciphertrust_user.user", "id", func(val string) error {
						capturedUserID = val
						return nil
					}),
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{"keycreate", "keydelete"}),
				),
			},
			{
				// Step 2: OOB modify - change the user's ACL actions to "view" only.
				// RefreshState detects drift: state now reflects the OOB-altered actions,
				// which differ from the configured ["keycreate","keydelete"].
				PreConfig: func() {
					logTestStep(t.Name(), "Step 2")
					awsAclOOBUpdate(capturedKmsID, capturedUserID, true, []string{"view"})
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: apply the original config to restore the configured actions.
				// Update reconciles and re-grants ["keycreate","keydelete"]. Verify via
				// live API that the actions are correctly restored.
				PreConfig: func() { logTestStep(t.Name(), "Step 3") },
				Config:    oobConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(userACLResourceName, "id"),
					resource.TestCheckResourceAttr(kmsDatasourceName, "kms.0.acls.#", "1"),
					checkAWSAclActions(&capturedKmsID, &capturedUserID, []string{"keycreate", "keydelete"}),
				),
			},
			{
				// Step 4: OOB delete - revoke all of the user's current actions (including
				// auto-added view actions) to fully remove them from the KMS ACL. CCKM
				// auto-adds view actions (viewnative, viewbyok, etc.) whenever keycreate or
				// keydelete are granted, so revoking only the configured actions leaves the
				// user entry in the acls array with view-only permissions. We must fetch the
				// full action list and revoke everything. RefreshState must then surface an
				// error diagnostic because the user no longer exists in the acls array.
				PreConfig: func() {
					logTestStep(t.Name(), "Step 4")
					allActions := awsGetSubjectActions(capturedKmsID, capturedUserID, false)
					awsAclOOBUpdate(capturedKmsID, capturedUserID, false, allActions)
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`AWS KMS ACL was not found`),
			},
		},
	})
}
