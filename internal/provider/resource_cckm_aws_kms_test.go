package provider

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/tidwall/gjson"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cleanupCckmAwsKMS lists all CCKM AWS KMS registrations in CipherTrust Manager and deletes each one.
// This is called via PreCheck on every CCKM AWS test to remove any KMS resources left behind by a
// previous failed test run. Only runs when TF_CCKM_CLEANUP=true is set, so that contributors do not
// accidentally wipe their own CM resources. All errors are logged as warnings - the cleanup is
// best-effort and never fails the test.
func cleanupCckmAwsKMS() {
	if os.Getenv("TF_CCKM_CLEANUP") != "true" {
		return
	}
	client, ok := createCMClient()
	if !ok {
		fmt.Println("cleanupCckmAwsKMS: could not create CM client, skipping cleanup")
		return
	}
	ctx := context.Background()
	filters := url.Values{}
	filters.Add("limit", "1000")
	response, err := client.ListWithFilters(ctx, uuid.NewString(), common.URL_AWS_KMS, filters)
	if err != nil {
		fmt.Printf("** cleanupCckmAwsKMS: failed to list KMS: %s\n", err.Error())
		return
	}
	resources := gjson.Get(response, "resources").Array()
	if len(resources) == 0 {
		return
	}
	fmt.Printf("Num kmses : %d\n", len(resources))
	for _, r := range resources {
		kmsID := gjson.Get(r.Raw, "id").String()
		kmsName := gjson.Get(r.Raw, "name").String()
		_, err := client.DeleteByURL(ctx, uuid.NewString(), common.URL_AWS_KMS+"/"+kmsID)
		if err != nil {
			if !strings.Contains(err.Error(), "Delete all custom key stores") {
				fmt.Printf("** cleanupCckmAwsKMS: failed to delete KMS '%s' (%s): %s\n", kmsName, kmsID, err.Error())
				continue
			}
			// The KMS has key stores.
			// Step 1: delete all keys in this KMS.
			keyFilters := url.Values{}
			keyFilters.Add("kms_id", kmsID)
			keyFilters.Add("limit", "1000")
			keyResp, err := client.ListWithFilters(ctx, uuid.NewString(), common.URL_AWS_KEY, keyFilters)
			if err != nil {
				fmt.Printf("** cleanupCckmAwsKMS: failed to list keys for KMS '%s': %s\n", kmsName, err.Error())
			} else {
				for _, k := range gjson.Get(keyResp, "resources").Array() {
					keyID := gjson.Get(k.Raw, "id").String()
					_, err := client.DeleteByURL(ctx, uuid.NewString(), common.URL_AWS_KEY+"/"+keyID)
					if err != nil {
						fmt.Printf("** cleanupCckmAwsKMS: failed to delete key %s for KMS '%s': %s\n", keyID, kmsName, err.Error())
					} else {
						fmt.Printf("cleanupCckmAwsKMS: deleted key %s for KMS '%s'\n", keyID, kmsName)
					}
				}
			}
			// Step 2: delete all custom key stores in this KMS.
			cksFilters := url.Values{}
			cksFilters.Add("kms_id", kmsID)
			cksFilters.Add("limit", "1000")
			cksResp, err := client.ListWithFilters(ctx, uuid.NewString(), common.URL_AWS_XKS, cksFilters)
			if err != nil {
				fmt.Printf("** cleanupCckmAwsKMS: failed to list custom key stores for KMS '%s': %s\n", kmsName, err.Error())
			} else {
				for _, c := range gjson.Get(cksResp, "resources").Array() {
					cksID := gjson.Get(c.Raw, "id").String()
					_, err := client.DeleteByURL(ctx, uuid.NewString(), common.URL_AWS_XKS+"/"+cksID)
					if err != nil {
						fmt.Printf("** cleanupCckmAwsKMS: failed to delete custom key store %s for KMS '%s': %s\n", cksID, kmsName, err.Error())
					} else {
						fmt.Printf("cleanupCckmAwsKMS: deleted custom key store %s for KMS '%s'\n", cksID, kmsName)
					}
				}
			}
			// Retry the KMS delete.
			_, err2 := client.DeleteByURL(ctx, uuid.NewString(), common.URL_AWS_KMS+"/"+kmsID)
			if err2 != nil {
				fmt.Printf("** cleanupCckmAwsKMS: failed to delete KMS '%s' (%s) after cascade cleanup: %s\n", kmsName, kmsID, err2.Error())
				continue
			}
		}
		fmt.Printf("cleanupCckmAwsKMS: deleted KMS '%s'\n", kmsName)
	}
}

func TestCckmAWSKms(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("AWS credentials not set")
	}
	uid := "tf-" + uuid.New().String()[:8]
	updatedConnName := uid + "-upd"

	createKmsConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			connection_id = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			connection_id  = ciphertrust_aws_connection.aws_connection.id
			name           = "%s"
			regions = [
				data.ciphertrust_aws_account_details.account_details.regions[0],
				data.ciphertrust_aws_account_details.account_details.regions[1],
				data.ciphertrust_aws_account_details.account_details.regions[2]
			]
		}`, uid, uid)

	updateKmsRegionsConfig := fmt.Sprintf(`
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			connection_id = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			connection_id  = ciphertrust_aws_connection.aws_connection.id
			name           = "%s"
			regions        = [data.ciphertrust_aws_account_details.account_details.regions[0]]
		}`, uid, uid)

	updateKmsConnectionConfig := `
		resource "ciphertrust_aws_connection" "new_aws_connection" {
			name = "%s"
		}
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			connection_id = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = %s
			connection_id  = ciphertrust_aws_connection.new_aws_connection.id
			name           = "%s"
			regions        = [data.ciphertrust_aws_account_details.account_details.regions[0]]
		}`
	updateKmsConnectionConfigStr := fmt.Sprintf(updateKmsConnectionConfig,
		updatedConnName, uid, "data.ciphertrust_aws_account_details.account_details.account_id", uid)
	modifyPlanConfigStr := fmt.Sprintf(updateKmsConnectionConfig,
		updatedConnName, uid, `"000000000000"`, uid)

	resourceName := "ciphertrust_aws_kms.kms"
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createKmsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "name", uid),
					resource.TestCheckResourceAttrSet(resourceName, "regions.#"),
				),
			},
			{
				// Import the KMS immediately after creation and verify all computed fields
				// round-trip correctly. updated_at is ignored because the two consecutive
				// Read calls made by ImportStateVerify may observe different timestamps if
				// any background process touches the KMS between them.
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"updated_at", "connection_id"},
			},
			{
				Config: updateKmsRegionsConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "regions.#", "1"),
				),
			},
			{
				Config: updateKmsConnectionConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "connection_name", updatedConnName),
					resource.TestCheckResourceAttr(resourceName, "regions.#", "1"),
				),
			},
			{
				// Verify ModifyPlan fires an error when account_id is changed.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Immutable attribute change detected`),
			},
		},
	})
}
