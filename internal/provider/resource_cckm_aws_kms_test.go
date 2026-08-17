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
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/tidwall/gjson"
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

	createKmsConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "%s"
		}
		resource "ciphertrust_aws_connection" "new_aws_connection" {
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
		}`

	updateKmsConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "%s"
		}
		resource "ciphertrust_aws_connection" "new_aws_connection" {
			name = "%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			connection_id = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = %s
			connection_id  = %s
			name           = "%s"
			# Place holder for archive attrib
			%s
			regions        = [data.ciphertrust_aws_account_details.account_details.regions[0]]
		}`

	// planArchiveOnCreateConfig verifies that archive = true is rejected at creation time.
	// The existing kms resource is included unchanged; kms_b is a new resource with archive = true.
	// This is plan-only so ModifyPlan fires and no apply occurs.
	planArchiveOnCreateConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
			name = "%s"
		}
		resource "ciphertrust_aws_connection" "new_aws_connection" {
			name = "%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
			connection_id = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = %s
			connection_id  = %s
			name           = "%s"
			archive        = false
			regions        = [data.ciphertrust_aws_account_details.account_details.regions[0]]
		}
		resource "ciphertrust_aws_kms" "kms_b" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			connection_id  = ciphertrust_aws_connection.aws_connection.id
			name           = "%s"
			archive        = true
			regions        = [data.ciphertrust_aws_account_details.account_details.regions[1]]
		}`

	connNameA := "tf-A" + uuid.New().String()[:8]
	connNameB := "tf-B" + uuid.New().String()[:8]
	kmsNameA := "tf-" + uuid.New().String()[:8]
	kmsNameB := "tf-" + uuid.New().String()[:8]
	connectionID := "ciphertrust_aws_connection.aws_connection.id"
	updatedConnectionID := "ciphertrust_aws_connection.new_aws_connection.id"
	accountID := "data.ciphertrust_aws_account_details.account_details.account_id"
	invalidAccountID := "000000000000"

	isCDSPaaS := os.Getenv("CDSPAAS") == "true"

	createKmsConfigStr := fmt.Sprintf(createKmsConfig, connNameA, connNameB, kmsNameA)
	// update regions; archive only on CM (CDSPaaS does not support archiving a KMS)
	archiveAttr := "archive = true"
	expectedArchive := "true"
	expectedStatus := "ARCHIVED"
	if isCDSPaaS {
		archiveAttr = "archive = false"
		expectedArchive = "false"
		expectedStatus = "ACTIVE"
	}
	updateKmsConfigStr := fmt.Sprintf(updateKmsConfig, connNameA, connNameB, accountID, connectionID, kmsNameA, archiveAttr)
	// un-archive the kms
	recoverKmsConfigStr := fmt.Sprintf(updateKmsConfig, connNameA, connNameB, accountID, connectionID, kmsNameA, "archive = false")
	// change the kms'es connection
	updateConnConfigStr := fmt.Sprintf(updateKmsConfig, connNameA, connNameB, accountID, updatedConnectionID, kmsNameA, "archive = false")
	// try to change account
	modifyPlanConfigStr := fmt.Sprintf(updateKmsConfig, connNameA, connNameB, invalidAccountID, updatedConnectionID, accountID, "archive = false")
	// plan-only: verify archive = true is rejected at creation time
	planArchiveOnCreateConfigStr := fmt.Sprintf(planArchiveOnCreateConfig, connNameA, connNameB, accountID, updatedConnectionID, kmsNameA, kmsNameB)

	resourceName := "ciphertrust_aws_kms.kms"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createKmsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "arn"),
					resource.TestCheckResourceAttr(resourceName, "name", kmsNameA),
					resource.TestCheckResourceAttrSet(resourceName, "regions.#"),
					resource.TestCheckResourceAttr(resourceName, "archive", "false"),
					resource.TestCheckResourceAttr(resourceName, "status", "ACTIVE"),
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
				ImportStateVerifyIgnore: []string{"updated_at"},
			},
			// Reduce regions; on CDSPaaS archive is not supported so archive stays false and status stays ACTIVE.
			{
				Config: updateKmsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "archive", expectedArchive),
					resource.TestCheckResourceAttr(resourceName, "status", expectedStatus),
				),
			},
			// Unarchive via update
			{
				Config: recoverKmsConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "regions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "archive", "false"),
					resource.TestCheckResourceAttr(resourceName, "status", "ACTIVE"),
				),
			},
			// Update connection
			{
				Config: updateConnConfigStr,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "connection_name", connNameB),
					resource.TestCheckResourceAttr(resourceName, "regions.#", "1"),
				),
			},
			{
				// Verify ModifyPlan fires an error when account_id is changed.
				Config:      modifyPlanConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Verify ModifyPlan fires an error when archive = true is set at creation time.
				Config:      planArchiveOnCreateConfigStr,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid create-time configuration`),
			},
		},
	})
}

func TestCckmAWSKmsCreateValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: connection_id empty string
			{
				Config: `
					resource "ciphertrust_aws_kms" "test" {
						account_id    = "123456789012"
						connection_id = ""
						name          = "valid-name"
						regions       = ["us-east-1"]
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			// Step 2: connection_id whitespace-only
			{
				Config: `
					resource "ciphertrust_aws_kms" "test" {
						account_id    = "123456789012"
						connection_id = "   "
						name          = "valid-name"
						regions       = ["us-east-1"]
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
		},
	})
}
