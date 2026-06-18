package provider

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
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
	for _, r := range resources {
		kmsID := gjson.Get(r.Raw, "id").String()
		kmsName := gjson.Get(r.Raw, "name").String()
		_, err := client.DeleteByURL(ctx, uuid.NewString(), common.URL_AWS_KMS+"/"+kmsID)
		if err != nil {
			fmt.Printf("** cleanupCckmAwsKMS: failed to delete KMS '%s' (%s): %s\n", kmsName, kmsID, err.Error())
		} else {
			fmt.Printf("cleanupCckmAwsKMS: deleted KMS '%s'\n", kmsName)
		}
	}
}

// TestCckmAWSKeyMinimalConfig verifies that a resource configuration
// containing only the minimal required attributes is accepted and applied
// without error.
func TestCckmAWSKeyMinimalConfig(t *testing.T) {
	awsConnectionResource, ok := initCckmAwsTest()
	if !ok {
		t.Skip()
	}
	nativeKeyConfig := `
		resource "ciphertrust_aws_key" "native_key" {
			alias        = [local.alias]
			kms          = ciphertrust_aws_kms.kms.id
			region       = ciphertrust_aws_kms.kms.regions[0]
            origin       = "AWS_KMS"
		}
		resource "ciphertrust_aws_policy_template" "policy_template" {
            kms    = ciphertrust_aws_kms.kms.id
			name   = "%s"
			policy = <<-EOT
				%s
			EOT
		}
		resource "ciphertrust_groups" "acl_group" {
			name = "%s"
		}
		resource "ciphertrust_aws_acl" "acl" {
			kms_id  = ciphertrust_aws_kms.kms.id
			group   = ciphertrust_groups.acl_group.id
			actions = ["view"]
		}
		resource "ciphertrust_cm_key" "cm_key" {
			name      = local.cmKeyName
			algorithm = "RSA"
			key_size  = 2048
		}
		resource "ciphertrust_aws_key" "external_key" {
			alias   = ["%s"]
			customer_master_key_spec = "RSA_2048"
			kms     = ciphertrust_aws_kms.kms.id
			region  = ciphertrust_aws_kms.kms.regions[0]
			upload_key {
				source_key_identifier = ciphertrust_cm_key.cm_key.id
			}
		}
		resource "ciphertrust_aws_key_import_material" "reimport" {
			key_id = ciphertrust_aws_key.external_key.key_id
			import_key_material {
				source_key_identifier = ciphertrust_aws_key.external_key.local_key_id
			}
		}`

	// customKeystoreConfig exercises ciphertrust_aws_custom_keystore and
	// ciphertrust_aws_xks_key with the minimal required attributes.
	// An AES CM key is created for the health-check key ID (the existing cm_key
	// is RSA and cannot be used for an XKS health check).
	// CM_ADDRESS must be set to the CipherTrust Manager HTTPS address so that
	// the XKS proxy URI endpoint passes API validation; the test is skipped when it is absent.
	customKeystoreConfig := `
		resource "ciphertrust_cm_key" "cm_aes_key" {
			name                         = "%s"
			algorithm                    = "AES"
			usage_mask                   = local.cm_key_usage_mask
			unexportable                 = true
			undeletable                  = true
			remove_from_state_on_destroy = true
		}
		resource "ciphertrust_aws_custom_keystore" "keystore" {
			name   = "%s"
			region = ciphertrust_aws_kms.kms.regions[0]
			kms    = ciphertrust_aws_kms.kms.id
			local_hosted_params {
				health_check_key_id = ciphertrust_cm_key.cm_aes_key.id
				max_credentials     = 8
				source_key_tier     = "local"
			}
			aws_param {
				custom_key_store_type  = "EXTERNAL_KEY_STORE"
				xks_proxy_connectivity = "PUBLIC_ENDPOINT"
				xks_proxy_uri_endpoint = "%s"
			}
		}
		resource "ciphertrust_aws_xks_key" "xks_key" {
			local_hosted_params {
				custom_key_store_id = ciphertrust_aws_custom_keystore.keystore.id
				blocked             = false
				linked              = false
				source_key_id       = ciphertrust_cm_key.cm_aes_key.id
				source_key_tier     = "local"
			}
		}`

	keyConfigStr := fmt.Sprintf(nativeKeyConfig, "tf-"+uuid.NewString()[:8], defaultPolicy, "tf-"+uuid.NewString()[:8], "tf-"+uuid.NewString()[:8])
	proxyURIEndpoint := os.Getenv("CM_ADDRESS")
	if os.Getenv("CDSPAAS") == "true" {
		proxyURIEndpoint = "https://xks." + proxyURIEndpoint[len("https://"):]
	}
	customKeyStoreConfigStr := fmt.Sprintf(customKeystoreConfig, "tf-aes-"+uuid.NewString()[:8], "tf-ks-"+uuid.NewString()[:8], proxyURIEndpoint)
	fullConfig := awsConnectionResource + keyConfigStr + customKeyStoreConfigStr
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fullConfig,
			},
			{
				RefreshState: true,
			},
		},
	})
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
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection = ciphertrust_aws_connection.aws_connection.name
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
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = data.ciphertrust_aws_account_details.account_details.account_id
			aws_connection = ciphertrust_aws_connection.aws_connection.name
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
			aws_connection = ciphertrust_aws_connection.aws_connection.id
		}
		resource "ciphertrust_aws_kms" "kms" {
			account_id     = %s
			aws_connection = ciphertrust_aws_connection.new_aws_connection.name
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
					resource.TestCheckResourceAttrSet(resourceName, "aws_connection"),
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
				ImportStateVerifyIgnore: []string{"updated_at"},
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
					resource.TestCheckResourceAttr(resourceName, "aws_connection", updatedConnName),
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
