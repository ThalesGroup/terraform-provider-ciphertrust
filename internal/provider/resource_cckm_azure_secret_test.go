package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// azureProviderSecretSettingsConfig returns config with the Azure secret delete settings added to the provider
// block. The settings in the config of a test run apply to every secret destroyed at the end of that run.
func azureProviderSecretSettingsConfig(config string, purgeSecretsOnDelete, recoverSoftDeletedSecrets bool) string {
	settings := fmt.Sprintf(`provider "ciphertrust" {
		cloud_key_manager = {
			azure = {
				purge_secrets_on_delete      = %t
				recover_soft_deleted_secrets = %t
			}
		}
	`, purgeSecretsOnDelete, recoverSoftDeletedSecrets)
	return strings.Replace(config, `provider "ciphertrust" {`, settings, 1)
}

// azureSecretSoftDeleteOutOfBand soft-deletes the secret with the CipherTrust Manager API, outside of Terraform.
// The secret keeps its ID and stays in the vault. The error is returned so the test can fail.
func azureSecretSoftDeleteOutOfBand(secretID string) error {
	client, ok := createCMClient()
	if !ok {
		return fmt.Errorf("unable to create a CipherTrust Manager client")
	}
	_, err := client.PostNoData(context.Background(), uuid.New().String(), common.URL_AZURE+"/secrets/"+secretID+"/soft-delete")
	if err != nil {
		fmt.Printf("azureSecretSoftDeleteOutOfBand failed err: %s\n", err.Error())
	}
	return err
}

// TestCckmAzureSecretValidation checks the configuration errors that are raised at plan time. Every step is
// PlanOnly, so no secret is created in Azure.
func TestCckmAzureSecretValidation(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureSecretValidation")
	}

	// secretConfig args: the body of the resource block.
	secretConfig := func(body string) string {
		return initConfig + fmt.Sprintf(`
		resource "ciphertrust_azure_secret" "secret" {
			vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
			%s
		}`, body)
	}

	nativeMode := `(?s)Invalid configuration for a native secret.*`
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The value is missing.
				Config:      secretConfig(`name = "tf-validation"`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(nativeMode + `Missing required attributes:\s+azure_params\.value`),
			},
			{
				// The name and the value are both missing, so one error lists both.
				Config:      secretConfig(`azure_params = { tags = { purpose = "validation" } }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(nativeMode + `Missing required attributes:\s+name,\s+azure_params\.value`),
			},
			{
				// Only the name is missing.
				Config:      secretConfig(`azure_params = { value = "tf-validation" }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(nativeMode + `Missing required attributes:\s+name\.`),
			},
			{
				// restore_secret cannot be combined with name.
				Config:      secretConfig(`name = "tf-validation"` + "\n" + `restore_secret = { secret_id = "11111111-1111-1111-1111-111111111111" }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
			{
				// restore_secret cannot be combined with azure_params.
				Config:      secretConfig(`azure_params = { value = "tf-validation" }` + "\n" + `restore_secret = { secret_id = "11111111-1111-1111-1111-111111111111" }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
			{
				// restore_secret needs secret_id.
				Config:      secretConfig(`restore_secret = {}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)secret_id.*required`),
			},
			{
				// The expiration date is not later than the activation date.
				Config: secretConfig(`name = "tf-validation"
			azure_params = {
				value = "tf-validation"
				attributes = {
					activation_date = "2030-01-01T00:00:00Z"
					expiration_date = "2029-01-01T00:00:00Z"
				}
			}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid expiration date`),
			},
			{
				// The name has characters that Azure does not allow.
				Config: secretConfig(`name = "tf_validation"
			azure_params = { value = "tf-validation" }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)alphanumeric`),
			},
			{
				// The date is not RFC3339.
				Config: secretConfig(`name = "tf-validation"
			azure_params = {
				value      = "tf-validation"
				attributes = { expiration_date = "2030-01-01" }
			}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)rfc3339`),
			},
		},
	})
}

// importStateVerifyIgnoreAzureSecret lists the attributes that are null after an import, because the API does not return
// them. ImportStateVerify ignores them.
var importStateVerifyIgnoreAzureSecret = []string{
	"azure_params.value",
	"azure_params.attributes.activation_date",
	"azure_params.attributes.expiration_date",
}

// TestCckmAzureSecretMaxConfigAndRecover creates a secret with every input in the nonpurgeable vault, then checks
// import, the in-place update, the immutable attributes, and the recover of a soft-deleted secret on create and
// on import. One secret is used for all of it to keep the cost down.
func TestCckmAzureSecretMaxConfigAndRecover(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureSecretMaxConfigAndRecover")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-secret-" + suffix
	resourceName := "ciphertrust_azure_secret.max_secret"

	activationTime := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	activationDate := activationTime.Format(time.RFC3339)
	expirationDate := activationTime.AddDate(1, 0, 0).Format(time.RFC3339)
	newActivationDate := activationTime.AddDate(0, 1, 0).Format(time.RFC3339)
	newExpirationDate := activationTime.AddDate(1, 1, 0).Format(time.RFC3339)

	// createConfig args: secret name, activation date, expiration date.
	createConfig := fmt.Sprintf(`
		resource "ciphertrust_azure_secret" "max_secret" {
			vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
			name     = %q
			azure_params = {
				value        = "tf-secret-value"
				content_type = "password"
				tags = {
					purpose = "secret-test"
					owner   = "terraform"
				}
				attributes = {
					enabled         = true
					activation_date = %q
					expiration_date = %q
				}
			}
		}`, name, activationDate, expirationDate)

	// Purge is off so that destroy soft-deletes the secret and recover is on so that creating a secret with the
	// name of a soft-deleted one recovers it.
	config := azureProviderSecretSettingsConfig(initConfig, false, true) + createConfig
	// Variants of the "create" config. Each ExpectError step changes one immutable attribute from the updated config.
	updateConfig := strings.NewReplacer(
		`content_type = "password"`, `content_type = "api-key"`,
		`purpose = "secret-test"`, `purpose = "secret-updated"`,
		`owner   = "terraform"`, `owner   = "terraform-updated"`,
		`enabled         = true`, `enabled         = false`,
		fmt.Sprintf(`activation_date = %q`, activationDate), fmt.Sprintf(`activation_date = %q`, newActivationDate),
		fmt.Sprintf(`expiration_date = %q`, expirationDate), fmt.Sprintf(`expiration_date = %q`, newExpirationDate),
	).Replace(config)
	immutableName := strings.Replace(updateConfig, fmt.Sprintf("name     = %q", name), fmt.Sprintf("name     = %q", name+"-x"), 1)
	immutableValue := strings.Replace(updateConfig, `value        = "tf-secret-value"`, `value        = "tf-secret-changed"`, 1)
	// clearTagsConfig is the updated config with the tags set to an empty map.
	clearTagsConfig := strings.Replace(updateConfig, `tags = {
					purpose = "secret-updated"
					owner   = "terraform-updated"
				}`, `tags = {}`, 1)

	// original holds the attributes of the secret after the tags are cleared. The recover steps at the end
	// compare the recovered secret against it and soft-delete it by its CipherTrust Manager id.
	var original map[string]string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with value checks. The framework fails the step if the plan after apply or refresh is not empty.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttrPair(resourceName, "vault_id", "ciphertrust_azure_vault.nonpurgeable_vault", "id"),
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					resource.TestCheckResourceAttrSet(resourceName, "version"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.secret_id"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.value", "tf-secret-value"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.content_type", "password"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "secret-test"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.owner", "terraform"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.attributes.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.attributes.activation_date", activationDate),
					resource.TestCheckResourceAttr(resourceName, "azure_params.attributes.expiration_date", expirationDate),
				),
			},
			{
				// Step 2: import reproduces the state. The value and the dates are not returned by the API.
				Config:                  config,
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAzureSecret,
			},
			{
				// Step 3: update content_type, tags, enabled and both dates in place.
				Config: updateConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "azure_params.content_type", "api-key"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "secret-updated"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.owner", "terraform-updated"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.attributes.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.attributes.activation_date", newActivationDate),
					resource.TestCheckResourceAttr(resourceName, "azure_params.attributes.expiration_date", newExpirationDate),
				),
			},
			{
				// Step 4: tags = {} removes all the tags.
				Config: clearTagsConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.%", "0"),
					azureCaptureCckmAttrs(resourceName, &original),
				),
			},
			{
				// Step 5: import reproduces the updated state.
				Config:                  clearTagsConfig,
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAzureSecret,
			},
			{
				// Step 6: name is immutable.
				Config:      immutableName,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Step 7: the value is immutable.
				Config:      immutableValue,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Step 8: soft-delete the secret out of band, then apply a config without it. Read keeps the
				// soft-deleted secret in state, so Terraform destroys it. Delete sees it is already soft-deleted
				// and removes it from state. The vault stays so its id is the same in step 11.
				PreConfig: func() {
					if err := azureSecretSoftDeleteOutOfBand(original["id"]); err != nil {
						t.Fatalf("out of band soft-delete of secret %s failed: %s", original["id"], err.Error())
					}
				},
				Config: azureProviderSecretSettingsConfig(initConfig, false, true),
				Check: func(s *terraform.State) error {
					if _, found := s.RootModule().Resources[resourceName]; found {
						return fmt.Errorf("resource %s is still in state", resourceName)
					}
					return nil
				},
			},
			{
				// Step 10: the cleared tags config finds the soft-deleted secret of the same name and recovers it.
				// The secret is recovered as is, so its id, version and attributes are unchanged. This also shows
				// the failed steps above left the secret recoverable.
				Config: clearTagsConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					azureCompareCckmAttrs(resourceName, &original),
				),
			},
		},
	})
}

// TestCckmAzureSecretMinConfigAndRestore creates a secret with only the required attributes in the purgeable vault
// and checks that the server-defaulted attributes are populated, the plan after apply and refresh is empty and
// import reproduces the state. The purgeable vault is used because it is the only vault that can purge, and a secret
// can only be restored once it is deleted. When the test below ends the secret is purged and CCKM keeps its record
// in the deleted state. A subtest then restores it into the nonpurgeable vault.
func TestCckmAzureSecretMinConfigAndRestore(t *testing.T) {
	initConfig, ok := initCckmAzureTestPurgeableVault()
	if !ok {
		t.Skip("Azure purgeable vault environment variables not set - skipping TestCckmAzureSecretMinConfigAndRestore")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-secret-min-" + suffix
	resourceName := "ciphertrust_azure_secret.min_secret"

	// createConfig args: secret name. Only the required attributes are set.
	createConfig := fmt.Sprintf(`
		resource "ciphertrust_azure_secret" "min_secret" {
			vault_id = ciphertrust_azure_vault.purgeable_vault.id
			name     = %q
			azure_params = {
				value = "tf-secret-value"
			}
		}`, name)

	// Purge is on so that destroy purges the secret from the purgeable vault. The restore subtest below needs the
	// secret to be in the deleted state in CCKM.
	config := azureProviderSecretSettingsConfig(initConfig, true, false) + createConfig

	// original holds the attributes of the created secret. The restore subtest restores this secret, so it needs
	// the CipherTrust Manager id and the name.
	var original map[string]string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with value checks. The framework fails the step if the plan after apply or refresh is not empty.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttrPair(resourceName, "vault_id", "ciphertrust_azure_vault.purgeable_vault", "id"),
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					resource.TestCheckResourceAttrSet(resourceName, "version"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.secret_id"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.value", "tf-secret-value"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.attributes.enabled"),
					azureCaptureCckmAttrs(resourceName, &original),
				),
			},
			{
				// Step 2: import reproduces the state. The value is not returned by the API.
				Config:                  config,
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: importStateVerifyIgnoreAzureSecret,
			},
		},
	})

	// The secret above was purged from the purgeable vault when the test above ended and CCKM keeps its record in
	// the deleted state. A secret can only be restored when it is deleted. This config re-adds the connection and
	// both vaults and restores the secret into the nonpurgeable vault by its CipherTrust Manager id.
	// Captured before the subtest starts because t inside the subtest is the subtest itself.
	parentFailed := t.Failed()
	t.Run("restore_into_nonpurgeable_vault", func(t *testing.T) {
		// Skip when the steps above failed. They leave resources behind that this subtest depends on.
		if parentFailed {
			t.Skip("earlier steps failed - skipping restore_into_nonpurgeable_vault")
		}
		if original["id"] == "" {
			t.Skip("secret id was not captured - skipping restore_into_nonpurgeable_vault")
		}
		restoredName := "ciphertrust_azure_secret.restored_secret"

		// restoreConfig args: secret id to restore.
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_secret" "restored_secret" {
				vault_id = ciphertrust_azure_vault.nonpurgeable_vault.id
				restore_secret = {
					secret_id = %q
				}
			}`, original["id"])

		// The nonpurgeable vault cannot purge, so purge on delete is off and destroy only soft-deletes the restored secret.
		restoreFullConfig := azureProviderSecretSettingsConfig(initConfig, false, false) + restoreConfig

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					// Restore the secret into the nonpurgeable vault. The framework fails the step if the plan
					// after apply or refresh is not empty.
					Config: restoreFullConfig,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(restoredName, "id", original["id"]),
						resource.TestCheckResourceAttr(restoredName, "name", original["name"]),
						resource.TestCheckResourceAttrPair(restoredName, "vault_id", "ciphertrust_azure_vault.nonpurgeable_vault", "id"),
						resource.TestCheckResourceAttr(restoredName, "status", "AVAILABLE"),
						resource.TestCheckResourceAttrSet(restoredName, "version"),
						resource.TestCheckResourceAttr(restoredName, "restore_secret.secret_id", original["id"]),
					),
				},
			},
		})
	})
}
