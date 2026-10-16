package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// azureProviderCertSettingsConfig returns config with the Azure certificate delete settings added to the
// provider block. The settings in the config of a test run apply to every certificate destroyed at the end
// of that run. Do not combine it with azureProviderSettingsConfig, which adds its own cloud_key_manager block.
func azureProviderCertSettingsConfig(config string, purgeCertificatesOnDelete, recoverSoftDeletedCertificates bool) string {
	settings := fmt.Sprintf(`provider "ciphertrust" {
		cloud_key_manager = {
			azure = {
				purge_certificates_on_delete      = %t
				recover_soft_deleted_certificates = %t
			}
		}
	`, purgeCertificatesOnDelete, recoverSoftDeletedCertificates)
	return strings.Replace(config, `provider "ciphertrust" {`, settings, 1)
}

// azureCertSoftDeleteOutOfBand soft-deletes the certificate with the CipherTrust Manager API, outside of
// Terraform. The certificate keeps its ID and stays in the vault. The error is returned so the test can fail.
func azureCertSoftDeleteOutOfBand(certID string) error {
	client, ok := createCMClient()
	if !ok {
		return fmt.Errorf("unable to create a CipherTrust Manager client")
	}
	_, err := client.PostNoData(context.Background(), uuid.New().String(), common.URL_AZURE+"/certificates/"+certID+"/soft-delete")
	if err != nil {
		fmt.Printf("azureCertSoftDeleteOutOfBand failed err: %s\n", err.Error())
	}
	return err
}

// azureCertCaptureAttrs copies every attribute of the resource in state into attrs.
func azureCertCaptureAttrs(resourceName string, attrs *map[string]string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		captured := make(map[string]string, len(rs.Primary.Attributes))
		for k, v := range rs.Primary.Attributes {
			captured[k] = v
		}
		*attrs = captured
		return nil
	}
}

// azureCertCompareAttrs checks that the resource in state has the same attributes as the ones captured earlier.
// Recover only makes a soft-deleted certificate available again, so everything except the attributes in
// ignore (status and updated_at by default) must be identical, including id and version.
func azureCertCompareAttrs(resourceName string, attrs *map[string]string, ignore ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found in state", resourceName)
		}
		if len(*attrs) == 0 {
			return fmt.Errorf("no attributes were captured for %s", resourceName)
		}
		skip := map[string]bool{"status": true, "updated_at": true}
		for _, k := range ignore {
			skip[k] = true
		}
		var diffs []string
		for k, want := range *attrs {
			if skip[k] {
				continue
			}
			if got, found := rs.Primary.Attributes[k]; !found || got != want {
				diffs = append(diffs, fmt.Sprintf("%s: want %q, got %q", k, want, got))
			}
		}
		for k, got := range rs.Primary.Attributes {
			if _, found := (*attrs)[k]; !found && !skip[k] {
				diffs = append(diffs, fmt.Sprintf("%s: unexpected value %q", k, got))
			}
		}
		if len(diffs) > 0 {
			sort.Strings(diffs)
			return fmt.Errorf("recovered certificate differs from the original:\n%s", strings.Join(diffs, "\n"))
		}
		return nil
	}
}

// The validation tests in this file only plan. ModifyPlan reports one aggregated error per mode. Where a
// schema validator (ConflictsWith, AlsoRequires) fires before ModifyPlan, the expected error is the schema one.

// initCckmAzureCertAndPrivateKeyTest returns the configuration from initCckmAzureTest plus the locals
// azure_cert_pem and azure_cert_private_key_pem. It returns false when the Azure environment variables,
// CCKM_TF_AZURE_CERT_PEM or CCKM_TF_AZURE_CERT_ENCRYPTED_PRIVATE_KEY_PEM are not set.
func initCckmAzureCertAndPrivateKeyTest(timeout ...int) (string, bool) {
	certPem := os.Getenv("CCKM_TF_AZURE_CERT_PEM")
	privateKeyPem := os.Getenv("CCKM_TF_AZURE_CERT_ENCRYPTED_PRIVATE_KEY_PEM")
	if certPem == "" || privateKeyPem == "" {
		return "", false
	}
	initConfig, ok := initCckmAzureTest(timeout...)
	if !ok {
		return "", false
	}
	localsConfig := fmt.Sprintf(`
		locals {
			azure_cert_pem             = %q
			azure_cert_private_key_pem = %q
		}`, certPem, privateKeyPem)
	return initConfig + localsConfig, true
}

// initCckmAzureCertPfxTest returns the configuration from initCckmAzureTest plus the local
// azure_cert_pfx_b64. It returns false when the Azure environment variables or
// CCKM_TF_AZURE_CERT_ENCRYPTED_PFX_B64 are not set.
func initCckmAzureCertPfxTest(timeout ...int) (string, bool) {
	pfxB64 := os.Getenv("CCKM_TF_AZURE_CERT_ENCRYPTED_PFX_B64")
	if pfxB64 == "" {
		return "", false
	}
	initConfig, ok := initCckmAzureTest(timeout...)
	if !ok {
		return "", false
	}
	localsConfig := fmt.Sprintf(`
		locals {
			azure_cert_pfx_b64 = %q
		}`, pfxB64)
	return initConfig + localsConfig, true
}

// TestCckmAzureCertificateValidationNative checks a native create without a name or without a policy.
func TestCckmAzureCertificateValidationNative(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureCertificateValidationNative")
	}

	nameOnlyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
		}`

	tagsOnlyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			azure_params = {
				tags = { purpose = "validation" }
			}
		}`

	policyNoNameConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			azure_params = {
				policy = {
					issuer     = { name = "Self" }
					key_props  = { kty = "RSA" }
					x509_props = { subject = "CN=tf-validation" }
				}
			}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The policy is missing.
				Config:      nameOnlyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for a native.*Missing required attributes:\s+azure_params\.policy`),
			},
			{
				// The name and the policy are both missing, so one error lists both.
				Config:      tagsOnlyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for a native.*Missing required attributes:\s+name,\s+azure_params\.policy`),
			},
			{
				// Only the name is missing.
				Config:      policyNoNameConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for a native.*Missing required attributes:\s+name\.`),
			},
		},
	})
}

// TestCckmAzureCertificateValidationRestore checks that restore_certificate rejects name and azure_params.
func TestCckmAzureCertificateValidationRestore(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureCertificateValidationRestore")
	}

	config := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			restore_certificate = {
				certificate_id = "placeholder-certificate-id"
			}
			azure_params = {
				tags = { purpose = "validation" }
			}
		}`

	nameOnlyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			restore_certificate = {
				certificate_id = "placeholder-certificate-id"
			}
		}`

	paramsOnlyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			restore_certificate = {
				certificate_id = "placeholder-certificate-id"
			}
			azure_params = {
				tags = { purpose = "validation" }
			}
		}`

	emptyBlockConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			restore_certificate = {}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      config,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for restore_certificate.*Attributes not allowed:\s+name,\s+azure_params`),
			},
			{
				// Only the name is not allowed.
				Config:      nameOnlyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for restore_certificate.*Attributes not allowed:\s+name\.`),
			},
			{
				// Only azure_params is not allowed.
				Config:      paramsOnlyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for restore_certificate.*Attributes not allowed:\s+azure_params\.`),
			},
			{
				// Schema: certificate_id is required.
				Config:      emptyBlockConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)certificate_id.*required`),
			},
		},
	})
}

// TestCckmAzureCertificateValidationUpload checks the upload_certificate requirements.
func TestCckmAzureCertificateValidationUpload(t *testing.T) {
	initConfig, ok := initCckmAzureCertAndPrivateKeyTest()
	if !ok {
		t.Skip("Azure or certificate environment variables not set - skipping TestCckmAzureCertificateValidationUpload")
	}

	emptyBlockConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id           = ciphertrust_azure_vault.standard_vault.id
			upload_certificate = {}
		}`

	noNameConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			upload_certificate = {
				certificate     = local.azure_cert_pem
				private_key_pem = local.azure_cert_private_key_pem
			}
			azure_params = {
				tags = { purpose = "validation" }
			}
		}`

	noPrivateKeyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			upload_certificate = {
				source_cert_id = "placeholder-source-id"
				ca_id          = "placeholder-ca-id"
			}
		}`

	certificateWithCaConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			upload_certificate = {
				certificate     = local.azure_cert_pem
				source_cert_id  = "placeholder-source-id"
				ca_id           = "placeholder-ca-id"
				private_key_pem = local.azure_cert_private_key_pem
			}
		}`

	privateKeyOnlyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			upload_certificate = {
				private_key_pem = local.azure_cert_private_key_pem
			}
		}`

	caOnlyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			upload_certificate = {
				ca_id = "placeholder-ca-id"
			}
		}`

	noCaIdConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			upload_certificate = {
				source_cert_id  = "placeholder-source-id"
				private_key_pem = local.azure_cert_private_key_pem
			}
		}`

	certificateWithPolicyConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			upload_certificate = {
				certificate     = local.azure_cert_pem
				private_key_pem = local.azure_cert_private_key_pem
			}
			azure_params = {
				policy = {
					issuer     = { name = "Self" }
					key_props  = { kty = "RSA" }
					x509_props = { subject = "CN=tf-validation" }
				}
			}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Nothing is set, so the name and the certificate source are both missing.
				Config:      emptyBlockConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for upload_certificate.*Missing required attributes:\s+name,\s+upload_certificate\.certificate`),
			},
			{
				// Only the name is missing.
				Config:      noNameConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for upload_certificate.*Missing required attributes:\s+name\.`),
			},
			{
				// Schema validator: source_cert_id requires private_key_pem.
				Config:      noPrivateKeyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination.*private_key_pem.*must\s+be\s+specified\s+when`),
			},
			{
				// Schema validator: certificate cannot be used with source_cert_id.
				Config:      certificateWithCaConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
			{
				// The private key alone implies a certificate from the CA, so source_cert_id and ca_id are missing.
				Config:      privateKeyOnlyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for upload_certificate.*Missing required attributes:\s+upload_certificate\.source_cert_id,\s+upload_certificate\.ca_id\.`),
			},
			{
				// Schema validator: ca_id requires source_cert_id.
				Config:      caOnlyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination.*source_cert_id.*must\s+be\s+specified\s+when`),
			},
			{
				// Schema validator: source_cert_id requires ca_id.
				Config:      noCaIdConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid Attribute Combination.*ca_id.*must\s+be\s+specified\s+when`),
			},
			{
				// Schema validator: upload_certificate cannot be used with azure_params.policy.
				Config:      certificateWithPolicyConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
		},
	})
}

// TestCckmAzureCertificateValidationUploadPfx checks the upload_certificate requirements for a PFX.
func TestCckmAzureCertificateValidationUploadPfx(t *testing.T) {
	initConfig, ok := initCckmAzureCertPfxTest()
	if !ok {
		t.Skip("Azure or PFX environment variables not set - skipping TestCckmAzureCertificateValidationUploadPfx")
	}

	noNameConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			upload_certificate = {
				certificate = local.azure_cert_pfx_b64
			}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      noNameConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Invalid configuration for upload_certificate.*Missing required attributes:\s+name\.`),
			},
		},
	})
}

// TestCckmAzureCertificateValidationConflicts checks that restore_certificate and upload_certificate
// cannot both be set.
func TestCckmAzureCertificateValidationConflicts(t *testing.T) {
	initConfig, ok := initCckmAzureCertAndPrivateKeyTest()
	if !ok {
		t.Skip("Azure or certificate environment variables not set - skipping TestCckmAzureCertificateValidationConflicts")
	}

	restoreAndUploadConfig := initConfig + `
		resource "ciphertrust_azure_certificate" "cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = "tf-validation"
			restore_certificate = {
				certificate_id = "placeholder-certificate-id"
			}
			upload_certificate = {
				certificate     = local.azure_cert_pem
				private_key_pem = local.azure_cert_private_key_pem
			}
		}`

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      restoreAndUploadConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
		},
	})
}

// TestCckmAzureCertificateMaxConfigAndRecover exercises a native ciphertrust_azure_certificate in the standard vault
// with every attribute set. It checks the in-place update and that the immutable attributes are rejected. It then
// soft-deletes the certificate out of band, removes it from state and applies the same config again. Create
// recovers the soft-deleted certificate, which is identical to the original. The subtests run in order and share
// one certificate to keep the number of certificates created small.
func TestCckmAzureCertificateMaxConfigAndRecover(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureCertificateMaxConfigAndRecover")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-native-" + suffix
	subject := "CN=" + name
	resourceName := "ciphertrust_azure_certificate.native_cert"

	// createConfig args: certificate name, subject.
	createConfig := fmt.Sprintf(`
		resource "ciphertrust_azure_certificate" "native_cert" {
			vault_id = ciphertrust_azure_vault.standard_vault.id
			name     = %q
			azure_params = {
				tags = {
					purpose = "native-test"
					owner   = "terraform"
				}
				policy = {
					issuer = { name = "Self" }
					key_props = {
						kty        = "RSA"
						key_size   = 4096
						exportable = true
						reuse_key  = true
					}
					x509_props = {
						subject         = %q
						validity_months = 12
						key_usage       = ["digitalSignature", "keyEncipherment"]
						enhanced_key_usage = ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"]
						sans = {
							dns_names            = ["a.example.com", "b.example.com"]
							emails               = ["tf@example.com"]
							user_principal_names = ["tf@example.com"]
						}
					}
					attributes = {
						enabled = true
					}
					secret_props = {
						content_type = "application/x-pkcs12"
					}
					lifetime_actions = [{
						trigger = { lifetime_percentage = 80 }
						action  = { action_type = "AutoRenew" }
					}]
				}
			}
		}`, name, subject)

	// Purge is off so that destroy soft-deletes the certificate and recover is on so that creating a certificate
	// with the name of a soft-deleted one recovers it.
	config := azureProviderCertSettingsConfig(initConfig, false, true) + createConfig
	// Variants of the "create" certificate config. Each ExpectError step changes one immutable attribute from the updated config.
	updateConfig := strings.NewReplacer(
		`purpose = "native-test"`, `purpose = "native-updated"`,
		`owner   = "terraform"`, `owner   = "terraform-updated"`,
		`enabled = true`, `enabled = false`,
	).Replace(config)
	immutableName := strings.Replace(updateConfig, fmt.Sprintf("name     = %q", name), fmt.Sprintf("name     = %q", name+"-x"), 1)
	immutableKeyProps := strings.Replace(updateConfig, `key_size   = 4096`, `key_size   = 2048`, 1)
	immutableX509 := strings.Replace(updateConfig, `validity_months = 12`, `validity_months = 24`, 1)
	immutableSecret := strings.Replace(updateConfig, `application/x-pkcs12`, `application/x-pem-file`, 1)
	immutableLifetime := strings.Replace(updateConfig, `lifetime_percentage = 80`, `lifetime_percentage = 70`, 1)
	// noRecoverConfig is the updated config with recover_soft_deleted_certificates set to false.
	noRecoverConfig := strings.Replace(updateConfig, `recover_soft_deleted_certificates = true`, `recover_soft_deleted_certificates = false`, 1)

	// original holds the attributes of the certificate after the in-place update. The recover steps at the end
	// compare the recovered certificate against it and soft-delete it by its CipherTrust Manager id.
	var original map[string]string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Subtest 1: create with value checks. The framework fails the step if the plan after apply or refresh is not empty.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttrPair(resourceName, "vault_id", "ciphertrust_azure_vault.standard_vault", "id"),
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					resource.TestCheckResourceAttrSet(resourceName, "version"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "native-test"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.owner", "terraform"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.issuer.name", "Self"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.kty", "RSA"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.key_size", "4096"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.exportable", "true"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.reuse_key", "true"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.subject", subject),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.validity_months", "12"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.key_usage.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "azure_params.policy.x509_props.key_usage.*", "digitalSignature"),
					resource.TestCheckTypeSetElemAttr(resourceName, "azure_params.policy.x509_props.key_usage.*", "keyEncipherment"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.enhanced_key_usage.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "azure_params.policy.x509_props.enhanced_key_usage.*", "1.3.6.1.5.5.7.3.1"),
					resource.TestCheckTypeSetElemAttr(resourceName, "azure_params.policy.x509_props.enhanced_key_usage.*", "1.3.6.1.5.5.7.3.2"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.sans.dns_names.#", "2"),
					resource.TestCheckTypeSetElemAttr(resourceName, "azure_params.policy.x509_props.sans.dns_names.*", "a.example.com"),
					resource.TestCheckTypeSetElemAttr(resourceName, "azure_params.policy.x509_props.sans.dns_names.*", "b.example.com"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.sans.emails.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.sans.user_principal_names.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.attributes.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.secret_props.content_type", "application/x-pkcs12"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.lifetime_actions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.lifetime_actions.0.action.action_type", "AutoRenew"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.lifetime_actions.0.trigger.lifetime_percentage", "80"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.attributes.activation_date"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.attributes.expiration_date"),
				),
			},
			{
				// Subtest 2: import reproduces the state.
				Config:            config,
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Subtest 3: update the tags and attributes.enabled in place. The id must not change.
				Config: updateConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "native-updated"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.owner", "terraform-updated"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.attributes.enabled", "false"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.key_size", "4096"),
					azureCertCaptureAttrs(resourceName, &original),
				),
			},
			{
				// Subtest 4: import reproduces the updated state.
				Config:            updateConfig,
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Subtest 5: name is immutable.
				Config:      immutableName,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Subtest 6: key_props is immutable.
				Config:      immutableKeyProps,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Subtest 7: x509_props is immutable.
				Config:      immutableX509,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Subtest 8: secret_props is immutable.
				Config:      immutableSecret,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Subtest 9: lifetime_actions is immutable.
				Config:      immutableLifetime,
				ExpectError: regexp.MustCompile(`Attribute is immutable`),
			},
			{
				// Subtest 10: soft-delete the certificate out of band, then apply a config without it. Read keeps the
				// soft-deleted certificate in state, so Terraform destroys it. Delete sees it is already soft-deleted
				// and removes it from state. The vault stays so its id is the same in subtest 13.
				PreConfig: func() {
					if err := azureCertSoftDeleteOutOfBand(original["id"]); err != nil {
						t.Fatalf("out of band soft-delete of certificate %s failed: %s", original["id"], err.Error())
					}
				},
				Config: azureProviderCertSettingsConfig(initConfig, false, true),
				Check: func(s *terraform.State) error {
					if _, found := s.RootModule().Resources[resourceName]; found {
						return fmt.Errorf("resource %s is still in state", resourceName)
					}
					return nil
				},
			},
			{
				// Subtest 11: with recover_soft_deleted_certificates false, create does not recover the soft-deleted
				// certificate of the same name. The create operation goes ahead and fails because the name is still taken.
				Config:      noRecoverConfig,
				ExpectError: regexp.MustCompile(`Error creating Azure certificate`),
			},
			{
				// Subtest 12: with recover_soft_deleted_certificates false, importing the soft-deleted certificate
				// fails, and it is not recovered. The id is given because the resource is not in state.
				Config:            noRecoverConfig,
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateIdFunc: func(*terraform.State) (string, error) { return original["id"], nil },
				ExpectError:       regexp.MustCompile(`recover_soft_deleted_certificates to true`),
			},
			{
				// Subtest 13: the updated config finds the soft-deleted certificate of the same name and recovers it.
				// The certificate is recovered as is, so its id, version and attributes are unchanged. This also shows
				// the failed steps above left the certificate recoverable.
				Config: updateConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					azureCertCompareAttrs(resourceName, &original),
				),
			},
		},
	})
}

// TestCckmAzureCertificateNativeMinConfigAndRestore creates a native certificate with only the required attributes
// in the premium vault and checks that the server-defaulted attributes are populated, the plan after apply and
// refresh is empty and import reproduces the state. The premium vault is used because it is the only vault that can
// purge, and a certificate can only be restored once it is deleted. When the test above ends the certificate is
// purged and CCKM keeps its record in the deleted state. A subtest then restores it into the standard vault.
func TestCckmAzureCertificateNativeMinConfigAndRestore(t *testing.T) {
	initConfig, ok := initCckmAzureTestPremiumVault()
	if !ok {
		t.Skip("Azure premium vault environment variables not set - skipping TestCckmAzureCertificateNativeMinConfigAndRestore")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-native-min-" + suffix
	subject := "CN=" + name
	resourceName := "ciphertrust_azure_certificate.native_min"

	// createConfig args: certificate name, subject. Only the required attributes are set.
	createConfig := fmt.Sprintf(`
	resource "ciphertrust_azure_certificate" "native_min" {
		vault_id = ciphertrust_azure_vault.premium_vault.id
		name     = %q
		azure_params = {
			policy = {
				issuer = { name = "Self" }
				key_props = {
					kty      = "RSA"
					key_size = 2048
				}
				x509_props = {
					subject         = %q
					validity_months = 12
				}
				lifetime_actions = [{
					trigger = { lifetime_percentage = 80 }
					action  = { action_type = "AutoRenew" }
				}]
			}
		}
	}`, name, subject)

	// Purge is on so that destroy purges the certificate from the premium vault. The restore subtest below needs
	// the certificate to be in the deleted state in CCKM.
	config := azureProviderCertSettingsConfig(initConfig, true, false) + createConfig

	// original holds the attributes of the created certificate. The restore subtest restores this certificate,
	// so it needs the CipherTrust Manager id and the name.
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
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					resource.TestCheckResourceAttrSet(resourceName, "version"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.issuer.name", "Self"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.kty", "RSA"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.key_size", "2048"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.subject", subject),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.validity_months", "12"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.x509_props.key_usage.#"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.x509_props.enhanced_key_usage.#"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.key_props.exportable"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.key_props.reuse_key"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.secret_props.content_type"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.attributes.enabled"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.attributes.activation_date"),
					resource.TestCheckResourceAttrSet(resourceName, "azure_params.policy.attributes.expiration_date"),
					azureCertCaptureAttrs(resourceName, &original),
				),
			},
			{
				// Step 2: import reproduces the state.
				Config:            config,
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})

	// The certificate above was purged from the premium vault when the test above ended and CCKM keeps its record
	// in the deleted state. A certificate can only be restored when it is deleted. This config re-adds the
	// connection and both vaults and restores the certificate into the standard vault by its CipherTrust Manager id.
	// Captured before the subtest starts because t inside the subtest is the subtest itself.
	parentFailed := t.Failed()
	t.Run("restore_into_standard_vault", func(t *testing.T) {
		// Skip when the steps above failed. They leave resources behind that this subtest depends on.
		if parentFailed {
			t.Skip("earlier steps failed - skipping restore_into_standard_vault")
		}
		if original["id"] == "" {
			t.Skip("certificate id was not captured - skipping restore_into_standard_vault")
		}
		restoredName := "ciphertrust_azure_certificate.restored_cert"

		// restoreConfig args: certificate id to restore.
		restoreConfig := fmt.Sprintf(`
			resource "ciphertrust_azure_certificate" "restored_cert" {
				vault_id = ciphertrust_azure_vault.standard_vault.id
				restore_certificate = {
					certificate_id = %q
				}
			}`, original["id"])

		// The standard vault cannot purge, so purge on delete is off and destroy only soft-deletes the restored certificate.
		restoreFullConfig := azureProviderCertSettingsConfig(initConfig, false, false) + restoreConfig

		resource.Test(t, resource.TestCase{
			PreCheck:                 func() { cleanupCckmAzureVaults() },
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					// Restore the certificate into the standard vault. The framework fails the step if the plan
					// after apply or refresh is not empty.
					Config: restoreFullConfig,
					Check: resource.ComposeAggregateTestCheckFunc(
						resource.TestCheckResourceAttr(restoredName, "id", original["id"]),
						resource.TestCheckResourceAttr(restoredName, "name", original["name"]),
						resource.TestCheckResourceAttrPair(restoredName, "vault_id", "ciphertrust_azure_vault.standard_vault", "id"),
						resource.TestCheckResourceAttr(restoredName, "status", "AVAILABLE"),
						resource.TestCheckResourceAttrSet(restoredName, "version"),
						resource.TestCheckResourceAttr(restoredName, "restore_certificate.certificate_id", original["id"]),
						resource.TestCheckResourceAttr(restoredName, "azure_params.policy.key_props.key_size", "2048"),
					),
				},
			},
		})
	})
}

// TestCckmAzureCertificateNativeECConfig creates an EC (P-256) certificate with an EmailContacts lifetime
// action, checks import and the in-place update of tags and enabled, and checks that the immutable
// attributes are rejected. It then soft-deletes the certificate out of band, removes it from state and imports
// it by the captured ID. Import recovers the certificate, which is identical to the original.
func TestCckmAzureCertificateNativeECConfigAndImport(t *testing.T) {
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureCertificateNativeECConfig")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-native-ec-" + suffix
	subject := "CN=" + name
	resourceName := "ciphertrust_azure_certificate.native_ec"

	// createConfig args: certificate name, subject. No key_size is set for an EC key.
	createConfig := fmt.Sprintf(`
	resource "ciphertrust_azure_certificate" "native_ec" {
		vault_id   = ciphertrust_azure_vault.standard_vault.id
		depends_on = [ciphertrust_azure_vault.standard_vault]
		name       = %q
		azure_params = {
			tags = { purpose = "native-ec-test" }
			policy = {
				issuer = { name = "Self" }
				key_props = {
					kty   = "EC"
					curve = "P-256"
				}
				x509_props = {
					subject         = %q
					validity_months = 12
				}
				attributes = { enabled = true }
				lifetime_actions = [{
					trigger = { days_before_expiry = 20 }
					action  = { action_type = "EmailContacts" }
				}]
			}
		}
	}`, name, subject)

	// minimalResource has only vault_id and name. azure_params is not needed because the certificate is already
	// in state when it is planned, so the policy comes from state. It is used for the
	// import so the plan after import shows which attributes the import brings in that a minimal config does not set.
	minimalResource := fmt.Sprintf(`
	resource "ciphertrust_azure_certificate" "native_ec" {
		vault_id   = ciphertrust_azure_vault.standard_vault.id
		depends_on = [ciphertrust_azure_vault.standard_vault]
		name       = %q
	}`, name)

	// Two list data sources used once after create. The name filter limits each to this certificate.
	dataSources := fmt.Sprintf(`
	data "ciphertrust_azure_certificate_list" "by_alg" {
		depends_on = [ciphertrust_azure_certificate.native_ec]
		filters = {
			cert_name = %q
			algorithm = "EC"
		}
	}
	data "ciphertrust_azure_certificate_list" "by_curve" {
		depends_on = [ciphertrust_azure_certificate.native_ec]
		filters = {
			cert_name = %q
			curve     = "P-256"
		}
	}
	data "ciphertrust_azure_certificate_list" "by_curve_lower" {
		depends_on = [ciphertrust_azure_certificate.native_ec]
		filters = {
			cert_name = %q
			curve     = "p-256"
		}
	}`, name, name, name)

	// Variants of the resource. They are built before initConfig is added so a replacement cannot match it.
	updateResource := strings.NewReplacer(
		`purpose = "native-ec-test"`, `purpose = "native-ec-updated"`,
		`enabled = true`, `enabled = false`,
	).Replace(createConfig)
	build := func(resourceConfig string) string {
		return azureProviderCertSettingsConfig(initConfig, false, true) + resourceConfig
	}
	config := build(createConfig)
	configWithDataSources := build(createConfig + dataSources)
	updateConfig := build(updateResource)
	minimalConfig := build(minimalResource)
	immutableCurve := build(strings.Replace(updateResource, `curve = "P-256"`, `curve = "P-384"`, 1))
	immutableKty := build(strings.Replace(updateResource, `kty   = "EC"`, `kty   = "RSA"`, 1))
	immutableValidity := build(strings.Replace(updateResource, `validity_months = 12`, `validity_months = 24`, 1))
	immutableLifetime := build(strings.Replace(updateResource, `days_before_expiry = 20`, `days_before_expiry = 30`, 1))
	immutableIssuer := build(strings.Replace(updateResource, `issuer = { name = "Self" }`, `issuer = { name = "Unknown" }`, 1))

	// Purge is off so that destroy soft-deletes the certificate. Recover is on so that import recovers it.
	noCertConfig := azureProviderCertSettingsConfig(initConfig, false, true)
	var original map[string]string
	var capturedID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with value checks. The framework fails the step if the plan after apply or refresh is not empty.
				// The by_alg and by_curve data sources must each return this certificate.
				Config: configWithDataSources,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					resource.TestMatchResourceAttr("data.ciphertrust_azure_certificate_list.by_alg", "matched", regexp.MustCompile(`^[1-9]`)),
					resource.TestCheckResourceAttrPair("data.ciphertrust_azure_certificate_list.by_alg", "certificates.0.id", resourceName, "id"),
					resource.TestMatchResourceAttr("data.ciphertrust_azure_certificate_list.by_curve", "matched", regexp.MustCompile(`^[1-9]`)),
					resource.TestCheckResourceAttrPair("data.ciphertrust_azure_certificate_list.by_curve", "certificates.0.id", resourceName, "id"),
					resource.TestMatchResourceAttr("data.ciphertrust_azure_certificate_list.by_curve_lower", "matched", regexp.MustCompile(`^[1-9]`)),
					resource.TestCheckResourceAttrPair("data.ciphertrust_azure_certificate_list.by_curve_lower", "certificates.0.id", resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "native-ec-test"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.kty", "EC"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.key_props.curve", "P-256"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.subject", subject),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.x509_props.validity_months", "12"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.attributes.enabled", "true"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.lifetime_actions.#", "1"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.lifetime_actions.0.action.action_type", "EmailContacts"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.lifetime_actions.0.trigger.days_before_expiry", "20"),
					azureCertCaptureAttrs(resourceName, &original),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: import reproduces the state.
				Config:            config,
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			{
				// Step 3: update the tags and attributes.enabled in place.
				Config: updateConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "native-ec-updated"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.policy.attributes.enabled", "false"),
					// A closure so capturedID is read when the check runs, not when the steps are built.
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						if rs.Primary.ID != capturedID {
							return fmt.Errorf("id changed on update: was %q, now %q", capturedID, rs.Primary.ID)
						}
						return nil
					},
				),
			},
			{
				// Step 4: import reproduces the updated state.
				Config:            updateConfig,
				ResourceName:      resourceName,
				ImportState:       true,
				ImportStateVerify: true,
			},
			// Steps 5-9: every immutable attribute is rejected at plan time.
			{Config: immutableCurve, ExpectError: regexp.MustCompile(`Attribute is immutable`)},
			{Config: immutableKty, ExpectError: regexp.MustCompile(`Attribute is immutable`)},
			{Config: immutableValidity, ExpectError: regexp.MustCompile(`Attribute is immutable`)},
			{Config: immutableLifetime, ExpectError: regexp.MustCompile(`Attribute is immutable`)},
			{Config: immutableIssuer, ExpectError: regexp.MustCompile(`Attribute is immutable`)},
			{
				// Step 10: soft-delete out of band, then apply a config without the certificate. Delete sees it is
				// already soft-deleted and removes it from state. The vault stays.
				PreConfig: func() {
					if err := azureCertSoftDeleteOutOfBand(capturedID); err != nil {
						t.Fatalf("out of band soft-delete of certificate %s failed: %s", capturedID, err.Error())
					}
				},
				Config: noCertConfig,
				Check: func(s *terraform.State) error {
					if _, found := s.RootModule().Resources[resourceName]; found {
						return fmt.Errorf("resource %s is still in state", resourceName)
					}
					return nil
				},
			},
			{
				// Step 11: import by the captured ID. Import recovers the soft-deleted certificate. The imported
				// state matches the original except for status and updated_at. The state is kept for step 12.
				Config:             minimalConfig,
				ResourceName:       resourceName,
				ImportState:        true,
				ImportStatePersist: true,
				ImportStateIdFunc:  func(_ *terraform.State) (string, error) { return capturedID, nil },
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					var found *terraform.InstanceState
					for _, st := range states {
						if st.ID == capturedID {
							found = st
							break
						}
					}
					if found == nil {
						return fmt.Errorf("no imported resource with id %q among %d imported resources", capturedID, len(states))
					}
					imported := found.Attributes
					if imported["status"] != "AVAILABLE" {
						return fmt.Errorf("imported certificate status is %q, expected AVAILABLE", imported["status"])
					}
					for _, key := range []string{"id", "name", "version", "vault_id", "kid", "azure_params.policy.key_props.curve"} {
						if imported[key] != original[key] {
							return fmt.Errorf("imported %s is %q, original is %q", key, imported[key], original[key])
						}
					}
					return nil
				},
			},
			{
				// Step 12: plan the imported state with the minimal config. The recovered certificate still has
				// the updated tags and enabled = false, so any difference in the plan shows which attributes
				// the import brings in that a minimal config does not set.
				Config:   minimalConfig,
				PlanOnly: true,
			},
			{
				// Step 13: remove the imported certificate while the vault stays, so the certificate is
				// deleted on its own and cannot race with the vault removal at the end of the test.
				Config: noCertConfig,
				Check: func(s *terraform.State) error {
					if _, found := s.RootModule().Resources[resourceName]; found {
						return fmt.Errorf("resource %s is still in state", resourceName)
					}
					return nil
				},
			},
		},
	})
}

// azureCertCreateCMSignedCert creates a certificate in CipherTrust Manager, outside of Terraform, for the
// upload test. It uses the first active local CA, generates an unencrypted RSA key and CSR, and has the CA sign
// the CSR. It returns the CA id, the id of the signed certificate and the private key PEM. Any failure fails
// the test. The certificate is deleted from CipherTrust Manager when the test finishes.
func azureCertCreateCMSignedCert(t *testing.T, name string) (caID string, certID string, privateKeyPem string) {
	t.Helper()
	client, ok := createCMClient()
	if !ok {
		t.Fatalf("unable to create a CipherTrust Manager client")
	}
	ctx := context.Background()

	// Step 1: the first active local CA.
	filters := url.Values{}
	filters.Add("state", "active")
	filters.Add("limit", "1")
	response, err := client.ListWithFilters(ctx, uuid.New().String(), common.URL_LOCAL_CA, filters)
	if err != nil {
		t.Fatalf("failed to list local CAs: %s", err)
	}
	var cas struct {
		Resources []struct {
			ID string `json:"id"`
		} `json:"resources"`
	}
	if err := json.Unmarshal([]byte(response), &cas); err != nil {
		t.Fatalf("failed to parse the local CA list: %s", err)
	}
	if len(cas.Resources) == 0 || cas.Resources[0].ID == "" {
		t.Fatalf("no active local CA found")
	}
	caID = cas.Resources[0].ID

	// Step 2: an unencrypted RSA key and its CSR. Nothing is stored in CipherTrust Manager.
	csrBody, err := json.Marshal(map[string]interface{}{
		"cn":        name,
		"algorithm": "RSA",
		"size":      2048,
	})
	if err != nil {
		t.Fatalf("failed to marshal the CSR request: %s", err)
	}
	response, err = client.PostDataV2(ctx, uuid.New().String(), "api/v1/ca/csr", csrBody)
	if err != nil {
		t.Fatalf("failed to create the CSR: %s", err)
	}
	var csr struct {
		Csr string `json:"csr"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(response), &csr); err != nil {
		t.Fatalf("failed to parse the CSR response: %s", err)
	}
	if csr.Csr == "" || csr.Key == "" {
		t.Fatalf("the CSR response has no csr or key")
	}
	privateKeyPem = csr.Key

	// Step 3: the local CA signs the CSR.
	certBody, err := json.Marshal(map[string]interface{}{
		"name":     name,
		"csr":      csr.Csr,
		"purpose":  "server",
		"duration": 30,
	})
	if err != nil {
		t.Fatalf("failed to marshal the certificate request: %s", err)
	}
	certsEndpoint := common.URL_LOCAL_CA + "/" + caID + "/certs"
	response, err = client.PostDataV2(ctx, uuid.New().String(), certsEndpoint, certBody)
	if err != nil {
		t.Fatalf("failed to issue the certificate from CA %s: %s", caID, err)
	}
	var issued struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(response), &issued); err != nil {
		t.Fatalf("failed to parse the issued certificate: %s", err)
	}
	if issued.ID == "" {
		t.Fatalf("the issued certificate has no id")
	}
	certID = issued.ID

	return caID, certID, privateKeyPem
}

// TestCckmAzureCertificateUploadLocal uploads a certificate signed by a CipherTrust Manager local CA. The
// certificate and its key are created outside of Terraform. Only azure_params.tags can be set with an upload.
// It is skipped on CDSPaaS, which has no certificate upload endpoint.
func TestCckmAzureCertificateUploadLocal(t *testing.T) {
	if os.Getenv(envCDSPaaS) == "true" {
		t.Skip("Certificate upload is not supported in CDSPaaS - skipping TestCckmAzureCertificateUploadLocal")
	}
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureCertificateUploadLocal")
	}
	azureCertConfig := azureProviderCertSettingsConfig(initConfig, false, true)

	suffix := uuid.New().String()[:8]
	name := "tf-upload-cm-" + suffix
	resourceName := "ciphertrust_azure_certificate.upload_cm"
	caID, sourceCertID, privateKeyPem := azureCertCreateCMSignedCert(t, name)

	// createConfig args: certificate name, source certificate id, CA id, private key.
	createConfig := fmt.Sprintf(`
	resource "ciphertrust_azure_certificate" "upload_cm" {
		vault_id   = ciphertrust_azure_vault.standard_vault.id
		depends_on = [ciphertrust_azure_vault.standard_vault]
		name       = %q
		azure_params = {
			tags = { purpose = "upload-cm-signed" }
		}
		upload_certificate = {
			source_cert_id  = %q
			ca_id           = %q
			private_key_pem = %q
		}
	}`, name, sourceCertID, caID, privateKeyPem)
	updateResource := strings.Replace(createConfig, `purpose = "upload-cm-signed"`, `purpose = "upload-cm-updated"`, 1)
	config := azureCertConfig + createConfig
	updateConfig := azureCertConfig + updateResource
	// The configuration a user has right after terraform import: no upload_certificate block.
	importedResource := fmt.Sprintf(`
	resource "ciphertrust_azure_certificate" "upload_cm" {
		vault_id   = ciphertrust_azure_vault.standard_vault.id
		depends_on = [ciphertrust_azure_vault.standard_vault]
		name       = %q
		azure_params = {
			tags = { purpose = "upload-cm-updated" }
		}
	}`, name)
	importedConfig := azureCertConfig + importedResource
	afterImportConfig := azureCertConfig + strings.Replace(createConfig, `purpose = "upload-cm-signed"`, `purpose = "upload-cm-after-import"`, 1)
	var capturedID string

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create by uploading the CipherTrust Manager certificate.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "status", "AVAILABLE"),
					resource.TestCheckResourceAttrSet(resourceName, "version"),
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "upload-cm-signed"),
					resource.TestCheckResourceAttr(resourceName, "upload_certificate.source_cert_id", sourceCertID),
					resource.TestCheckResourceAttr(resourceName, "upload_certificate.ca_id", caID),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: update the tags in place. The id must not change.
				Config: updateConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "upload-cm-updated"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						if rs.Primary.ID != capturedID {
							return fmt.Errorf("id changed on update: was %q, now %q", capturedID, rs.Primary.ID)
						}
						return nil
					},
				),
			},
			{
				// Step 3: import. The private key is never returned by the API, so it is ignored.
				Config:                  updateConfig,
				ResourceName:            resourceName,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"upload_certificate"},
			},
			{
				// Step 4: remove the certificate from state while the vault and connection stay. With
				// purge_certificates_on_delete false the certificate is soft-deleted, so it can be imported
				// again. The persisted import in the next step needs the resource to be out of state.
				Config: azureCertConfig,
				Check: func(s *terraform.State) error {
					if _, found := s.RootModule().Resources[resourceName]; found {
						return fmt.Errorf("resource %s is still in state", resourceName)
					}
					return nil
				},
			},
			{
				// Step 5: import and keep the imported state, which is what a user has after terraform import.
				// The soft-deleted certificate is recovered. The upload_certificate block is not returned by
				// the API, so it must be absent from state.
				Config:             importedConfig,
				ResourceName:       resourceName,
				ImportState:        true,
				ImportStatePersist: true,
				ImportStateIdFunc:  func(_ *terraform.State) (string, error) { return capturedID, nil },
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					var found *terraform.InstanceState
					for _, st := range states {
						if st.ID == capturedID {
							found = st
							break
						}
					}
					if found == nil {
						return fmt.Errorf("no imported resource with id %q among %d imported resources", capturedID, len(states))
					}
					for key := range found.Attributes {
						if strings.HasPrefix(key, "upload_certificate.") {
							return fmt.Errorf("imported state has %s, expected no upload_certificate block", key)
						}
					}
					if found.Attributes["azure_params.tags.purpose"] != "upload-cm-updated" {
						return fmt.Errorf("imported azure_params.tags.purpose is %q, expected upload-cm-updated", found.Attributes["azure_params.tags.purpose"])
					}
					return nil
				},
			},
			{
				// Step 6: plan the imported state with a config that has no upload_certificate block. It must
				// plan cleanly, with no unknown or changed attributes.
				Config:   importedConfig,
				PlanOnly: true,
			},
			{
				// Step 7: add the upload_certificate block to the imported resource. The ID must not change and
				// the block must be populated from the configuration, including source_cert_id.
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "upload-cm-signed"),
					resource.TestCheckResourceAttr(resourceName, "upload_certificate.source_cert_id", sourceCertID),
					resource.TestCheckResourceAttr(resourceName, "upload_certificate.ca_id", caID),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						if rs.Primary.ID != capturedID {
							return fmt.Errorf("id changed after adding upload_certificate: was %q, now %q", capturedID, rs.Primary.ID)
						}
						return nil
					},
				),
			},
			{
				// Step 8: change the tags with the block present after the import.
				Config: afterImportConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "azure_params.tags.purpose", "upload-cm-after-import"),
					resource.TestCheckResourceAttr(resourceName, "upload_certificate.source_cert_id", sourceCertID),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						if rs.Primary.ID != capturedID {
							return fmt.Errorf("id changed on update: was %q, now %q", capturedID, rs.Primary.ID)
						}
						return nil
					},
				),
			},
		},
	})
}

// TestCckmAzureCertificateWithIssuer creates a certificate with a certificate authority (CA) issuer in the
// standard vault instead of the Self issuer. CCKM_TF_FAKE_AZURE_CA is the name of that issuer. The test is
// skipped when it is not set.
//
// THIS TEST IS EXPECTED TO FAIL TO CREATE. The issuer is a CA registered in the Azure key vault with dummy
// values (for example a DigiCert provider with a made up account ID and organization ID), so Azure can never
// issue the certificate. The certificate is accepted, then goes to the failed state. The create must report
// that error and nothing must be left in Terraform state. To run it, add a certificate authority with dummy
// values to the standard vault in the Azure portal (Certificates > Certificate Authorities > Add) and set
// CCKM_TF_FAKE_AZURE_CA to its name.
func TestCckmAzureCertificateWithIssuer(t *testing.T) {
	issuerName := os.Getenv("CCKM_TF_FAKE_AZURE_CA")
	if issuerName == "" {
		t.Skip("CCKM_TF_FAKE_AZURE_CA not set - skipping TestCckmAzureCertificateWithIssuer")
	}
	initConfig, ok := initCckmAzureTest()
	if !ok {
		t.Skip("Azure environment variables not set - skipping TestCckmAzureCertificateWithIssuer")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-issuer-" + suffix
	subject := "CN=" + name

	// createConfig args: certificate name, issuer name, subject.
	createConfig := fmt.Sprintf(`
	resource "ciphertrust_azure_certificate" "with_issuer" {
		vault_id   = ciphertrust_azure_vault.standard_vault.id
		depends_on = [ciphertrust_azure_vault.standard_vault]
		name       = %q
		azure_params = {
			policy = {
				issuer = { name = %q }
				key_props = {
					kty   = "EC"
					curve = "P-256"
				}
				x509_props = {
					subject         = %q
					validity_months = 12
				}
				attributes = { enabled = true }
			}
		}
	}`, name, issuerName, subject)

	config := azureProviderCertSettingsConfig(initConfig, false, true) + createConfig

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAzureVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// The create fails when the certificate reports the failed state, or when waiting for it
				// times out. Either way no certificate is left in state.
				Config:      config,
				ExpectError: regexp.MustCompile(`(?s)Error creating Azure certificate.*(the operation failed|timed out)`),
			},
		},
	})
}
