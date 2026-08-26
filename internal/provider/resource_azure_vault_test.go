package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAzureVault_basic(t *testing.T) {
	RequireCM(t)
	connID := os.Getenv("AZURE_CONNECTION_ID")
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	vaultJSON := os.Getenv("AZURE_STANDARD_VAULT_JSON")
	if connID == "" || subID == "" || vaultJSON == "" {
		t.Skip("AZURE_CONNECTION_ID, AZURE_SUBSCRIPTION_ID, and AZURE_STANDARD_VAULT_JSON must be set")
	}
	name := "tf-azure-vault-" + uuid.New().String()[:8]

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}`, name, connID, subID, vaultJSON)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "basic-create",
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "azure_vault_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "subscription_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "created_at"),
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

func TestCckmAzureVault_acls(t *testing.T) {
	RequireCM(t)
	connID := os.Getenv("AZURE_CONNECTION_ID")
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	vaultJSON := os.Getenv("AZURE_STANDARD_VAULT_JSON")
	if connID == "" || subID == "" || vaultJSON == "" {
		t.Skip("AZURE_CONNECTION_ID, AZURE_SUBSCRIPTION_ID, and AZURE_STANDARD_VAULT_JSON must be set")
	}
	name := "tf-azure-vault-" + uuid.New().String()[:8]

	cfgBase := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}`, name, connID, subID, vaultJSON)

	cfgWithAcls := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
  acls {
    group      = "admin"
    allow_list = ["ReadKey"]
  }
}`, name, connID, subID, vaultJSON)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfgBase,
				Check: checkStep(t, "acls-create",
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "id"),
				),
			},
			{
				Config: cfgWithAcls,
				Check: checkStep(t, "acls-add",
					resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "acls.%", "1"),
				),
			},
			{
				Config: cfgBase,
				Check: checkStep(t, "acls-remove",
					resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "acls.%", "0"),
				),
			},
		},
	})
}

func TestCckmAzureVault_rotation(t *testing.T) {
	RequireCM(t)
	connID := os.Getenv("AZURE_CONNECTION_ID")
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	vaultJSON := os.Getenv("AZURE_STANDARD_VAULT_JSON")
	if connID == "" || subID == "" || vaultJSON == "" {
		t.Skip("AZURE_CONNECTION_ID, AZURE_SUBSCRIPTION_ID, and AZURE_STANDARD_VAULT_JSON must be set")
	}
	name := "tf-azure-vault-" + uuid.New().String()[:8]

	cfgBase := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}`, name, connID, subID, vaultJSON)

	cfgRotationEnabled := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name                = %q
  connection_id       = %q
  subscription_id     = %q
  azure               = %q
  enable_rotation     = true
  rotation_job_params = jsonencode({cloud_name = "AzureCloud"})
}`, name, connID, subID, vaultJSON)

	cfgRotationDisabled := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
  enable_rotation = false
}`, name, connID, subID, vaultJSON)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfgBase,
				Check: checkStep(t, "rotation-base",
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "id"),
				),
			},
			{
				Config: cfgRotationEnabled,
				Check: checkStep(t, "rotation-enable",
					resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "enable_rotation", "true"),
				),
			},
			{
				Config:             cfgRotationEnabled,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cfgRotationDisabled,
				Check: checkStep(t, "rotation-disable",
					resource.TestCheckResourceAttr("ciphertrust_azure_vault.test", "enable_rotation", "false"),
				),
			},
		},
	})
}

func TestCckmAzureVault_import(t *testing.T) {
	RequireCM(t)
	connID := os.Getenv("AZURE_CONNECTION_ID")
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	vaultJSON := os.Getenv("AZURE_STANDARD_VAULT_JSON")
	if connID == "" || subID == "" || vaultJSON == "" {
		t.Skip("AZURE_CONNECTION_ID, AZURE_SUBSCRIPTION_ID, and AZURE_STANDARD_VAULT_JSON must be set")
	}
	name := "tf-azure-vault-" + uuid.New().String()[:8]

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}`, name, connID, subID, vaultJSON)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "import-create",
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "id"),
				),
			},
			{
				ResourceName:      "ciphertrust_azure_vault.test",
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateVerifyIgnore: []string{
					"connection_id",
					"managed_hsm",
					"azure",
					"enable_rotation",
					"rotation_job_params",
				},
			},
		},
	})
}

func TestCckmAzureVault_immutable(t *testing.T) {
	RequireCM(t)
	connID := os.Getenv("AZURE_CONNECTION_ID")
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	vaultJSON := os.Getenv("AZURE_STANDARD_VAULT_JSON")
	if connID == "" || subID == "" || vaultJSON == "" {
		t.Skip("AZURE_CONNECTION_ID, AZURE_SUBSCRIPTION_ID, and AZURE_STANDARD_VAULT_JSON must be set")
	}
	name := "tf-azure-vault-" + uuid.New().String()[:8]

	cfgOriginal := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}`, name, connID, subID, vaultJSON)

	changedConnID := connID + "-changed"
	cfgChanged := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}`, name, changedConnID, subID, vaultJSON)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfgOriginal,
				Check: checkStep(t, "immutable-create",
					resource.TestCheckResourceAttrSet("ciphertrust_azure_vault.test", "id"),
				),
			},
			{
				Config:      cfgChanged,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

func TestCckmAzureVault_datasource(t *testing.T) {
	RequireCM(t)
	connID := os.Getenv("AZURE_CONNECTION_ID")
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	vaultJSON := os.Getenv("AZURE_STANDARD_VAULT_JSON")
	if connID == "" || subID == "" || vaultJSON == "" {
		t.Skip("AZURE_CONNECTION_ID, AZURE_SUBSCRIPTION_ID, and AZURE_STANDARD_VAULT_JSON must be set")
	}
	name := "tf-azure-vault-" + uuid.New().String()[:8]

	cfgWithDS := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}

data "ciphertrust_azure_vaults" "test" {
  name       = %q
  depends_on = [ciphertrust_azure_vault.test]
}`, name, connID, subID, vaultJSON, name)

	cfgEmptyDS := providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_vault" "test" {
  name            = %q
  connection_id   = %q
  subscription_id = %q
  azure           = %q
}

data "ciphertrust_azure_vaults" "test" {
  name       = "nonexistent-vault-zzz-no-match"
  depends_on = [ciphertrust_azure_vault.test]
}`, name, connID, subID, vaultJSON)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfgWithDS,
				Check: checkStep(t, "ds-match",
					resource.TestCheckResourceAttrSet("data.ciphertrust_azure_vaults.test", "resources.0.id"),
					resource.TestCheckResourceAttr("data.ciphertrust_azure_vaults.test", "resources.#", "1"),
				),
			},
			{
				Config: cfgEmptyDS,
				Check: checkStep(t, "ds-empty",
					resource.TestCheckResourceAttr("data.ciphertrust_azure_vaults.test", "resources.#", "0"),
				),
			},
		},
	})
}
