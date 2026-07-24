// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_ResourceAzureConnection(t *testing.T) {
	// Use a unique name to avoid 409 conflicts from prior failed runs.
	name := "TestAzureConnection-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// creating a Azure connection
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_connection" "azure_connection" {
  name = %q
  client_id="3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"
  tenant_id= "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  client_secret="3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"
  cloud_name= "AzureCloud"
  products = [
    "cckm"
  ]
  description = "a description of the connection"
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1" = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }
}
`, name),

				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_azure_connection.azure_connection", "id"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "tenant_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c71285nfjdu2"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "description", "a description of the connection"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "client_id", "3bf0dbe6-a2c7-431d-9a6f-4843b74c7e12"),
				),
			},

			// Step 2: Update the resource
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_connection" "azure_connection" {
  name        = %q
  client_id   = "updated-client-id"
  tenant_id   = "updated-tenant-id"
  products    = ["cckm"]
  description = "updated description of the connection"
}
`, name),

				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "tenant_id", "updated-tenant-id"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "description", "updated description of the connection"),
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.azure_connection", "client_id", "updated-client-id"),
				),
			},

			// Step 3: cloud_name rejects unsupported values at plan time. Must not be
			// last — the OneOf validator also runs during the post-test destroy plan.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_connection" "azure_connection" {
  name      = %q
  client_id = "updated-client-id"
  tenant_id = "updated-tenant-id"
  products  = ["cckm"]
}
`, name+"-renamed"),
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
				PlanOnly:    true,
			},

			// Step 4: renaming is immutable and fails at plan time. Kept last since
			// this plan modifier only fires on updates, not destroy.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_connection" "azure_connection" {
  name       = %q
  client_id  = "updated-client-id"
  tenant_id  = "updated-tenant-id"
  products   = ["cckm"]
  cloud_name = "AzureBogusCloud"
}
`, name),
				ExpectError: regexp.MustCompile(`(?i)value must be one of`),
				PlanOnly:    true,
			},
			// Step 5: Restore valid config so the framework can run a clean destroy.
			// Without this, the cleanup phase uses Step 4's config (AzureBogusCloud)
			// which the validator rejects, leaving dangling resources.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_azure_connection" "azure_connection" {
  name        = %q
  client_id   = "updated-client-id"
  tenant_id   = "updated-tenant-id"
  products    = ["cckm"]
  description = "updated description of the connection"
}
`, name),
			},
		},
	})
}

func Test_CM_CipherTrust_AzureConnection_NameImmutable(t *testing.T) {
	RequireCM(t)
	if os.Getenv("AZURE_CLIENT_ID") == "" || os.Getenv("AZURE_TENANT_ID") == "" || os.Getenv("AZURE_CLIENT_SECRET") == "" {
		t.Skip("AZURE_CLIENT_ID / AZURE_TENANT_ID / AZURE_CLIENT_SECRET not set — skipping Azure connection immutability test")
	}
	t.Setenv("TF_VAR_azure_client_secret", os.Getenv("AZURE_CLIENT_SECRET"))

	azureConnBase := fmt.Sprintf(`
variable "azure_client_secret" { sensitive = true }
resource "ciphertrust_azure_connection" "test" {
  client_id     = %q
  tenant_id     = %q
  client_secret = var.azure_client_secret
`, os.Getenv("AZURE_CLIENT_ID"), os.Getenv("AZURE_TENANT_ID"))

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + azureConnBase + `  name = "tf-test-azure-conn"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_azure_connection.test", "name", "tf-test-azure-conn"),
				),
			},
			{
				Config: providerConfig + azureConnBase + `  name = "tf-test-azure-conn-renamed"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
