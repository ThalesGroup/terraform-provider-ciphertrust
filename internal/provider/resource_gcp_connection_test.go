package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func Test_CM_ResourceGCPConnection(t *testing.T) {
	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("Failed to set GCP connection variables")
	}

	name := "test-gcp-conn-" + uuid.New().String()[:8]

	// On CDSPaaS the "ddc" product is not supported for GCP connections (422).
	// Use "cckm" for both steps on CDSPaaS and still verify the update by
	// changing the description. On CM use "ddc" as originally intended.
	updateProduct := "ddc"
	if os.Getenv(envCDSPaaS) == "true" {
		updateProduct = "cckm"
	}

	createResourcesConfig := `
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name = %q
  products = [%q]
  key_file    = <<-EOT
    %s
  EOT
  cloud_name  = "gcp"
  description = %q
  labels = {
    "environment" = "devenv"
  }
  meta = {
    "custom_meta_key1"   = "custom_value1"
    "customer_meta_key2" = "custom_value2"
  }
}`

	createConfig := fmt.Sprintf(createResourcesConfig, name, "cckm", gcpKeyFile, "connection description")
	updateConfig := fmt.Sprintf(createResourcesConfig, name, updateProduct, gcpKeyFile, "updated connection description")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + createConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "private_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "client_email"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "cloud_name", "gcp"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", "cckm"),
				),
			},

			// Step 2: Update — product and description
			{
				Config: providerConfig + updateConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "private_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_gcp_connection.gcp_connection", "client_email"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "description", "updated connection description"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.gcp_connection", "products.0", updateProduct),
				),
			},

			// Step 3: cloud_name rejects unsupported values at plan time. Must not be
			// last — the OneOf validator also runs during the post-test destroy plan.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name       = %q
  key_file   = <<-EOT
    %s
  EOT
  cloud_name = "gcp-invalid"
}
`, name, gcpKeyFile),
				ExpectError: regexp.MustCompile(`(?i)value must be one of`),
				PlanOnly:    true,
			},

			// Step 4: renaming is immutable and fails at plan time. Kept last since
			// this plan modifier only fires on updates, not destroy.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_gcp_connection" "gcp_connection" {
  name     = "test-gcp-connection-renamed"
  key_file = <<-EOT
    %s
  EOT
}
`, gcpKeyFile),
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
				PlanOnly:    true,
			},
			// Step 5: Restore valid config so the framework can run a clean destroy.
			// Without this, the cleanup phase uses Step 4's config (gcp-invalid)
			// which the validator rejects, leaving dangling resources.
			{
				Config: providerConfig + updateConfig,
			},
		},
	})
}

func Test_CM_CipherTrust_GCPConnection_NameImmutable(t *testing.T) {
	RequireCM(t)
	if os.Getenv("GCP_KEY_FILE") == "" {
		t.Skip("GCP_KEY_FILE not set — skipping GCP connection immutability test")
	}
	t.Setenv("TF_VAR_gcp_key_file", os.Getenv("GCP_KEY_FILE"))

	gcpConnBase := `
variable "gcp_key_file" { sensitive = true }
resource "ciphertrust_gcp_connection" "test" {
  key_file = var.gcp_key_file
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + gcpConnBase + `  name = "tf-test-gcp-conn"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.test", "name", "tf-test-gcp-conn"),
				),
			},
			{
				Config: providerConfig + gcpConnBase + `  name = "tf-test-gcp-conn-renamed"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test

// Test_CM_AccGCPConnection_LabelsMetaKeyRemovalConverges verifies that removing
// a key from labels or meta converges cleanly — the provider must send null for
// the removed key so CM's merge-PATCH deletes it rather than preserving it (TFIN-602).
// Confirmed live: on-prem and CDSPaaS both correctly honour null for labels/meta on GCP.
func Test_CM_AccGCPConnection_LabelsMetaKeyRemovalConverges(t *testing.T) {
	gcpKeyFile := os.Getenv("CCKM_GOOGLE_KEY_FILE")
	if gcpKeyFile == "" {
		t.Skip("CCKM_GOOGLE_KEY_FILE not set")
	}
	name := "tf-602-gcp-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create with two labels and two meta keys.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_gcp_connection" "test" {
  name     = %q
  key_file = %q
  labels   = { env = "test", team = "vaqa" }
  meta     = { m1 = "v1", m2 = "v2" }
}`, name, gcpKeyFile),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.test", "labels.env", "test"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.test", "labels.team", "vaqa"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.test", "meta.m1", "v1"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.test", "meta.m2", "v2"),
				),
			},
			{
				// Step 2: remove "team" from labels and "m2" from meta.
				// Without the TFIN-602 fix, apply crashes with
				// "Provider produced inconsistent result: new element 'team' has appeared."
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_gcp_connection" "test" {
  name     = %q
  key_file = %q
  labels   = { env = "test" }
  meta     = { m1 = "v1" }
}`, name, gcpKeyFile),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.test", "labels.env", "test"),
					resource.TestCheckNoResourceAttr("ciphertrust_gcp_connection.test", "labels.team"),
					resource.TestCheckResourceAttr("ciphertrust_gcp_connection.test", "meta.m1", "v1"),
					resource.TestCheckNoResourceAttr("ciphertrust_gcp_connection.test", "meta.m2"),
				),
				// Second plan after apply must be empty — both keys fully converged.
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
