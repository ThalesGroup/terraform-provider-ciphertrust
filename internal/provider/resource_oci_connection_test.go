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

// Test_CM_CckmOCIConnection exercises the full lifecycle of the ciphertrust_oci_connection resource:
// Create, RefreshState, ImportState, Update (description change), and Update (region change).
func Test_CM_CckmOCIConnection(t *testing.T) {
	ociKeyFile := os.Getenv("CCKM_OCI_KEY_FILE")
	ociPubKeyFP := os.Getenv("CCKM_OCI_FINGERPRINT")
	ociRegion := os.Getenv("CCKM_OCI_REGION")
	ociTenancyOCID := os.Getenv("CCKM_OCI_CONN_TENANCY")
	ociUserOCID := os.Getenv("CCKM_OCI_USER")
	ok := ociKeyFile != "" && ociPubKeyFP != "" && ociRegion != "" && ociTenancyOCID != "" && ociUserOCID != ""
	if !ok {
		t.Skip("Skipping OCI connection test: required environment variables not set " +
			"(CCKM_OCI_KEY_FILE, CCKM_OCI_FINGERPRINT, CCKM_OCI_REGION, CCKM_OCI_CONN_TENANCY, CCKM_OCI_USER)")
	}

	connectionTemplate := `
		resource "ciphertrust_oci_connection" "connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
			%s
		}`

	name := "tf-" + uuid.New().String()[:8]
	connectionResource := "ciphertrust_oci_connection.connection"

	// Step 1 config - no description
	createConfig := fmt.Sprintf(connectionTemplate,
		ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID, "")

	// Step 4 config - add description
	updateConfig := fmt.Sprintf(connectionTemplate,
		ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID,
		`description = "Updated by Terraform test"`)

	// Step 5 config - change region (in-place update, no replacement)
	updatedRegion := "us-phoenix-1"
	if ociRegion == updatedRegion {
		updatedRegion = "us-ashburn-1"
	}
	regionUpdateConfig := fmt.Sprintf(connectionTemplate,
		ociKeyFile, name, ociPubKeyFP, updatedRegion, ociTenancyOCID, ociUserOCID,
		`description = "Updated by Terraform test"`)

	// Step 6 config - rename the connection (must return an error, not corrupt state)
	renamedConfig := fmt.Sprintf(connectionTemplate,
		ociKeyFile, name+"-renamed", ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID, "")

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmOCIVaults() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create and verify core attributes
			{
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(connectionResource, "id"),
					resource.TestCheckResourceAttr(connectionResource, "name", name),
					resource.TestCheckResourceAttr(connectionResource, "region", ociRegion),
					resource.TestCheckResourceAttr(connectionResource, "tenancy_ocid", ociTenancyOCID),
					resource.TestCheckResourceAttr(connectionResource, "user_ocid", ociUserOCID),
					resource.TestCheckResourceAttr(connectionResource, "pub_key_fingerprint", ociPubKeyFP),
					resource.TestCheckResourceAttr(connectionResource, "products.#", "1"),
					resource.TestCheckResourceAttr(connectionResource, "products.0", "cckm"),
					resource.TestCheckResourceAttrSet(connectionResource, "created_at"),
					resource.TestCheckResourceAttr(connectionResource, "last_connection_ok", "true"),
				),
			},
			// Step 2: RefreshState - verify state is consistent with the API
			{
				RefreshState: true,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(connectionResource, "id"),
					resource.TestCheckResourceAttr(connectionResource, "name", name),
					resource.TestCheckResourceAttr(connectionResource, "region", ociRegion),
				),
			},
			// Step 3: ImportState - verify the resource can be re-imported by ID
			{
				ResourceName:            connectionResource,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"key_file", "key_file_pass_phrase", "skip_connection_params_test"},
			},
			// Step 4: Update - change description and verify it is reflected in state
			{
				Config: updateConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(connectionResource, "id"),
					resource.TestCheckResourceAttr(connectionResource, "name", name),
					resource.TestCheckResourceAttr(connectionResource, "description", "Updated by Terraform test"),
					resource.TestCheckResourceAttr(connectionResource, "region", ociRegion),
					resource.TestCheckResourceAttr(connectionResource, "last_connection_ok", "true"),
				),
			},
			// Step 5: Update region in-place - must succeed without replacement and without
			// "Provider produced inconsistent result after apply" (regression test for bug fix).
			{
				Config: regionUpdateConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(connectionResource, "id"),
					resource.TestCheckResourceAttr(connectionResource, "name", name),
					resource.TestCheckResourceAttr(connectionResource, "region", updatedRegion),
				),
			},
			// Step 6: Attempt to rename the connection - must return a clear provider error and
			// leave the resource untouched on CM (regression test for bug fix).
			{
				Config:      renamedConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
		},
	})
}

// Test_CM_CckmOCIConnectionNameImmutable is a focused regression test that verifies the provider
// returns a clear, actionable error (not a framework-level "inconsistent result") when the
// user attempts to change the immutable 'name' field of an OCI connection.
func Test_CM_CckmOCIConnectionNameImmutable(t *testing.T) {
	ociKeyFile := os.Getenv("CCKM_OCI_KEY_FILE")
	ociPubKeyFP := os.Getenv("CCKM_OCI_FINGERPRINT")
	ociRegion := os.Getenv("CCKM_OCI_REGION")
	ociTenancyOCID := os.Getenv("CCKM_OCI_CONN_TENANCY")
	ociUserOCID := os.Getenv("CCKM_OCI_USER")
	ok := ociKeyFile != "" && ociPubKeyFP != "" && ociRegion != "" && ociTenancyOCID != "" && ociUserOCID != ""
	if !ok {
		t.Skip("Skipping OCI connection name-immutability test: required environment variables not set")
	}

	name := "tf-" + uuid.New().String()[:8]
	connectionResource := "ciphertrust_oci_connection.connection"

	tmpl := `
		resource "ciphertrust_oci_connection" "connection" {
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}`

	createConfig := fmt.Sprintf(tmpl, ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	renameConfig := fmt.Sprintf(tmpl, ociKeyFile, name+"-renamed", ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the connection.
			{
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(connectionResource, "id"),
					resource.TestCheckResourceAttr(connectionResource, "name", name),
				),
			},
			// Step 2: Attempt rename — provider must return a clear error; no state corruption.
			{
				Config:      renameConfig,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
			// Step 3: Re-apply original config — state must still be intact and consistent.
			{
				Config: createConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(connectionResource, "name", name),
				),
			},
		},
	})
}

func Test_CM_CipherTrust_OCIConnection_NameImmutable(t *testing.T) {
	RequireCM(t)
	if os.Getenv("OCI_USER_OCID") == "" || os.Getenv("OCI_TENANCY_OCID") == "" {
		t.Skip("OCI_USER_OCID / OCI_TENANCY_OCID not set — skipping OCI connection immutability test")
	}
	t.Setenv("TF_VAR_oci_key_file", os.Getenv("OCI_KEY_FILE"))

	fingerprint := os.Getenv("OCI_FINGERPRINT")
	region := os.Getenv("OCI_REGION")
	tenancyOCID := os.Getenv("OCI_TENANCY_OCID")
	userOCID := os.Getenv("OCI_USER_OCID")

	ociConnBase := fmt.Sprintf(`
variable "oci_key_file" { sensitive = true }
resource "ciphertrust_oci_connection" "test" {
  key_file              = var.oci_key_file
  pub_key_fingerprint   = %q
  region                = %q
  tenancy_ocid          = %q
  user_ocid             = %q
  skip_connection_params_test = true
`, fingerprint, region, tenancyOCID, userOCID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + ociConnBase + `  name = "tf-test-oci-conn"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_oci_connection.test", "name", "tf-test-oci-conn"),
				),
			},
			{
				Config: providerConfig + ociConnBase + `  name = "tf-test-oci-conn-renamed"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed|cannot update`),
			},
		},
	})
}
