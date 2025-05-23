package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestOciConnection(t *testing.T) {
	ociKeyFile := os.Getenv("OCI_KEYFILE")
	ociPubKeyFP := os.Getenv("OCI_PUBKEY_FP")
	ociRegion := os.Getenv("OCI_REGION")
	ociTenancyOCID := os.Getenv("OCI_TENANCY_OCID")
	ociUserOCID := os.Getenv("OCI_USER_OCID")
	ok := ociKeyFile != "" && ociPubKeyFP != "" && ociRegion != "" && ociTenancyOCID != "" && ociUserOCID != ""
	if !ok {
		t.Skip("Failed to set OCI connection variables")
	}
	minParamsConfig := `
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
	maxParamsConfig := `
		resource "ciphertrust_oci_connection" "connection" {
			description = "connection desc"
			meta        = { meta-key = "meta-value" }
			key_file = <<-EOT
			%s
			EOT
			name                = "%s"
			pub_key_fingerprint = "%s"
			region              = "%s"
			tenancy_ocid        = "%s"
			user_ocid           = "%s"
		}`
	name := "tf-" + uuid.New().String()[:8]
	minParamsConfigStr := fmt.Sprintf(minParamsConfig, ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	maxParamsConfigStr := fmt.Sprintf(maxParamsConfig, ociKeyFile, name, ociPubKeyFP, ociRegion, ociTenancyOCID, ociUserOCID)
	connectionResource := "ciphertrust_oci_connection.connection"

	t.Run("MinParamsToMax", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: minParamsConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(connectionResource, "meta.%", "0"),
					),
				},
				{
					Config: maxParamsConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(connectionResource, "meta.%", "1"),
						resource.TestCheckResourceAttr(connectionResource, "meta.meta-key", "meta-value"),
						resource.TestCheckResourceAttr(connectionResource, "description", "connection desc"),
					),
				},
				{
					Config: minParamsConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(connectionResource, "meta.%", "0"),
						testCheckAttributeNotSet(connectionResource, "description"),
					),
				},
			},
		})
	})

	t.Run("MaxParamsToMin", func(t *testing.T) {
		resource.Test(t, resource.TestCase{
			ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
			Steps: []resource.TestStep{
				{
					Config: maxParamsConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(connectionResource, "meta.%", "1"),
						resource.TestCheckResourceAttr(connectionResource, "meta.meta-key", "meta-value"),
						resource.TestCheckResourceAttr(connectionResource, "description", "connection desc"),
					),
				},
				{
					Config: minParamsConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(connectionResource, "meta.%", "0"),
						testCheckAttributeNotSet(connectionResource, "description"),
					),
				},
				{
					Config: maxParamsConfigStr,
					Check: resource.ComposeTestCheckFunc(
						resource.TestCheckResourceAttr(connectionResource, "meta.%", "1"),
						resource.TestCheckResourceAttr(connectionResource, "meta.meta-key", "meta-value"),
						resource.TestCheckResourceAttr(connectionResource, "description", "connection desc"),
					),
				},
			},
		})
	})
}
