package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceTrialLicense(t *testing.T) {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	bootstrap := "no"

	if address == "" || username == "" || password == "" {
		t.Fatal("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, and CIPHERTRUST_PASSWORD must be set for testing")
	}

	providerConfig := fmt.Sprintf(providerConfig, address, username, password, bootstrap)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_trial_license" "trial_license" {
  }
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_trial_license.trial_license", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}
