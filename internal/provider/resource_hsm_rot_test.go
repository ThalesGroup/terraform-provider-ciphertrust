package provider

import (
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"testing"
)

func TestResourceHSMRootOfTrustSetupLuna(t *testing.T) {
	// Remove skip after actual HSM data is used in test
	t.Skip("Skipped!! dummy data in resource parameters")

	// Create HSM RoT Setup with type "luna"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: providerConfig + `
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "luna"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  initial_config = {
    host           = "10.10.10.10"
    serial         = "1234"
    server-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert-key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
  reset = true
  delay = 50
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "type", "luna"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.%", "4"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.host", "10.10.10.10"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.partition_name", "kylo-partition"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.serial", "1234"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test

func TestResourceHSMRootOfTrustSetupLunaPCI(t *testing.T) {
	// Remove skip after actual HSM data is used in test
	t.Skip("Skipped!! dummy data in resource parameters")

	// Create HSM RoT Setup with type "lunapci"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: providerConfig + `
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "lunapci"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  reset = true
  delay = 50
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "type", "lunapci"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "sub_type", "k7"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.%", "1"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.partition_name", "kylo-partition"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test

func TestResourceHSMRootOfTrustSetupLunatct(t *testing.T) {
	// Remove skip after actual HSM data is used in test
	t.Skip("Skipped!! dummy data in resource parameters")

	// Create HSM RoT Setup with type "lunatct"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{Config: providerConfig + `
resource "ciphertrust_hsm_root_of_trust_setup" "cm_hsm_rot_setup" {
  type         = "lunatct"
  conn_info = {
    partition_name     = "kylo-partition"
    partition_password = "sOmeP@ssword"
  }
  initial_config = {
    host           = "10.10.10.10"
    serial         = "1234"
    server-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert    = "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    client-cert-key = "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
  }
  reset = true
  delay = 50
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "id"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "type", "lunatct"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.%", "4"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.host", "10.10.10.10"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.partition_name", "kylo-partition"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.cm_hsm_rot_setup", "config.serial", "1234"),
				),
			},
		},
	})
}

// terraform destroy will perform automatically at the end of the test
