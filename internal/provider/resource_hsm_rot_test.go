package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceHSMRootOfTrustSetupLuna(t *testing.T) {
	RequireCM(t)
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
	RequireCM(t)
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
	RequireCM(t)
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

// hsmRotConfig returns an HCL config for the HSM root-of-trust resource.
func hsmRotConfig(hsmType, connInfoPartitionName, connInfoPartitionPassword string, reset bool, delay int64) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_hsm_root_of_trust_setup" "test" {
  type  = %q
  conn_info = {
    partition_name     = %q
    partition_password = %q
  }
  reset = %v
  delay = %d
}
`, hsmType, connInfoPartitionName, connInfoPartitionPassword, reset, delay)
}

// hsmRotConfigWithType returns an HCL config with the given type (all other fields fixed).
func hsmRotConfigWithType(hsmType string) string {
	return hsmRotConfig(hsmType, "test-partition", "test-password", true, 5)
}

// hsmRotConfigWithConnInfo returns an HCL config with the given conn_info partition_name (type fixed).
func hsmRotConfigWithConnInfo(partitionName string) string {
	return hsmRotConfig("lunapci", partitionName, "test-password", true, 5)
}

// hsmRotConfigWithReset returns an HCL config with the given reset value (all other fields fixed).
func hsmRotConfigWithReset(reset bool) string {
	return hsmRotConfig("lunapci", "test-partition", "test-password", reset, 5)
}

// TestCipherTrust_HSMRot_NoDrift verifies that after apply, a subsequent plan shows no changes.
func TestCipherTrust_HSMRot_NoDrift(t *testing.T) {
	RequireCM(t)
	t.Skip("Skipped — requires a live HSM appliance connected to CipherTrust Manager")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: hsmRotConfig("lunapci", "test-partition", "test-password", true, 5),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_hsm_root_of_trust_setup.test", "type", "lunapci"),
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "sub_type"),
				),
			},
			{
				// RefreshState re-reads from the API using the config from the previous step.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCipherTrust_HSMRot_ImmutableType verifies that changing the type field after creation
// emits an immutability error at plan time (not destroy+recreate).
func TestCipherTrust_HSMRot_ImmutableType(t *testing.T) {
	RequireCM(t)
	t.Skip("Skipped — requires a live HSM appliance connected to CipherTrust Manager")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: hsmRotConfig("lunapci", "test-partition", "test-password", true, 5),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config:      hsmRotConfigWithType("luna"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// TestCipherTrust_HSMRot_ImmutableConnInfo verifies that changing conn_info after creation
// emits an immutability error at plan time.
func TestCipherTrust_HSMRot_ImmutableConnInfo(t *testing.T) {
	RequireCM(t)
	t.Skip("Skipped — requires a live HSM appliance connected to CipherTrust Manager")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: hsmRotConfig("lunapci", "partition-one", "test-password", true, 5),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config:      hsmRotConfigWithConnInfo("partition-two"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// TestCipherTrust_HSMRot_ImmutableReset verifies that changing the reset field after creation
// emits an immutability error at plan time.
func TestCipherTrust_HSMRot_ImmutableReset(t *testing.T) {
	RequireCM(t)
	t.Skip("Skipped — requires a live HSM appliance connected to CipherTrust Manager")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: hsmRotConfig("lunapci", "test-partition", "test-password", true, 5),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config:      hsmRotConfigWithReset(false),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// TestCipherTrust_HSMRot_DestroyNotFound verifies that terraform destroy succeeds when the
// HSM setup record was already deleted out-of-band (the notFoundError guard in Delete()
// prevents an error).
func TestCipherTrust_HSMRot_DestroyNotFound(t *testing.T) {
	RequireCM(t)
	t.Skip("Skipped — requires a live HSM appliance connected to CipherTrust Manager")

	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient: required env vars not set")
	}

	var hsmRotID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: hsmRotConfig("lunapci", "test-partition", "test-password", true, 5),
				Check: func(s *terraform.State) error {
					hsmRotID = s.RootModule().Resources["ciphertrust_hsm_root_of_trust_setup.test"].Primary.ID
					return nil
				},
			},
			{
				PreConfig: func() {
					// Delete the resource out-of-band so that the destroy step hits the 404 guard.
					deletePayload := []byte(`{"reset":true,"delay":5}`)
					deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_HSM_Server, hsmRotID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", uuid.New().String(), deleteURL, deletePayload)
				},
				Destroy: true,
				Config:  hsmRotConfig("lunapci", "test-partition", "test-password", true, 5),
			},
		},
	})
}
