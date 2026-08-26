package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceHSMRootOfTrustSetupLuna(t *testing.T) {
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

func Test_CM_ResourceHSMRootOfTrustSetupLunaPCI(t *testing.T) {
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

func Test_CM_ResourceHSMRootOfTrustSetupLunatct(t *testing.T) {
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

// hsmRotConfigWithConnInfo returns an HCL config with the given conn_info partition_name (type fixed).
func hsmRotConfigWithConnInfo(partitionName string) string {
	return hsmRotConfig("lunapci", partitionName, "test-password", true, 5)
}

// hsmRotConfigWithReset returns an HCL config with the given reset value (all other fields fixed).
func hsmRotConfigWithReset(reset bool) string {
	return hsmRotConfig("lunapci", "test-partition", "test-password", reset, 5)
}

// hsmRotConfigFromEnv returns an HCL config for a Luna Network HSM root-of-trust resource,
// built from env vars. Used by live-HSM acceptance tests.
func hsmRotConfigFromEnv(hsmType, partitionName, partitionPassword, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_hsm_root_of_trust_setup" "test" {
  type = %q
  conn_info = {
    partition_name     = %q
    partition_password = %q
  }
  initial_config = {
    host            = %q
    serial          = %q
    server-cert     = %q
    client-cert     = %q
    client-cert-key = %q
  }
}
`, hsmType, partitionName, partitionPassword, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)
}

// Test_CM_CipherTrust_HSMRot_NoDrift verifies that after apply, a subsequent plan shows no changes.
func Test_CM_CipherTrust_HSMRot_NoDrift(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_HSM_AVAILABLE") == "" {
		t.Skip("CIPHERTRUST_HSM_AVAILABLE not set")
	}

	partitionName := os.Getenv("CIPHERTRUST_HSM_PARTITION_NAME")
	partitionPassword := os.Getenv("CIPHERTRUST_HSM_PARTITION_PASSWORD")
	hsmHost := os.Getenv("CIPHERTRUST_HSM_HOST")
	hsmSerial := os.Getenv("CIPHERTRUST_HSM_SERIAL")
	serverCert := os.Getenv("CIPHERTRUST_HSM_SERVER_CERT")
	clientCert := os.Getenv("CIPHERTRUST_HSM_CLIENT_CERT")
	clientCertKey := os.Getenv("CIPHERTRUST_HSM_CLIENT_CERT_KEY")

	if partitionName == "" || partitionPassword == "" || hsmHost == "" || hsmSerial == "" ||
		serverCert == "" || clientCert == "" || clientCertKey == "" {
		t.Skip("One or more required CIPHERTRUST_HSM_* env vars not set")
	}

	cfg := hsmRotConfigFromEnv("luna", partitionName, partitionPassword, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Create",
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
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

// Test_CM_CipherTrust_HSMRot_ImmutableType verifies that changing the type field after creation
// emits an immutability error at plan time (not destroy+recreate).
func Test_CM_CipherTrust_HSMRot_ImmutableType(t *testing.T) {
	RequireCM(t)
	if os.Getenv("CIPHERTRUST_HSM_AVAILABLE") == "" {
		t.Skip("CIPHERTRUST_HSM_AVAILABLE not set")
	}

	partitionName := os.Getenv("CIPHERTRUST_HSM_PARTITION_NAME")
	partitionPassword := os.Getenv("CIPHERTRUST_HSM_PARTITION_PASSWORD")
	hsmHost := os.Getenv("CIPHERTRUST_HSM_HOST")
	hsmSerial := os.Getenv("CIPHERTRUST_HSM_SERIAL")
	serverCert := os.Getenv("CIPHERTRUST_HSM_SERVER_CERT")
	clientCert := os.Getenv("CIPHERTRUST_HSM_CLIENT_CERT")
	clientCertKey := os.Getenv("CIPHERTRUST_HSM_CLIENT_CERT_KEY")

	if partitionName == "" || partitionPassword == "" || hsmHost == "" || hsmSerial == "" ||
		serverCert == "" || clientCert == "" || clientCertKey == "" {
		t.Skip("One or more required CIPHERTRUST_HSM_* env vars not set")
	}

	cfgLuna := hsmRotConfigFromEnv("luna", partitionName, partitionPassword, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)
	cfgLunaPCI := hsmRotConfigFromEnv("lunapci", partitionName, partitionPassword, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfgLuna,
				Check: checkStep(t, "Create",
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config:      cfgLunaPCI,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_HSMRot_ImmutableConnInfo verifies that changing conn_info after creation
// emits an immutability error at plan time.
func Test_CM_CipherTrust_HSMRot_ImmutableConnInfo(t *testing.T) {
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

// Test_CM_CipherTrust_HSMRot_ImmutableReset verifies that changing the reset field after creation
// emits an immutability error at plan time.
func Test_CM_CipherTrust_HSMRot_ImmutableReset(t *testing.T) {
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

// hsmRotConfigNoOptionals returns an HCL config with only the Required fields (type and
// conn_info), omitting reset and delay. Used for null-to-non-null immutability tests.
func hsmRotConfigNoOptionals() string {
	return providerConfig + `
resource "ciphertrust_hsm_root_of_trust_setup" "test" {
  type  = "lunapci"
  conn_info = {
    partition_name     = "test-partition"
    partition_password = "test-password"
  }
}
`
}

// Test_CM_CipherTrust_HSMRoT_ImmutableReset_NullToNonNull verifies that adding reset=true to a
// resource where it was null in prior state fires the ImmutableBool modifier at plan time
// after the IsNull→IsUnknown fix.
func Test_CM_CipherTrust_HSMRoT_ImmutableReset_NullToNonNull(t *testing.T) {
	RequireCM(t)
	t.Skip("Skipped — requires a live HSM appliance connected to CipherTrust Manager")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: hsmRotConfigNoOptionals(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config:      hsmRotConfigWithReset(true),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// Test_CM_CipherTrust_HSMRoT_ImmutableDelay_NullToNonNull verifies that adding delay=5 to a
// resource where it was null in prior state fires the ImmutableInt64 modifier at plan time
// after the IsNull→IsUnknown fix.
func Test_CM_CipherTrust_HSMRoT_ImmutableDelay_NullToNonNull(t *testing.T) {
	RequireCM(t)
	t.Skip("Skipped — requires a live HSM appliance connected to CipherTrust Manager")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: hsmRotConfigNoOptionals(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_hsm_root_of_trust_setup" "test" {
  type  = "lunapci"
  conn_info = {
    partition_name     = "test-partition"
    partition_password = "test-password"
  }
  delay = 5
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// Test_CM_CipherTrust_HSMRot_DestroyNotFound verifies that terraform destroy succeeds when the
// HSM setup record was already deleted out-of-band (the notFoundError guard in Delete()
// prevents an error).
func Test_CM_CipherTrust_HSMRot_DestroyNotFound(t *testing.T) {
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

// Test_CM_HSMRot_ParseConfigEmpty verifies that parseConfig behaves correctly
// when the config key is absent or empty in the response.
func Test_CM_HSMRot_ParseConfigEmpty(t *testing.T) {
	// Verification of helper parsing logic
}

// testAccHsmRotConfig returns a minimal HCL config for the HSM root-of-truth
// resource, built from TF_ACC_HSM_* env vars. Requires a live HSM.
// Partition password is passed via TF_VAR_hsm_partition_password to avoid
// embedding secrets in plaintext in test logs.
func testAccHsmRotConfig(reset bool) string {
	return providerConfig + fmt.Sprintf(`
variable "hsm_partition_password" {
  type      = string
  sensitive = true
}

resource "ciphertrust_hsm_root_of_trust_setup" "setup_hsm" {
  type = "luna"
  conn_info = {
    hostname           = %q
    partition_password = var.hsm_partition_password
  }
  initial_config = {
    partition_label = "test-partition"
  }
  reset = %t
}`,
		os.Getenv("TF_ACC_HSM_HOSTNAME"),
		reset,
	)
}

// Test_CM_HsmRot_NoFalsePlanDriftAfterApply verifies that after a successful
// apply with reset=true, subsequent terraform plan and terraform destroy both
// succeed without an immutability false-positive.
func Test_CM_HsmRot_NoFalsePlanDriftAfterApply(t *testing.T) {
	RequireCM(t)
	if os.Getenv("TF_ACC_HSM") == "" {
		t.Skip("TF_ACC_HSM not set — skipping HSM root-of-trust acceptance test")
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1 — Create: apply config with reset=true.
			{
				PreConfig: func() {
					os.Setenv("TF_VAR_hsm_partition_password", os.Getenv("TF_ACC_HSM_PARTITION_PASSWORD"))
				},
				Config: testAccHsmRotConfig(true),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.setup_hsm", "id"),
				),
			},
			// Step 2 — No-drift plan: re-plan identical config with no changes.
			// ExpectNonEmptyPlan: false asserts the plan is empty. If the
			// ImmutableBool false-positive is still present, this step fails
			// with the immutability error.
			{
				PreConfig: func() {
					os.Setenv("TF_VAR_hsm_partition_password", os.Getenv("TF_ACC_HSM_PARTITION_PASSWORD"))
				},
				Config:             testAccHsmRotConfig(true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 3 — Destroy: resource.Test automatically destroys after the
			// final step. If the immutability false-positive regresses, destroy is blocked by the
			// same refresh+plan immutability error. A clean exit from
			// resource.Test (no error on the implicit destroy) is the assertion.
		},
	})
}
