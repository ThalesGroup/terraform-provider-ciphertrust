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

// hsmRotConfigSecure returns an HCL config that reads partition_password from a Terraform
// variable (var.hsm_partition_password) rather than interpolating it directly into the
// config string. Callers must set TF_VAR_hsm_partition_password before the test step runs.
// This prevents the partition password from appearing in plaintext in test framework logs.
func hsmRotConfigSecure(hsmType, partitionName, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey string) string {
	return providerConfig + fmt.Sprintf(`
variable "hsm_partition_password" {
  type      = string
  sensitive = true
}

resource "ciphertrust_hsm_root_of_trust_setup" "test" {
  type = %q
  conn_info = {
    partition_name     = %q
    partition_password = var.hsm_partition_password
  }
  initial_config = {
    host            = %q
    serial          = %q
    server-cert     = %q
    client-cert     = %q
    client-cert-key = %q
  }
}
`, hsmType, partitionName, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)
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

// Test_CM_HSMRootOfTrustSetup_NoDriftAfterApply verifies that after a successful apply,
// a subsequent plan-only step with the same config reports no changes. This exercises
// the Fix 2 else-null removal for the reset field in Read().
func Test_CM_HSMRootOfTrustSetup_NoDriftAfterApply(t *testing.T) {
	RequireCM(t)
	if os.Getenv("TF_ACC_HSM") != "1" {
		t.Skip("requires Luna HSM hardware — set TF_ACC_HSM=1 to run")
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

	// Pass partition_password via TF_VAR to prevent it from appearing in test framework logs.
	t.Setenv("TF_VAR_hsm_partition_password", partitionPassword)
	cfg := hsmRotConfigSecure("luna", partitionName, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// Test_CM_HSMRootOfTrustSetup_ImmutableMapRejected verifies that a genuine change to
// conn_info still fires an immutability error after Fix 1, confirming ImmutableMap
// enforcement is not disabled by the null/unknown PlanValue guard.
func Test_CM_HSMRootOfTrustSetup_ImmutableMapRejected(t *testing.T) {
	RequireCM(t)
	if os.Getenv("TF_ACC_HSM") != "1" {
		t.Skip("requires Luna HSM hardware — set TF_ACC_HSM=1 to run")
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

	// Pass partition_password via TF_VAR to prevent it from appearing in test framework logs.
	t.Setenv("TF_VAR_hsm_partition_password", partitionPassword)
	cfgOriginal := hsmRotConfigSecure("luna", partitionName, hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)
	cfgChangedConnInfo := hsmRotConfigSecure("luna", partitionName+"-changed", hsmHost, hsmSerial, serverCert, clientCert, clientCertKey)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfgOriginal,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_hsm_root_of_trust_setup.test", "id"),
				),
			},
			{
				Config:      cfgChangedConnInfo,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)cannot be changed after creation`),
			},
		},
	})
}

// Test_CM_HSMRootOfTrustSetup_DriftDetected_Reset verifies that Read() correctly hydrates
// a changed reset value from CM when it differs from what is tracked in state, producing a
// non-empty plan (drift detection). Gates on TF_ACC_HSM=1 since it requires live HSM hardware.
// If CM does not expose reset as a mutable PATCH field, this test is skipped with a note.
func Test_CM_HSMRootOfTrustSetup_DriftDetected_Reset(t *testing.T) {
	RequireCM(t)
	if os.Getenv("TF_ACC_HSM") != "1" {
		t.Skip("requires Luna HSM hardware — set TF_ACC_HSM=1 to run")
	}
	t.Skip("CM API does not permit out-of-band mutation of reset — drift scenario not exercisable without live HSM PATCH support")
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
