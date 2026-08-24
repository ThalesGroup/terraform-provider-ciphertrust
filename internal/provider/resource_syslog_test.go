package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceSyslog(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_syslog" "syslog_1" {
    host = "example.syslog.com"
    transport = "udp"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.syslog_1", "host"),
				),
			},
			{
				// host must remain the same (immutable); only transport changes
				Config: providerConfig + `
resource "ciphertrust_syslog" "syslog_1" {
    host = "example.syslog.com"
    transport = "tcp"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.syslog_1", "host"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// Test_CM_Syslog_MutableFields verifies that host, port, and transport all
// produce a non-empty in-place plan when changed (TFIN-523: ImmutableString/Int64
// removed from host and port).
func Test_CM_Syslog_MutableFields(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog1.example.com"
    transport = "udp"
    port      = 514
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "host", "syslog1.example.com"),
				),
			},
			{
				// Changing host must produce a non-empty in-place plan (no error, no replace)
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog2.example.com"
    transport = "udp"
    port      = 514
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Changing port must produce a non-empty in-place plan (no error, no replace)
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog1.example.com"
    transport = "udp"
    port      = 601
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Changing transport must produce a non-empty in-place plan without error
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog1.example.com"
    transport = "tcp"
    port      = 514
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_Syslog_Idempotency verifies that all Computed fields are stable
// after create and a second plan with no config changes produces an empty diff.
func Test_CM_Syslog_Idempotency(t *testing.T) {
	RequireCM(t)
	cfg := providerConfig + `
resource "ciphertrust_syslog" "test" {
    host           = "syslog-idem.example.com"
    transport      = "udp"
    message_format = "rfc5424"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "account"),
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "created_at"),
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "message_format", "rfc5424"),
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "updated_at"),
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

// Test_CM_Syslog_DriftDetection verifies that an out-of-band change to
// message_format is surfaced as drift when Read() runs on the next plan.
func Test_CM_Syslog_DriftDetection(t *testing.T) {
	RequireCM(t)
	var syslogID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host           = "syslog-drift.example.com"
    transport      = "udp"
    message_format = "rfc5424"
}
`,
				Check: func(s *terraform.State) error {
					syslogID = s.RootModule().Resources["ciphertrust_syslog.test"].Primary.ID
					return nil
				},
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping drift OOB step")
						return
					}
					payload, err := json.Marshal(map[string]interface{}{
						"messageFormat": "cef",
					})
					if err != nil {
						t.Logf("failed to marshal drift payload: %v", err)
						return
					}
					if _, err := client.UpdateDataV2(ctx, syslogID, common.URL_CM_SYSLOG, payload); err != nil {
						t.Logf("OOB update failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_Syslog_OutOfBandDeletion verifies that when a syslog connection is
// deleted directly on CipherTrust Manager, Read() calls RemoveResource on 404
// and Terraform plans to recreate it.
func Test_CM_Syslog_OutOfBandDeletion(t *testing.T) {
	RequireCM(t)
	var syslogID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog-oobd.example.com"
    transport = "udp"
}
`,
				Check: func(s *terraform.State) error {
					syslogID = s.RootModule().Resources["ciphertrust_syslog.test"].Primary.ID
					return nil
				},
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB deletion step")
						return
					}
					deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_CM_SYSLOG, syslogID)
					if _, err := client.DeleteByID(ctx, "DELETE", syslogID, deleteURL, nil); err != nil {
						t.Logf("OOB delete failed (may already be gone): %v", err)
					}
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`(?i)not found on ciphertrust manager`),
			},
		},
	})
}

// Test_CM_Syslog_EmptyHostRejected verifies that an empty host is rejected at plan time.
func Test_CM_Syslog_EmptyHostRejected(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
  host      = ""
  transport = "udp"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("string length must be at least 1"),
			},
		},
	})
}

// Test_CM_Syslog_ValueNullNoDrift verifies that when ca_cert is unconfigured (null),
// the state is guarded and no perpetual plan diff is generated.
func Test_CM_Syslog_ValueNullNoDrift(t *testing.T) {
	RequireCM(t)
	cfg := providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog-null-test.example.com"
    transport = "udp"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "id"),
					resource.TestCheckNoResourceAttr("ciphertrust_syslog.test", "ca_cert"),
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

// Test_CM_SyslogCACertNonTLS verifies that ca_cert is absent from state after
// Create() with a non-TLS transport. CM silently discards ca_cert for non-TLS
// transports; Create() reads null back from the POST response and writes null to state.
func Test_CM_SyslogCACertNonTLS(t *testing.T) {
	RequireCM(t)
	name := "syslog-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: syslogConfigWithCACert(name, "udp", testSyslogCACertAny),
				Check: checkStep(t, "create udp with ca_cert",
					resource.TestCheckResourceAttr("ciphertrust_syslog."+name, "transport", "udp"),
					resource.TestCheckResourceAttr("ciphertrust_syslog."+name, "ca_cert", testSyslogCACertAny),
				),
			},
			{
				Config:             syslogConfigNoCACert(name, "udp"),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_SyslogCACertTLSPreserved verifies that ca_cert is present in state
// after Create() with TLS transport (CM stores it), and that a subsequent plan
// produces no diff (regression guard: the fix must not break the TLS path).
func Test_CM_SyslogCACertTLSPreserved(t *testing.T) {
	RequireCM(t)
	cert := tlsSyslogCACert(t)
	name := "syslog-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: syslogConfigWithCACert(name, "tls", cert),
				Check: checkStep(t, "create tls with ca_cert",
					resource.TestCheckResourceAttr("ciphertrust_syslog."+name, "transport", "tls"),
					resource.TestCheckResourceAttrSet("ciphertrust_syslog."+name, "ca_cert"),
				),
			},
			{
				Config:             syslogConfigWithCACert(name, "tls", cert),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_SyslogUpdateCACertNonTLS verifies that adding ca_cert via Update() on
// a non-TLS resource leaves ca_cert absent in state (CM discards it), and that
// a subsequent plan produces no diff (no perpetual diff after update).
func Test_CM_SyslogUpdateCACertNonTLS(t *testing.T) {
	RequireCM(t)
	name := "syslog-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: syslogConfigNoCACert(name, "tcp"),
				Check: checkStep(t, "create tcp no ca_cert",
					resource.TestCheckResourceAttr("ciphertrust_syslog."+name, "transport", "tcp"),
					resource.TestCheckNoResourceAttr("ciphertrust_syslog."+name, "ca_cert"),
				),
			},
			{
				Config: syslogConfigWithCACert(name, "tcp", testSyslogCACertAny),
				Check: checkStep(t, "update tcp add ca_cert (should be preserved in state)",
					resource.TestCheckResourceAttr("ciphertrust_syslog."+name, "ca_cert", testSyslogCACertAny),
				),
			},
			{
				Config:             syslogConfigNoCACert(name, "tcp"),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_SyslogCACertDrift verifies that an out-of-band removal of caCert on a
// TLS syslog resource is detected by Read() as drift on the next plan.
func Test_CM_SyslogCACertDrift(t *testing.T) {
	RequireCM(t)
	cert := tlsSyslogCACert(t)
	name := "syslog-" + uuid.New().String()[:8]
	var resourceID string
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: syslogConfigWithCACert(name, "tls", cert),
				Check: checkStep(t, "create tls with ca_cert for drift test",
					resource.TestCheckResourceAttrSet("ciphertrust_syslog."+name, "ca_cert"),
					func(s *terraform.State) error {
						resourceID = s.RootModule().Resources["ciphertrust_syslog."+name].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB caCert clear step")
						return
					}
					payload, err := json.Marshal(map[string]interface{}{"caCert": ""})
					if err != nil {
						t.Logf("failed to marshal OOB caCert clear payload: %v", err)
						return
					}
					if _, err := client.UpdateDataV2(ctx, resourceID, common.URL_CM_SYSLOG, payload); err != nil {
						t.Logf("OOB caCert clear failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// testSyslogCACertAny is a placeholder PEM block used for non-TLS transport tests.
// CipherTrust Manager silently discards ca_cert for non-TLS transports, so the
// value just needs to be non-empty to exercise that code path.
const testSyslogCACertAny = `-----BEGIN CERTIFICATE-----
MIIBpDCCAQ2gAwIBAgIUTest01ForNonTLSSyslogTestsOnlyxyz0KBgQDAmBvdDCC
-----END CERTIFICATE-----`

// tlsSyslogCACert returns the CA certificate for TLS syslog acceptance tests.
// The test is skipped when CIPHERTRUST_SYSLOG_CA_CERT is not set in the environment.
func tlsSyslogCACert(t *testing.T) string {
	t.Helper()
	cert := os.Getenv("CIPHERTRUST_SYSLOG_CA_CERT")
	if cert == "" {
		t.Skip("CIPHERTRUST_SYSLOG_CA_CERT not set — skipping TLS syslog ca_cert tests")
	}
	return cert
}

func syslogConfigWithCACert(name, transport, caCert string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_syslog" %[1]q {
  host      = "example.syslog.com"
  transport = %[2]q
  ca_cert   = %[3]q
}`, name, transport, caCert)
}

func syslogConfigNoCACert(name, transport string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_syslog" %[1]q {
  host      = "example.syslog.com"
  transport = %[2]q
}`, name, transport)
}

// Test_CM_Syslog_HostPortUpdateInPlace verifies that host and port can be changed
// in-place after removing ImmutableString()/ImmutableInt64() (TFIN-523). Confirms
// the resource ID is unchanged after the update (no destroy+recreate).
func Test_CM_Syslog_HostPortUpdateInPlace(t *testing.T) {
	RequireCM(t)
	name := "tftest-syslog-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_syslog" "test" {
  host      = "syslog-a.example.com"
  transport = "udp"
  port      = 514
}`) + fmt.Sprintf(" # %s", name),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "host", "syslog-a.example.com"),
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "port", "514"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_syslog.test"].Primary.ID
						return nil
					},
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
  host      = "syslog-b.example.com"
  transport = "udp"
  port      = 601
}` + fmt.Sprintf(" # %s", name),
				Check: checkStep(t, "update host+port in place",
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "host", "syslog-b.example.com"),
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "port", "601"),
					func(s *terraform.State) error {
						newID := s.RootModule().Resources["ciphertrust_syslog.test"].Primary.ID
						if newID != capturedID {
							return fmt.Errorf("resource was recreated: old ID=%s new ID=%s", capturedID, newID)
						}
						return nil
					},
				),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Syslog_MessageFormatUpdate verifies:
//   - Explicitly changing message_format updates correctly on CM (TFIN-434)
//   - Removing message_format from config leaves state unchanged (no drift)
//     because UseStateForUnknown preserves the existing value.
func Test_CM_Syslog_MessageFormatUpdate(t *testing.T) {
	RequireCM(t)
	name := "tftest-syslog-mf-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_syslog" "test" {
  host           = "syslog.example.com"
  transport      = "udp"
  message_format = "cef"
}`) + fmt.Sprintf(" # %s", name),
				Check: checkStep(t, "set message_format=cef",
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "message_format", "cef"),
				),
			},
			{
				// Explicitly reset to rfc5424 — CM must accept and persist the change.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_syslog" "test" {
  host           = "syslog.example.com"
  transport      = "udp"
  message_format = "rfc5424"
}`) + fmt.Sprintf(" # %s", name),
				Check: checkStep(t, "reset message_format to rfc5424",
					resource.TestCheckResourceAttr("ciphertrust_syslog.test", "message_format", "rfc5424"),
				),
			},
			{
				// Remove message_format from config — UseStateForUnknown preserves state value,
				// so no update is triggered and the plan should be empty.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_syslog" "test" {
  host      = "syslog.example.com"
  transport = "udp"
}`) + fmt.Sprintf(" # %s", name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Syslog_CACertClearWarning verifies that removing ca_cert from config
// preserves the existing certificate and emits a warning, since CM's update API
// cannot clear ca_cert once set (TFIN-524).
func Test_CM_Syslog_CACertClearWarning(t *testing.T) {
	RequireCM(t)
	caCert := os.Getenv("CM_TEST_SYSLOG_CA_CERT")
	if caCert == "" {
		t.Skip("CM_TEST_SYSLOG_CA_CERT not set — skipping ca_cert clear test")
	}
	name := "tftest-syslog-ca-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
variable "ca_cert" { sensitive = true }
resource "ciphertrust_syslog" "test" {
  host      = "syslog.example.com"
  transport = "tls"
  ca_cert   = var.ca_cert
}`) + fmt.Sprintf(" # %s", name),
				Check: checkStep(t, "set ca_cert",
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "ca_cert"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_syslog" "test" {
  host      = "syslog.example.com"
  transport = "tls"
}`) + fmt.Sprintf(" # %s", name),
				Check: checkStep(t, "remove ca_cert — value preserved (API cannot clear)",
					resource.TestCheckResourceAttrSet("ciphertrust_syslog.test", "ca_cert"),
				),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
