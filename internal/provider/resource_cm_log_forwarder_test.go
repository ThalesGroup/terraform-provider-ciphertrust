package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// requireESConnID skips the calling test when no elasticsearch log-forwarder
// connection ID is available in the environment.
func requireESConnID(t *testing.T) string {
	t.Helper()
	connID := os.Getenv("CIPHERTRUST_ES_LOG_FORWARDER_CONN_ID")
	if connID == "" {
		t.Skip("Skipping: CIPHERTRUST_ES_LOG_FORWARDER_CONN_ID is not set")
	}
	return connID
}

// requireLokiConnID skips the calling test when no loki log-forwarder
// connection ID is available in the environment.
func requireLokiConnID(t *testing.T) string {
	t.Helper()
	connID := os.Getenv("CIPHERTRUST_LOKI_LOG_FORWARDER_CONN_ID")
	if connID == "" {
		t.Skip("Skipping: CIPHERTRUST_LOKI_LOG_FORWARDER_CONN_ID is not set")
	}
	return connID
}

// TestAccCMLogForwarder_elasticsearchDrift verifies that Read() surfaces drift
// on all four elasticsearch_params.indices fields when they are mutated
// out-of-band via the CM API.
func TestAccCMLogForwarder_elasticsearchDrift(t *testing.T) {
	RequireCM(t)
	connID := requireESConnID(t)
	name := "tf-lf-es-drift-" + uuid.New().String()[:8]
	const res = "ciphertrust_log_forwarder.test"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "elasticsearch"
  elasticsearch_params {
    indices {
      activity_kmip        = "kmip-index"
      activity_nae         = "nae-index"
      client_audit_records = "client-index"
      server_audit_records = "server-index"
    }
  }
}
`, connID, name),
				Check: checkStep(t, "Step 1: apply elasticsearch log forwarder",
					resource.TestCheckResourceAttrSet(res, "id"),
					resource.TestCheckResourceAttr(res, "elasticsearch_params.indices.activity_kmip", "kmip-index"),
					resource.TestCheckResourceAttr(res, "elasticsearch_params.indices.activity_nae", "nae-index"),
					resource.TestCheckResourceAttr(res, "elasticsearch_params.indices.client_audit_records", "client-index"),
					resource.TestCheckResourceAttr(res, "elasticsearch_params.indices.server_audit_records", "server-index"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[res]
						if !ok {
							return fmt.Errorf("resource %s not found in state", res)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band mutation; RefreshState must detect drift on all four fields.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := map[string]interface{}{
						"elasticsearch_params": map[string]interface{}{
							"indices": map[string]interface{}{
								"activity_kmip":        "kmip-index-changed",
								"activity_nae":         "nae-index-changed",
								"client_audit_records": "client-index-changed",
								"server_audit_records": "server-index-changed",
							},
						},
					}
					payloadJSON, _ := json.Marshal(payload)
					_, _ = client.UpdateDataV2(context.Background(), uuid.NewString(), common.URL_CM_LOG_FORWARDS+"/"+capturedID, payloadJSON)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMLogForwarder_lokiDrift verifies that Read() surfaces drift on all
// four loki_params.labels fields when they are mutated out-of-band.
func TestAccCMLogForwarder_lokiDrift(t *testing.T) {
	RequireCM(t)
	connID := requireLokiConnID(t)
	name := "tf-lf-loki-drift-" + uuid.New().String()[:8]
	const res = "ciphertrust_log_forwarder.test"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "loki"
  loki_params {
    labels {
      activity_kmip        = "kmip-label"
      activity_nae         = "nae-label"
      client_audit_records = "client-label"
      server_audit_records = "server-label"
    }
  }
}
`, connID, name),
				Check: checkStep(t, "Step 1: apply loki log forwarder",
					resource.TestCheckResourceAttrSet(res, "id"),
					resource.TestCheckResourceAttr(res, "loki_params.labels.activity_kmip", "kmip-label"),
					resource.TestCheckResourceAttr(res, "loki_params.labels.activity_nae", "nae-label"),
					resource.TestCheckResourceAttr(res, "loki_params.labels.client_audit_records", "client-label"),
					resource.TestCheckResourceAttr(res, "loki_params.labels.server_audit_records", "server-label"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[res]
						if !ok {
							return fmt.Errorf("resource %s not found in state", res)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band mutation; RefreshState must detect drift on all four fields.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := map[string]interface{}{
						"loki_params": map[string]interface{}{
							"labels": map[string]interface{}{
								"activity_kmip":        "kmip-label-changed",
								"activity_nae":         "nae-label-changed",
								"client_audit_records": "client-label-changed",
								"server_audit_records": "server-label-changed",
							},
						},
					}
					payloadJSON, _ := json.Marshal(payload)
					_, _ = client.UpdateDataV2(context.Background(), uuid.NewString(), common.URL_CM_LOG_FORWARDS+"/"+capturedID, payloadJSON)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMLogForwarder_syslogDrift verifies that Read() surfaces drift on all
// four syslog_params boolean fields when they are flipped out-of-band.
func TestAccCMLogForwarder_syslogDrift(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	name := "tf-lf-syslog-drift-" + uuid.New().String()[:8]
	const res = "ciphertrust_log_forwarder.test"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
  syslog_params {
    forward_logs {
      activity_kmip        = true
      activity_nae         = true
      client_audit_records = true
      server_audit_records = true
    }
  }
}
`, connID, name),
				Check: checkStep(t, "Step 1: apply syslog log forwarder with inner params",
					resource.TestCheckResourceAttrSet(res, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[res]
						if !ok {
							return fmt.Errorf("resource %s not found in state", res)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Flip all four syslog inner boolean fields to false out-of-band.
				// Read() must surface drift via the syslog_params.syslog_params.* gjson path.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := map[string]interface{}{
						"syslog_params": map[string]interface{}{
							"syslog_params": map[string]interface{}{
								"activity_kmip":        false,
								"activity_nae":         false,
								"client_audit_records": false,
								"server_audit_records": false,
							},
						},
					}
					payloadJSON, _ := json.Marshal(payload)
					_, _ = client.UpdateDataV2(context.Background(), uuid.NewString(), common.URL_CM_LOG_FORWARDS+"/"+capturedID, payloadJSON)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMLogForwarder_updatedAtRefresh confirms that updated_at is hydrated
// by Read() on every refresh, with no plan drift on a subsequent plan.
func TestAccCMLogForwarder_updatedAtRefresh(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	name := "tf-lf-updat-" + uuid.New().String()[:8]
	const res = "ciphertrust_log_forwarder.test"

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "Step 1: apply and verify updated_at is set",
					resource.TestCheckResourceAttrSet(res, "id"),
					resource.TestCheckResourceAttrSet(res, "updated_at"),
				),
			},
			{
				// RefreshState re-reads from the API; updated_at should remain set
				// and the plan should be empty (no drift).
				RefreshState: true,
				Check: checkStep(t, "Step 2: refresh and verify updated_at persists",
					resource.TestCheckResourceAttrSet(res, "updated_at"),
				),
			},
		},
	})
}

// TestAccCMLogForwarder_destroyOOB confirms that Delete() exits cleanly (404
// guard) when the resource was already removed out-of-band.
func TestAccCMLogForwarder_destroyOOB(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	name := "tf-lf-oob-" + uuid.New().String()[:8]
	const res = "ciphertrust_log_forwarder.test"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, name),
				Check: checkStep(t, "Step 1: apply minimal log forwarder",
					resource.TestCheckResourceAttrSet(res, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[res]
						if !ok {
							return fmt.Errorf("resource %s not found in state", res)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the resource out-of-band, then refresh. Read() must call
				// RemoveResource on 404, and the subsequent implicit destroy by
				// the test framework must not fail.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_CM_LOG_FORWARDS+"/"+capturedID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCMLogForwarder_destroyLifecycle verifies that Delete() uses
// URL_CM_LOG_FORWARDS so the framework's implicit terraform destroy succeeds.
func TestAccCMLogForwarder_destroyLifecycle(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	name := "tf-lf-dstry-" + uuid.New().String()[:8]
	const res = "ciphertrust_log_forwarder.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, name),
				Check: checkStep(t, "Step 1: apply and verify no plan diff",
					resource.TestCheckResourceAttrSet(res, "id"),
				),
			},
		},
	})
}
