package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const logForwarderResource = "ciphertrust_log_forwarder.test_lf"

// requireLogForwarderConnID skips the calling test when the environment variable
// that holds a pre-existing log-forwarder connection ID is not set.
// The log_forwarder resource requires an existing connection (elasticsearch,
// loki, or syslog) and we cannot create one in-band without additional
// credentials, so tests accept the ID from the environment instead.
func requireLogForwarderConnID(t *testing.T) string {
	t.Helper()
	connID := os.Getenv("CIPHERTRUST_LOG_FORWARDER_CONNECTION_ID")
	if connID == "" {
		t.Skip("Skipping log_forwarder test: CIPHERTRUST_LOG_FORWARDER_CONNECTION_ID is not set")
	}
	return connID
}

// Test_CM_CMLogForwarderCRUD creates a syslog log forwarder, verifies it, then
// updates a mutable field (name) and verifies the update.
func Test_CM_CMLogForwarderCRUD(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	rNameUpdated := rName + "-upd"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(logForwarderResource, "id"),
					resource.TestCheckResourceAttr(logForwarderResource, "name", rName),
					resource.TestCheckResourceAttr(logForwarderResource, "type", "syslog"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rNameUpdated),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(logForwarderResource, "name", rNameUpdated),
				),
			},
		},
	})
}

// Test_CM_CMLogForwarderTypeImmutable verifies that attempting to change the
// 'type' field after creation produces a clear, actionable plan-time error
// rather than silent state drift.
func Test_CM_CMLogForwarderTypeImmutable(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rName),
				Check: resource.TestCheckResourceAttrSet(logForwarderResource, "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "elasticsearch"
}
`, connID, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// Test_CM_AccCMLogForwarder_TypeImmutable verifies that attempting to change the
// 'type' field after creation produces a clear immutable-field plan-time error.
func Test_CM_AccCMLogForwarder_TypeImmutable(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-imm-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rName),
				Check: resource.TestCheckResourceAttrSet(logForwarderResource, "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "loki"
}
`, connID, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// requireLogForwarderESConnID skips the calling test when the environment variable
// that holds a pre-existing elasticsearch log-forwarder connection ID is not set.
func requireLogForwarderESConnID(t *testing.T) string {
	t.Helper()
	connID := os.Getenv("CIPHERTRUST_LOG_FORWARDER_ES_CONNECTION_ID")
	if connID == "" {
		t.Skip("Skipping log_forwarder elasticsearch test: CIPHERTRUST_LOG_FORWARDER_ES_CONNECTION_ID is not set")
	}
	return connID
}

// requireLogForwarderLokiConnID skips the calling test when the environment variable
// that holds a pre-existing loki log-forwarder connection ID is not set.
func requireLogForwarderLokiConnID(t *testing.T) string {
	t.Helper()
	connID := os.Getenv("CIPHERTRUST_LOG_FORWARDER_LOKI_CONNECTION_ID")
	if connID == "" {
		t.Skip("Skipping log_forwarder loki test: CIPHERTRUST_LOG_FORWARDER_LOKI_CONNECTION_ID is not set")
	}
	return connID
}

// Test_CM_AccCMLogForwarder_elasticsearchDrift verifies that Read() surfaces an
// out-of-band elasticsearch_params change as drift.
func Test_CM_AccCMLogForwarder_elasticsearchDrift(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderESConnID(t)
	rName := "tf-lf-es-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "elasticsearch"
  elasticsearch_params {
    indices {
      activity_kmip = "kmip-index"
    }
  }
}
`, connID, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "es-drift: create",
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "elasticsearch_params.0.indices.0.activity_kmip", "kmip-index"),
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := []byte(`{"elasticsearch_params":{"indices":{"activity_kmip":"kmip-index-modified"}}}`)
					_, _ = client.UpdateDataV2(
						context.Background(),
						uuid.New().String(),
						common.URL_CM_LOG_FORWARDS+"/"+capturedID,
						payload,
					)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMLogForwarder_lokiDrift verifies that Read() surfaces an out-of-band
// loki_params change as drift.
func Test_CM_AccCMLogForwarder_lokiDrift(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderLokiConnID(t)
	rName := "tf-lf-loki-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "loki"
  loki_params {
    labels {
      activity_kmip = "kmip-label"
    }
  }
}
`, connID, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "loki-drift: create",
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "loki_params.0.labels.0.activity_kmip", "kmip-label"),
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := []byte(`{"loki_params":{"labels":{"activity_kmip":"kmip-label-modified"}}}`)
					_, _ = client.UpdateDataV2(
						context.Background(),
						uuid.New().String(),
						common.URL_CM_LOG_FORWARDS+"/"+capturedID,
						payload,
					)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMLogForwarder_syslogDrift verifies that Read() surfaces an out-of-band
// syslog_params change as drift and that updated_at is populated.
func Test_CM_AccCMLogForwarder_syslogDrift(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-sys-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
  syslog_params {
    forward_logs {
      activity_kmip = true
    }
  }
}
`, connID, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "syslog-drift: create",
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "syslog_params.0.forward_logs.0.activity_kmip", "true"),
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "updated_at"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := []byte(`{"syslog_params":{"syslog_params":{"activity_kmip":false}}}`)
					_, _ = client.UpdateDataV2(
						context.Background(),
						uuid.New().String(),
						common.URL_CM_LOG_FORWARDS+"/"+capturedID,
						payload,
					)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMLogForwarder_destroy verifies that:
//   - An out-of-band delete leaves the resource in Terraform state (404 → warning, no RemoveResource).
//   - terraform destroy uses the correct URL_CM_LOG_FORWARDS endpoint.
func Test_CM_AccCMLogForwarder_destroy(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-del-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		CheckDestroy: func(s *terraform.State) error {
			client, ok := createCMClient()
			if !ok {
				return nil
			}
			for _, rs := range s.RootModule().Resources {
				if rs.Type != "ciphertrust_log_forwarder" {
					continue
				}
				_, err := client.ReadDataByParam(
					context.Background(),
					uuid.New().String(),
					rs.Primary.ID,
					common.URL_CM_LOG_FORWARDS,
				)
				if err == nil {
					return fmt.Errorf("log forwarder %s still exists after destroy", rs.Primary.ID)
				}
				if !strings.Contains(err.Error(), "status: 404") {
					return fmt.Errorf("unexpected error checking forwarder %s: %v", rs.Primary.ID, err)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "destroy: create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Delete out-of-band; with corrected 404 behaviour Read() leaves the
				// resource in state so Terraform plans recreation on the next apply.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_CM_LOG_FORWARDS, capturedID)
					_, err := client.DeleteByID(context.Background(), "DELETE", capturedID, url, nil)
					if err != nil && !strings.Contains(err.Error(), "status: 404") {
						t.Logf("out-of-band delete warning: %v", err)
					}
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`(?i)not found on ciphertrust manager`),
			},
		},
	})
}

// Test_CM_LogForwarder_BasicCreateUpdate verifies that a ciphertrust_log_forwarder resource
// can be created, that id is populated after apply, and that updating the name field
// (a mutable attribute) takes effect on the next apply.
// Required env var: CIPHERTRUST_LOG_FORWARDER_CONNECTION_ID.
func Test_CM_LogForwarder_BasicCreateUpdate(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-basic-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	rNameUpdated := rName + "-upd"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccLogForwarderBasicConfig(connID, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.basic", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.basic", "name", rName),
				),
			},
			{
				Config: testAccLogForwarderBasicConfig(connID, rNameUpdated),
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.basic", "name", rNameUpdated),
				),
			},
		},
	})
}

// Test_CM_LogForwarder_Drift verifies that Read() surfaces an out-of-band name change
// as drift when RefreshState is used (ExpectNonEmptyPlan: true).
func Test_CM_LogForwarder_Drift(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "name", rName),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := []byte(`{"name":"drifted-name"}`)
					_, _ = client.UpdateDataV2(
						context.Background(),
						capturedID,
						common.URL_CM_LOG_FORWARDS,
						payload,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_LogForwarder_OOBDeletion verifies that Read() calls RemoveResource on 404
// and Terraform plans recreation when the resource is deleted out-of-band.
func Test_CM_LogForwarder_OOBDeletion(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-oobdel-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "oob-deletion: create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						capturedID,
						common.URL_CM_LOG_FORWARDS+"/"+capturedID,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func testAccLogForwarderBasicConfig(connID, name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "basic" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, name)
}

// Test_CM_LogForwarder_LokiCreateUpdate verifies that a loki-type log forwarder can be
// created and updated without CM rejecting the request body (the omitempty fix).
func Test_CM_LogForwarder_LokiCreateUpdate(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderLokiConnID(t)
	name := "loki-" + uuid.New().String()[:8]

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
      activity_kmip = "job=kmip"
    }
  }
}
`, connID, name),
				Check: checkStep(t, "loki create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "type", "loki"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "name", name),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "loki"
  loki_params {
    labels {
      activity_kmip = "job=kmip-updated"
    }
  }
}
`, connID, name),
				Check: checkStep(t, "loki update",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
				),
			},
		},
	})
}

// Test_CM_LogForwarder_ESCreate verifies that an elasticsearch-type log forwarder can be
// created without CM rejecting the request body (the omitempty fix).
// Requires CIPHERTRUST_LOG_FORWARDER_ES_CONNECTION_ID to be set.
func Test_CM_LogForwarder_ESCreate(t *testing.T) {
	RequireCM(t)
	esConnID := requireLogForwarderESConnID(t)
	name := "es-" + uuid.New().String()[:8]

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
      activity_kmip = "kmip-index"
    }
  }
}
`, esConnID, name),
				Check: checkStep(t, "es create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "type", "elasticsearch"),
				),
			},
		},
	})
}

// Test_CM_LogForwarder_SyslogCreate verifies that a syslog-type log forwarder can be
// created without CM rejecting the request body (the omitempty fix).
// Requires CIPHERTRUST_LOG_FORWARDER_CONNECTION_ID to be set.
func Test_CM_LogForwarder_SyslogCreate(t *testing.T) {
	RequireCM(t)
	syslogConnID := requireLogForwarderConnID(t)
	name := "syslog-" + uuid.New().String()[:8]

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
      activity_kmip = true
    }
  }
}
`, syslogConnID, name),
				Check: checkStep(t, "syslog create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "type", "syslog"),
				),
			},
		},
	})
}

// Test_CM_LogForwarder_ConnectionIDUpdateInPlace verifies that changing connection_id
// produces a non-empty in-place plan without an immutability error (TFIN-529:
// ImmutableString() removed from connection_id — CM accepts in-place changes).
func Test_CM_LogForwarder_ConnectionIDUpdateInPlace(t *testing.T) {
	RequireCM(t)
	connID1 := requireLogForwarderConnID(t)
	connID2 := "00000000-0000-0000-0000-000000000001"
	rName := "tf-lf-connupd-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID1, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test_lf", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test_lf", "connection_id", connID1),
				),
			},
			{
				// Changing connection_id must produce an in-place plan (no replace, no error).
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test_lf" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID2, rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_LogForwarder_UpdateInPlace verifies that Update() reaches CM with the correct
// URL and that no destroy+recreate happens on a name change (TFIN-528 regression).
func Test_CM_LogForwarder_UpdateInPlace(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-updinplace-" + uuid.New().String()[:8]
	rNameUpdated := rName + "-v2"
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
`, connID, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "name", rName),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						return nil
					},
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
}
`, connID, rNameUpdated),
				Check: checkStep(t, "update name in place",
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "name", rNameUpdated),
					func(s *terraform.State) error {
						newID := s.RootModule().Resources["ciphertrust_log_forwarder.test"].Primary.ID
						if newID != capturedID {
							return fmt.Errorf("resource was recreated: old ID=%s new ID=%s", capturedID, newID)
						}
						return nil
					},
				),
			},
		},
	})
}

// Test_CM_LogForwarder_SyslogCreateUpdate verifies that type=syslog can be created
// and updated without 400 errors (TFIN-530: fixed forward_logs JSON tag).
func Test_CM_LogForwarder_SyslogCreateUpdate(t *testing.T) {
	RequireCM(t)
	connID := requireLogForwarderConnID(t)
	rName := "tf-lf-syslogupd-" + uuid.New().String()[:8]

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
      activity_kmip = true
    }
  }
}
`, connID, rName),
				Check: checkStep(t, "syslog create",
					resource.TestCheckResourceAttrSet("ciphertrust_log_forwarder.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "type", "syslog"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_log_forwarder" "test" {
  connection_id = %q
  name          = %q
  type          = "syslog"
  syslog_params {
    forward_logs {
      activity_kmip        = true
      server_audit_records = true
    }
  }
}
`, connID, rName),
				Check: checkStep(t, "syslog update forward_logs",
					resource.TestCheckResourceAttr("ciphertrust_log_forwarder.test", "type", "syslog"),
				),
			},
		},
	})
}
