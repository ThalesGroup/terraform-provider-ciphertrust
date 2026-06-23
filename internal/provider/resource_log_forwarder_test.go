package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
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

// TestCMLogForwarderCRUD creates a syslog log forwarder, verifies it, then
// updates a mutable field (name) and verifies the update.
func TestCMLogForwarderCRUD(t *testing.T) {
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

// TestCMLogForwarderTypeImmutable verifies that attempting to change the
// 'type' field after creation produces a clear, actionable plan-time error
// rather than silent state drift.
func TestCMLogForwarderTypeImmutable(t *testing.T) {
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
