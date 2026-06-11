package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const syslogResource = "ciphertrust_syslog.test"

func syslogConfig(host, transport, messageFormat string, port int64) string {
	cfg := fmt.Sprintf(`
resource "ciphertrust_syslog" "test" {
  host      = %q
  transport = %q
`, host, transport)
	if messageFormat != "" {
		cfg += fmt.Sprintf("  message_format = %q\n", messageFormat)
	}
	if port != 0 {
		cfg += fmt.Sprintf("  port = %d\n", port)
	}
	cfg += "}\n"
	return providerConfig + cfg
}

func TestAccCMSyslog_NullGuardDrift(t *testing.T) {
	var capturedID string
	host := "192.0.2.1"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create without optional fields. The CM API sets server-side defaults
			// (message_format="rfc5424", port=514). With Optional+Computed schema these
			// defaults are captured in state -- verify they are present.
			{
				Config: syslogConfig(host, "udp", "", 0),
				Check: checkStep(t, "create without optional fields",
					resource.TestCheckResourceAttrSet(syslogResource, "id"),
					resource.TestCheckResourceAttr(syslogResource, "host", host),
					resource.TestCheckResourceAttr(syslogResource, "transport", "udp"),
					resource.TestCheckResourceAttr(syslogResource, "message_format", "rfc5424"),
					resource.TestCheckResourceAttr(syslogResource, "port", "514"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[syslogResource]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: OOB mutation -- change message_format to "cef" via the CM API.
			// The config explicitly specifies "rfc5424", so after Read() returns "cef"
			// the plan diff (config "rfc5424" vs refreshed state "cef") is non-empty,
			// confirming that Read() unconditionally surfaces OOB changes.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateDataV2(
						context.Background(),
						capturedID,
						common.URL_CM_SYSLOG,
						[]byte(`{"messageFormat":"cef"}`),
					)
				},
				Config:             syslogConfig(host, "udp", "rfc5424", 514),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Step 3: Apply config with an explicit message_format that differs from the
			// OOB "cef" value left on the server by Step 2.
			{
				Config: syslogConfig(host, "udp", "plain_message", 514),
				Check: checkStep(t, "apply with explicit optional fields",
					resource.TestCheckResourceAttr(syslogResource, "message_format", "plain_message"),
					resource.TestCheckResourceAttr(syslogResource, "port", "514"),
				),
			},
			// Step 4: No-drift check -- same config, plan must be empty.
			{
				Config:             syslogConfig(host, "udp", "plain_message", 514),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMSyslog_BasicNoDrift(t *testing.T) {
	host := "192.0.2." + uuid.New().String()[:2]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: syslogConfig(host, "tcp", "rfc5424", 601),
				Check: checkStep(t, "create with optional fields",
					resource.TestCheckResourceAttrSet(syslogResource, "id"),
					resource.TestCheckResourceAttr(syslogResource, "host", host),
					resource.TestCheckResourceAttr(syslogResource, "transport", "tcp"),
					resource.TestCheckResourceAttr(syslogResource, "message_format", "rfc5424"),
					resource.TestCheckResourceAttr(syslogResource, "port", "601"),
				),
			},
			{
				Config:             syslogConfig(host, "tcp", "rfc5424", 601),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
