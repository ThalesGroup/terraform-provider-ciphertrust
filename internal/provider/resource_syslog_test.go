package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
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

// Test_CM_Syslog_ImmutableFields verifies that host and port are blocked at
// plan time when changed, while transport is freely mutable.
func Test_CM_Syslog_ImmutableFields(t *testing.T) {
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
				// Changing host must be rejected at plan time by ImmutableString modifier
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog2.example.com"
    transport = "udp"
    port      = 514
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			{
				// Restore original host, change port — must be rejected at plan time by ImmutableInt64 modifier
				Config: providerConfig + `
resource "ciphertrust_syslog" "test" {
    host      = "syslog1.example.com"
    transport = "udp"
    port      = 601
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			{
				// Restore original port, change transport — must produce a non-empty plan without error
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
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
