package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceCMNTP(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { ntpSweep("time1.google.com") },
				Config: providerConfig + `
resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time1.google.com"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.ntp_server_1", "host", "time1.google.com"),
				),
			},
			{
				// host is now immutable — changing it must produce an error at plan time.
				Config: providerConfig + `
resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time2.google.com"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// ntpSweep deletes an NTP host from CipherTrust Manager, ignoring all errors.
// Used as a pre-test sweep to ensure no stale entries block Create().
func ntpSweep(host string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	_, _ = client.DeleteByID(
		context.Background(),
		"DELETE",
		host,
		fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_NTP, host),
		nil,
	)
}

// Test_CM_AccCMNTP_NoDrift verifies no spurious drift is produced when no out-of-band changes occur.
func Test_CM_AccCMNTP_NoDrift(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { ntpSweep("time4.google.com") },
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host = "time4.google.com"
}
`,
				Check: checkStep(t, "no drift: create",
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", "time4.google.com"),
				),
			},
			{
				// No out-of-band change; Read() must produce no diff.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMNTP_Delete404Guard verifies that Delete() succeeds when the resource was already deleted out-of-band.
func Test_CM_AccCMNTP_Delete404Guard(t *testing.T) {
	RequireCM(t)
	var hostVal string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { ntpSweep("time3.google.com") },
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host = "time3.google.com"
}
`,
				Check: checkStep(t, "delete 404 guard: create",
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", "time3.google.com"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_ntp.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						hostVal = rs.Primary.Attributes["host"]
						return nil
					},
				),
			},
			{
				// Delete the NTP server out-of-band, then destroy via Terraform; must not error.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client")
					}
					_, _ = client.DeleteByID(
						context.Background(),
						"DELETE",
						hostVal,
						fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_NTP, hostVal),
						nil,
					)
				},
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host = "time3.google.com"
}
`,
			Destroy: true,
			},
		},
	})
}

// Test_CM_AccCipherTrust_NTP_ImmutableFields verifies that changing any immutable field on
// ciphertrust_ntp produces a plan-time error from the ImmutableString modifier.
func Test_CM_AccCipherTrust_NTP_ImmutableFields(t *testing.T) {
	RequireCM(t)

	initialConfig := providerConfig + `
resource "ciphertrust_ntp" "test" {
  host     = "time5.google.com"
  key      = "testkey123"
  key_type = "SHA-256"
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { ntpSweep("time5.google.com") },
				Config:    initialConfig,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_ntp.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", "time5.google.com"),
				),
			},
			// Changing host must produce an immutable error at plan time.
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host     = "time.google.com"
  key      = "testkey123"
  key_type = "SHA-256"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			// Changing key must produce an immutable error at plan time.
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host     = "time5.google.com"
  key      = "differentkey456"
  key_type = "SHA-256"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			// Changing key_type must produce an immutable error at plan time.
			{
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host     = "time5.google.com"
  key      = "testkey123"
  key_type = "MD5"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMNTP_DriftDetection verifies that an out-of-band deletion is detected as drift.
// NOTE: This test performs an out-of-band deletion that disturbs the NTP daemon; it runs last
// so that earlier tests are not affected by the daemon's recovery period.
func Test_CM_AccCMNTP_DriftDetection(t *testing.T) {
	RequireCM(t)
	var hostVal string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { ntpSweep("time3.google.com") },
				Config: providerConfig + `
resource "ciphertrust_ntp" "test" {
  host = "time3.google.com"
}
`,
				Check: checkStep(t, "drift detection: create",
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", "time3.google.com"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_ntp.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						hostVal = rs.Primary.Attributes["host"]
						return nil
					},
				),
			},
			{
				// Delete the NTP server out-of-band; Read() must detect the absence and mark for re-creation.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client")
					}
					_, _ = client.DeleteByID(
						context.Background(),
						"DELETE",
						hostVal,
						fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_NTP, hostVal),
						nil,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
