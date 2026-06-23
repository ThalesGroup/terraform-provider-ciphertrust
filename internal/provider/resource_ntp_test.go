package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMNTP(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
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
				// Update test - this will trigger a replace (delete + create) due to RequiresReplace
				Config: providerConfig + `
resource "ciphertrust_ntp" "ntp_server_1" {
  host = "time2.google.com"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.ntp_server_1", "host", "time2.google.com"),
				),
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

// TestAccCMNTP_DriftDetection verifies that an out-of-band deletion is detected as drift.
func TestAccCMNTP_DriftDetection(t *testing.T) {
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
				// Delete the NTP server out-of-band; Read() must detect the 404 and mark for re-creation.
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

// TestAccCMNTP_NoDrift verifies no spurious drift is produced when no out-of-band changes occur.
func TestAccCMNTP_NoDrift(t *testing.T) {
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

// TestAccCMNTP_Delete404Guard verifies that Delete() succeeds when the resource was already deleted out-of-band.
func TestAccCMNTP_Delete404Guard(t *testing.T) {
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
