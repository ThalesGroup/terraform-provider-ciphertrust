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

func ntpConfig(host string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "test" {
  host = %q
}
`, host)
}

func TestResourceCMNTP(t *testing.T) {
	RequireCM(t)
	host1 := "ntp-test1-" + uuid.New().String()[:8] + ".test.local"
	host2 := "ntp-test2-" + uuid.New().String()[:8] + ".test.local"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "ntp_server_1" {
  host = %q
}
`, host1),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.ntp_server_1", "host", host1),
				),
			},
			{
				// Update test - this will trigger a replace (delete + create) due to RequiresReplace
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_ntp" "ntp_server_1" {
  host = %q
}
`, host2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.ntp_server_1", "host", host2),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestAccCipherTrustNTP_DriftDetection verifies that out-of-band deletion
// (deletion via direct API call outside of Terraform) is detected during refresh,
// causing Terraform to plan a re-create of the resource.
func TestAccCipherTrustNTP_DriftDetection(t *testing.T) {
	RequireCM(t)
	host := "ntp-drift-" + uuid.New().String()[:8] + ".test.local"
	var capturedHost string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: ntpConfig(host),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", host),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_ntp.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedHost = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion; next refresh should detect drift and remove from state.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_NTP+"/"+capturedHost,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustNTP_DestroyOOB verifies that terraform destroy succeeds
// when the NTP server was already deleted out-of-band (HTTP 404 guard in Delete()).
func TestAccCipherTrustNTP_DestroyOOB(t *testing.T) {
	RequireCM(t)
	host := "ntp-destroy-oob-" + uuid.New().String()[:8] + ".test.local"
	var capturedHost string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: ntpConfig(host),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", host),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_ntp.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedHost = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion before destroy; terraform destroy must succeed without error.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_NTP+"/"+capturedHost,
					)
				},
				// Empty config triggers destroy; the 404 guard in Delete() should handle it gracefully.
				Config: providerConfig + ``,
			},
		},
	})
}

// TestAccCipherTrustNTP_Idempotent verifies that a subsequent plan with no
// out-of-band changes produces an empty diff (no spurious drift).
func TestAccCipherTrustNTP_Idempotent(t *testing.T) {
	RequireCM(t)
	host := "ntp-idempotent-" + uuid.New().String()[:8] + ".test.local"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: ntpConfig(host),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_ntp.test", "host", host),
				),
			},
			{
				// Subsequent plan with no changes should produce an empty diff.
				Config:             ntpConfig(host),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
