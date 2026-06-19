package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func TestResourceCMDomain(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name = "%s"
  admins = ["admin"]
  allow_user_management = false
  meta_data = {
      "abc": "xyz"
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.testDomain", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.testDomain", "name", rName),
				),
			},
			// Update and Read testing
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name = "%s"
  admins = ["admin"]
  allow_user_management = false
  meta_data = {
      "abc": "xyz",
	  "color": "blue"
  }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.testDomain", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.testDomain", "name", rName),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestCMDomainNameImmutable verifies that attempting to rename a domain after
// creation produces a clear, actionable plan-time error rather than silent
// state drift.
func TestCMDomainNameImmutable(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.testDomain", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.testDomain", "name", rName),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name   = %q
  admins = ["admin"]
}
`, rName+"-renamed"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// TestAccCipherTrustCMDomain_drift verifies that Read() detects an out-of-band
// deletion (404) and removes the resource from state so Terraform plans
// recreation.
func TestAccCipherTrustCMDomain_drift(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	rName := "tf-domain-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = [%q]
}
`, rName, adminUser),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Delete domain out-of-band; Read() should detect 404 and call
				// RemoveResource, causing Terraform to plan recreation.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client for OOB delete")
					}
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, capturedID)
					client.DeleteByID(context.Background(), "DELETE", capturedID, url, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_allowUserMgmtDrift verifies drift detection for
// the allow_user_management attribute.
func TestAccCipherTrustCMDomain_allowUserMgmtDrift(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	rName := "tf-domain-aum-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name                  = %q
  admins                = [%q]
  allow_user_management = false
}
`, rName, adminUser),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "allow_user_management", "false"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Flip allow_user_management to true out-of-band; drift should be detected.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client for OOB update")
					}
					payloadBytes, _ := json.Marshal(map[string]interface{}{
						"allow_user_management": true,
					})
					client.UpdateData(context.Background(), capturedID, common.URL_DOMAIN, payloadBytes, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_adminsDrift verifies drift detection for the
// admins list attribute.
func TestAccCipherTrustCMDomain_adminsDrift(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	adminUser2 := os.Getenv("CIPHERTRUST_ADMIN_USER2")
	if adminUser2 == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER2 must be set to a second valid CM username for this test")
	}
	rName := "tf-domain-adm-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = [%q]
}
`, rName, adminUser),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Replace admins list out-of-band; drift should be detected.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client for OOB update")
					}
					payloadBytes, _ := json.Marshal(map[string]interface{}{
						"admins": []string{adminUser2},
					})
					client.UpdateData(context.Background(), capturedID, common.URL_DOMAIN, payloadBytes, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_metaDataDrift verifies drift detection for the
// meta_data map attribute.
func TestAccCipherTrustCMDomain_metaDataDrift(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	rName := "tf-domain-meta-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = [%q]
  meta_data = { "env" = "test" }
}
`, rName, adminUser),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Change meta_data out-of-band; drift should be detected.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client for OOB update")
					}
					payloadBytes, _ := json.Marshal(map[string]interface{}{
						"meta": map[string]string{"env": "oob-changed"},
					})
					client.UpdateData(context.Background(), capturedID, common.URL_DOMAIN, payloadBytes, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_parentCaIdDrift verifies drift detection for the
// parent_ca_id attribute. Requires CIPHERTRUST_PARENT_CA_ID to be set.
func TestAccCipherTrustCMDomain_parentCaIdDrift(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	parentCaId := os.Getenv("CIPHERTRUST_PARENT_CA_ID")
	if parentCaId == "" {
		t.Skip("CIPHERTRUST_PARENT_CA_ID must be set to a valid CA ID for this test")
	}
	rName := "tf-domain-pca-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name         = %q
  admins       = [%q]
  parent_ca_id = %q
}
`, rName, adminUser, parentCaId),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Clear parent_ca_id out-of-band; drift should be detected.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client for OOB update")
					}
					payloadBytes, _ := json.Marshal(map[string]interface{}{
						"parent_ca_id": "",
					})
					client.UpdateData(context.Background(), capturedID, common.URL_DOMAIN, payloadBytes, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_hsmConnectionIdDrift verifies drift detection for
// the hsm_connection_id attribute. Requires CIPHERTRUST_HSM_CONNECTION_ID.
func TestAccCipherTrustCMDomain_hsmConnectionIdDrift(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	hsmConnID := os.Getenv("CIPHERTRUST_HSM_CONNECTION_ID")
	if hsmConnID == "" {
		t.Skip("CIPHERTRUST_HSM_CONNECTION_ID must be set to a valid HSM connection ID for this test")
	}
	rName := "tf-domain-hsm-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name              = %q
  admins            = [%q]
  hsm_connection_id = %q
}
`, rName, adminUser, hsmConnID),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Clear hsm_connection_id out-of-band; drift should be detected.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client for OOB update")
					}
					payloadBytes, _ := json.Marshal(map[string]interface{}{
						"hsm_connection_id": "",
					})
					client.UpdateData(context.Background(), capturedID, common.URL_DOMAIN, payloadBytes, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_hsmKekLabelDrift verifies drift detection for the
// hsm_kek_label attribute. Requires CIPHERTRUST_HSM_CONNECTION_ID and
// CIPHERTRUST_HSM_KEK_LABEL.
func TestAccCipherTrustCMDomain_hsmKekLabelDrift(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	hsmConnID := os.Getenv("CIPHERTRUST_HSM_CONNECTION_ID")
	if hsmConnID == "" {
		t.Skip("CIPHERTRUST_HSM_CONNECTION_ID must be set to a valid HSM connection ID for this test")
	}
	hsmKekLabel := os.Getenv("CIPHERTRUST_HSM_KEK_LABEL")
	if hsmKekLabel == "" {
		t.Skip("CIPHERTRUST_HSM_KEK_LABEL must be set for this test")
	}
	rName := "tf-domain-kek-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name              = %q
  admins            = [%q]
  hsm_connection_id = %q
  hsm_kek_label     = %q
}
`, rName, adminUser, hsmConnID, hsmKekLabel),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Change hsm_kek_label out-of-band; drift should be detected.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client for OOB update")
					}
					payloadBytes, _ := json.Marshal(map[string]interface{}{
						"hsm_kek_label": "oob-changed-label",
					})
					client.UpdateData(context.Background(), capturedID, common.URL_DOMAIN, payloadBytes, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_updateUsesID verifies that Update() uses the
// domain UUID as the PATCH path segment (not the domain name). If the wrong
// path segment were used, the PATCH would 404 and step 2 would fail.
// Requires CIPHERTRUST_ADMIN_USER and CIPHERTRUST_ADMIN_USER2.
//
// Note: TestAccCipherTrustCMDomain_destroyAfterOOBDelete is not implemented.
// When terraform destroy runs, the framework invokes Read() first. Read() calls
// RemoveResource on 404, removing the domain from state before Delete() is
// invoked. The notFoundError guard in Delete() covers only the race window
// between Read() returning and Delete() being called, which the test framework
// cannot reproduce. The guard is verified by code review only.
func TestAccCipherTrustCMDomain_updateUsesID(t *testing.T) {
	RequireCM(t)
	adminUser := os.Getenv("CIPHERTRUST_ADMIN_USER")
	if adminUser == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER must be set to a valid CM username for this test")
	}
	adminUser2 := os.Getenv("CIPHERTRUST_ADMIN_USER2")
	if adminUser2 == "" {
		t.Skip("CIPHERTRUST_ADMIN_USER2 must be set to a second valid CM username for this test")
	}
	rName := "tf-domain-uid-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = [%q]
}
`, rName, adminUser),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.#", "1"),
				),
			},
			{
				// Update admins — if PATCH used domain name instead of UUID the request
				// would 404 and this step would fail.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = [%q, %q]
}
`, rName, adminUser, adminUser2),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.#", "2"),
				),
			},
		},
	})
}
