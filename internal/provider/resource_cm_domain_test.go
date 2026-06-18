package provider

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// requireDomainLicenseOrSkip skips the test when the CM instance does not have
// a license that permits domain creation (API returns status 409 with
// "Operation not permitted by current license").
func requireDomainLicenseOrSkip(t *testing.T) {
	t.Helper()
	client, ok := createCMClient()
	if !ok {
		t.Skip("skipping: could not create CM client")
		return
	}
	// Probe: attempt to create a transient domain. A 409 license error
	// means domain creation is not licensed on this instance.
	probeName := "__license_probe_" + uuid.New().String()[:8] + "__"
	probePayload := []byte(`{"name":"` + probeName + `","admins":["admin"]}`)
	resp, err := client.PostDataV2(context.Background(), uuid.NewString(), common.URL_DOMAIN, probePayload)
	if err != nil {
		if strings.Contains(err.Error(), "Operation not permitted by current license") {
			t.Skipf("skipping: domain creation is not permitted by the CM license on this instance: %v", err)
		}
		// Any other error (e.g. 409 name conflict) means domains are supported — continue.
		return
	}
	// Probe succeeded — delete the transient domain (best-effort).
	if domainID := gjson.Get(resp, "id").String(); domainID != "" {
		url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, domainID)
		_, _ = client.DeleteByID(context.Background(), "DELETE", domainID, url, nil)
	}
}

func TestResourceCMDomain(t *testing.T) {
	RequireCM(t)
	requireDomainLicenseOrSkip(t)
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

// TestAccCipherTrustCMDomain_drift verifies that Read() surfaces out-of-band
// changes to allow_user_management as Terraform drift.
func TestAccCipherTrustCMDomain_drift(t *testing.T) {
	RequireCM(t)
	requireDomainLicenseOrSkip(t)
	rName := "tf-domain-drift-" + uuid.New().String()[:8]
	const resourceName = "ciphertrust_domain.test"

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create domain with allow_user_management=false; assert state.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name                  = %q
  admins                = ["admin"]
  allow_user_management = false
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "allow_user_management", "false"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: update allow_user_management=true out-of-band, then refresh.
				// Read() must surface the changed value (drift detection).
				PreConfig: func() {
					if capturedID == "" {
						return
					}
					client, ok := createCMClient()
					if !ok {
						return
					}
					payload := []byte(`{"allow_user_management":true}`)
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_DOMAIN,
						payload,
						"updatedAt",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_updatePathKey verifies that Update() uses state.ID
// (not plan.Name) as the PATCH path segment, preventing 404 errors when the
// domain name is not a UUID.
func TestAccCipherTrustCMDomain_updatePathKey(t *testing.T) {
	RequireCM(t)
	requireDomainLicenseOrSkip(t)
	rName := "tf-domain-upd-" + uuid.New().String()[:8]
	const resourceName = "ciphertrust_domain.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create domain without meta_data.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttr(resourceName, "name", rName),
				),
			},
			{
				// Step 2: apply in-place update adding meta_data. Succeeds only if
				// state.ID is used as the PATCH path segment — old code sent name
				// which is not a UUID and caused a 404.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { "env" = "test" }
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "meta_data.env", "test"),
				),
			},
			{
				// Step 3: assert no drift after the apply.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { "env" = "test" }
}
`, rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_destroyOOB verifies that Delete() succeeds even
// when the domain has already been deleted out-of-band (exercises 404 guard).
func TestAccCipherTrustCMDomain_destroyOOB(t *testing.T) {
	RequireCM(t)
	requireDomainLicenseOrSkip(t)
	rName := "tf-domain-oob-" + uuid.New().String()[:8]
	const resourceName = "ciphertrust_domain.test"

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create domain and capture its ID.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[resourceName]
						if !ok {
							return fmt.Errorf("resource %s not found in state", resourceName)
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: delete the domain out-of-band before Terraform destroy.
				// Without the 404 guard, DeleteByID returns a 404 error and the
				// destroy step fails. With the guard it completes successfully.
				PreConfig: func() {
					if capturedID == "" {
						return
					}
					client, ok := createCMClient()
					if !ok {
						return
					}
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, capturedID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", capturedID, url, nil)
				},
				Destroy: true,
			},
		},
	})
}
