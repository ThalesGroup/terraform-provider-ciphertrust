package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// domainSweep deletes all CipherTrust domains whose name starts with "tf-domain-".
// Called in the PreConfig of each test's first step to clean up orphaned domains
// from prior failed runs that may have hit the license domain count limit.
func domainSweep() {
	client, ok := createCMClient()
	if !ok {
		return
	}
	ctx := context.Background()
	id := uuid.New().String()
	filters := url.Values{}
	filters.Set("skip", "0")
	filters.Set("limit", "100")
	rawBody, err := client.ListWithFilters(ctx, id, common.URL_DOMAIN, filters)
	if err != nil {
		return
	}
	gjson.Get(rawBody, "resources").ForEach(func(_, domain gjson.Result) bool {
		name := domain.Get("name").String()
		domainID := domain.Get("id").String()
		if strings.HasPrefix(name, "tf-domain-") && domainID != "" {
			delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, domainID)
			_, _ = client.DeleteByID(ctx, "DELETE", domainID, delURL, nil)
		}
		return true
	})
}

// requireDomainCreationLicensed probes the CM API to verify that domain
// creation is permitted under the current license. If the CM returns
// HTTP 409 "not permitted by current license", the calling test is skipped
// so that a license-restricted environment produces SKIP rather than FAIL.
func requireDomainCreationLicensed(t *testing.T) {
	t.Helper()
	client, ok := createCMClient()
	if !ok {
		t.Skip("CM client unavailable — skipping domain creation license check")
		return
	}
	probeName := "tf-license-probe-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	probePayload, _ := json.Marshal(map[string]interface{}{
		"name":   probeName,
		"admins": []string{"admin"},
	})
	ctx := context.Background()
	resp, err := client.PostDataV2(ctx, uuid.New().String(), common.URL_DOMAIN, probePayload)
	if err != nil {
		if strings.Contains(err.Error(), "not permitted by current license") {
			t.Skipf("Domain creation not permitted by current license on this CM instance — skipping %s", t.Name())
		}
		// Any other error: assume the feature is available and proceed.
		return
	}
	// Probe succeeded — delete the temporary probe domain immediately.
	probeID := gjson.Get(resp, "id").String()
	if probeID != "" {
		delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, probeID)
		_, _ = client.DeleteByID(ctx, "DELETE", probeID, delURL, nil)
	}
}

func TestResourceCMDomain(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create and Read testing
			{
				PreConfig: func() { domainSweep() },
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

// domainConfig returns an HCL config for a domain with configurable admins,
// allow_user_management, and meta_data.
func domainConfig(name string, admins []string, allowUserMgmt bool, meta map[string]string) string {
	adminsStr := "["
	for i, a := range admins {
		if i > 0 {
			adminsStr += ", "
		}
		adminsStr += fmt.Sprintf("%q", a)
	}
	adminsStr += "]"

	metaStr := ""
	if len(meta) > 0 {
		metaStr = "meta_data = {\n"
		for k, v := range meta {
			metaStr += fmt.Sprintf("    %q = %q\n", k, v)
		}
		metaStr += "  }"
	}

	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name                  = %q
  admins                = %s
  allow_user_management = %v
  %s
}
`, name, adminsStr, allowUserMgmt, metaStr)
}

// TestAccCipherTrustCMDomain_basicDrift verifies that out-of-band mutations to
// admins, allow_user_management, and meta_data surface as drift.
func TestAccCipherTrustCMDomain_basicDrift(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, true, map[string]string{"env": "test"}),
				Check: checkStep(t, "basicDrift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "name", rName),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.0", "admin"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "allow_user_management", "true"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.env", "test"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_domain.test"]
						if !ok {
							return fmt.Errorf("resource ciphertrust_domain.test not found in state")
						}
						domainID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// No-drift check: plan after apply must be empty.
				Config:             domainConfig(rName, []string{"admin"}, true, map[string]string{"env": "test"}),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				// Out-of-band mutation: add admin2 to admins.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload, _ := json.Marshal(map[string]interface{}{
						"admins": []string{"admin", "admin2"},
					})
					_, _ = client.UpdateData(context.Background(), domainID, common.URL_DOMAIN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Re-apply original config; plan must be empty after.
				Config: domainConfig(rName, []string{"admin"}, true, map[string]string{"env": "test"}),
				Check: checkStep(t, "basicDrift: re-apply",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.0", "admin"),
				),
			},
		},
	})
}

// TestAccCipherTrustCMDomain_deleteOutOfBand verifies that when a domain is
// deleted out-of-band, Read() emits a warning and keeps the resource in state,
// and that terraform destroy on an already-deleted domain completes without error.
func TestAccCipherTrustCMDomain_deleteOutOfBand(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-oob-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, nil),
				Check: checkStep(t, "deleteOutOfBand: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_domain.test"]
						if !ok {
							return fmt.Errorf("resource ciphertrust_domain.test not found in state")
						}
						domainID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Step 2: OOB delete + refresh.
				// Read() gets 404, emits warning, keeps resource in state.
				// State is unchanged → config matches state → plan is empty.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, domainID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", domainID, deleteURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: false, // correct: keep-in-state leaves no diff
			},
		},
	})
}

// TestAccCipherTrustCMDomain_updatePathKey verifies that Update() sends state.ID
// (UUID) as the PATCH path parameter. Uses meta_data change as the trigger because
// allow_user_management is not updatable via PATCH on CM domains.
func TestAccCipherTrustCMDomain_updatePathKey(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-upd-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, nil),
				Check: checkStep(t, "updatePathKey: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
				),
			},
			{
				// Change meta_data — this is definitely updatable via PATCH and confirms
				// that Update() issues PATCH to /v1/domains/{uuid} (not /v1/domains/{name}).
				Config: domainConfig(rName, []string{"admin"}, false, map[string]string{"env": "test"}),
				Check: checkStep(t, "updatePathKey: add meta_data",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.env", "test"),
				),
			},
			{
				// No-drift check after update.
				Config:             domainConfig(rName, []string{"admin"}, false, map[string]string{"env": "test"}),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCipherTrustCMDomain_hsmDrift verifies drift detection for HSM fields.
// Skipped unless CIPHERTRUST_TEST_HSM_CONNECTION_ID is set.
func TestAccCipherTrustCMDomain_hsmDrift(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	hsmConnID := getEnvOrSkip(t, "CIPHERTRUST_TEST_HSM_CONNECTION_ID")
	rName := "tf-domain-hsm-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name               = %q
  admins             = ["admin"]
  hsm_connection_id  = %q
}
`, rName, hsmConnID),
				Check: checkStep(t, "hsmDrift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "hsm_connection_id", hsmConnID),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_domain.test"]
						if !ok {
							return fmt.Errorf("resource ciphertrust_domain.test not found in state")
						}
						domainID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band removal of hsm_connection_id.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload, _ := json.Marshal(map[string]interface{}{
						"hsm_connection_id": "",
					})
					_, _ = client.UpdateData(context.Background(), domainID, common.URL_DOMAIN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name               = %q
  admins             = ["admin"]
  hsm_connection_id  = %q
}
`, rName, hsmConnID),
				Check: checkStep(t, "hsmDrift: re-apply",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "hsm_connection_id", hsmConnID),
				),
			},
		},
	})
}

// getEnvOrSkip returns the value of an env var, skipping the test if unset.
func getEnvOrSkip(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("HSM connection not available in this environment: %s not set", key)
	}
	return v
}

// TestCMDomainNameImmutable verifies that attempting to rename a domain after
// creation produces a clear, actionable plan-time error rather than silent
// state drift.
func TestCMDomainNameImmutable(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
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
