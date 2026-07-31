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
	if os.Getenv("TF_ACC") == "" {
		return
	}
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

func Test_CM_ResourceCMDomain(t *testing.T) {
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

// cmDomainOOBConfig returns an HCL config for a domain resource used in
// out-of-band delete testing. Uses the resource label "oob" to avoid
// conflicts with other tests using "test" label.
func cmDomainOOBConfig(name string) string {
	return fmt.Sprintf(providerConfig+`
resource "ciphertrust_domain" "oob" {
  name   = %q
  admins = ["admin"]
}
`, name)
}

// Test_CM_AccCipherTrustCMDomain_basicDrift verifies that out-of-band mutations to
// admins, allow_user_management, and meta_data surface as drift.
func Test_CM_AccCipherTrustCMDomain_basicDrift(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainName string

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
						// CM domain PATCH uses name as the path key, not UUID.
						domainName = rs.Primary.Attributes["name"]
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
					// CM domain PATCH endpoint uses the domain name as the URL path key.
					_, _ = client.UpdateData(context.Background(), domainName, common.URL_DOMAIN, patchPayload, "id")
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

// Test_CM_AccCipherTrustCMDomain_deleteOutOfBand verifies that when a domain is
// deleted out-of-band, Read() calls RemoveResource to remove the resource from state,
// and the plan correctly proposes recreation. After re-apply, the domain is recreated.
func Test_CM_AccCipherTrustCMDomain_deleteOutOfBand(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-oob-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    cmDomainOOBConfig(rName),
				Check: checkStep(t, "deleteOutOfBand: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.oob", "id"),
					resource.TestCheckResourceAttrWith("ciphertrust_domain.oob", "id", func(val string) error {
						domainID = val
						return nil
					}),
				),
			},
			{
				// Step 2: OOB delete + refresh.
				// Read() gets 404, calls RemoveResource — resource removed from state.
				// Config still wants the resource → plan proposes recreation → non-empty plan.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, domainID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", domainID, deleteURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 3: re-apply config — Terraform recreates the domain.
				Config: cmDomainOOBConfig(rName),
				Check: checkStep(t, "deleteOutOfBand: recreated",
					resource.TestCheckResourceAttr("ciphertrust_domain.oob", "name", rName),
				),
			},
		},
	})
}

// Test_CM_AccCipherTrustCMDomain_updatePathKey verifies that Update() sends state.ID
// (UUID) as the PATCH path parameter. Uses meta_data change as the trigger because
// allow_user_management is not updatable via PATCH on CM domains.
func Test_CM_AccCipherTrustCMDomain_updatePathKey(t *testing.T) {
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

// Test_CM_AccCipherTrustCMDomain_hsmDrift verifies drift detection for HSM fields.
// Skipped unless CIPHERTRUST_TEST_HSM_CONNECTION_ID is set.
func Test_CM_AccCipherTrustCMDomain_hsmDrift(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	hsmConnID := getEnvOrSkip(t, "CIPHERTRUST_TEST_HSM_CONNECTION_ID")
	rName := "tf-domain-hsm-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainName string

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
						// CM domain PATCH uses name as the path key, not UUID.
						domainName = rs.Primary.Attributes["name"]
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
					// CM domain PATCH endpoint uses the domain name as the URL path key.
					_, _ = client.UpdateData(context.Background(), domainName, common.URL_DOMAIN, patchPayload, "id")
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

// Test_CM_AccCMDomain_ImmutableFields verifies that name, admins, and
// allow_user_management are each blocked at plan time by the immutable modifier.
func Test_CM_AccCMDomain_ImmutableFields(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-imm-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, nil),
				Check: checkStep(t, "ImmutableFields: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "name", rName),
				),
			},
			// Rename attempt must be blocked at plan time.
			{
				Config:      domainConfig(rName+"-renamed", []string{"admin"}, false, nil),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			// Admins change must be blocked at plan time.
			{
				Config:      domainConfig(rName, []string{"admin", "admin2"}, false, nil),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
			// allow_user_management change must be blocked at plan time.
			{
				Config:      domainConfig(rName, []string{"admin"}, true, nil),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
			},
		},
	})
}

// Test_CM_AccCMDomain_ParentCAIdImmutable verifies that parent_ca_id is blocked at
// plan time when a change is attempted after creation. Requires
// CIPHERTRUST_TEST_PARENT_CA_ID to be set to a valid CA ID on the CM instance
// (analogous to CIPHERTRUST_TEST_HSM_CONNECTION_ID for HSM tests).
func Test_CM_AccCMDomain_ParentCAIdImmutable(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	parentCAID := getEnvOrSkip(t, "CIPHERTRUST_TEST_PARENT_CA_ID")
	rName := "tf-domain-pca-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name         = %q
  admins       = ["admin"]
  parent_ca_id = %q
}
`, rName, parentCAID),
				Check: checkStep(t, "ParentCAIdImmutable: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "parent_ca_id", parentCAID),
				),
			},
			// Changing parent_ca_id must be blocked at plan time.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name         = %q
  admins       = ["admin"]
  parent_ca_id = %q
}
`, rName, parentCAID+"-changed"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
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

// Test_CM_CMDomainNameImmutable verifies that attempting to rename a domain after
// creation produces a clear, actionable plan-time error rather than silent
// state drift.
func Test_CM_CMDomainNameImmutable(t *testing.T) {
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

// Test_CM_AccCMDomain_Drift verifies that out-of-band mutations to meta_data surface as
// drift when the !state.Meta.IsNull() guard is active (meta_data is configured in step 1).
func Test_CM_AccCMDomain_Drift(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-drift2-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, map[string]string{"env": "test"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
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
				// Out-of-band mutation — change meta_data value.
				// The three-branch Read() (with !state.Meta.IsNull() guard active because
				// prior state has non-null meta_data) must surface the drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(
						context.Background(),
						domainID,
						common.URL_DOMAIN,
						[]byte(`{"meta":{"env":"changed-oob"}}`),
						"updatedAt",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMDomain_DeleteOutOfBand verifies that when a domain is deleted out-of-band,
// the fixed Read() calls RemoveResource (not AddWarning) on 404 and Terraform plans recreation.
func Test_CM_AccCMDomain_DeleteOutOfBand(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-oob2-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var domainID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    cmDomainOOBConfig(rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.oob", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_domain.oob"]
						if !ok {
							return fmt.Errorf("resource ciphertrust_domain.oob not found in state")
						}
						domainID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// OOB delete — Read() must call RemoveResource on 404; plan proposes recreation.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, domainID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", domainID, deleteURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMDomain_Idempotency verifies that when meta_data is absent from config,
// the !state.Meta.IsNull() guard in Read() leaves state as MapNull even when CM returns
// "{}", producing no phantom drift on a second plan.
func Test_CM_AccCMDomain_Idempotency(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-idem-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	// Use domainConfig with nil meta so no meta_data block appears in HCL.
	cfg := domainConfig(rName, []string{"admin"}, false, nil)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    cfg,
				Check: checkStep(t, "Idempotency: create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "name", rName),
				),
			},
			// Second plan with identical config — must be empty (no phantom meta_data drift).
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// domainConfigEmptyMeta returns an HCL config for a domain with meta_data = {}.
// The domainConfig() helper cannot produce this because an empty map is treated
// the same as nil (no meta_data attribute).
func domainConfigEmptyMeta(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name                  = %q
  admins                = ["admin"]
  allow_user_management = false
  meta_data             = {}
}
`, name)
}

// TestCipherTrust_CMDomain_MetaDataClear verifies that clearing meta_data to an empty
// map ({}) removes all keys from CM and leaves state as {} (not null), and that a
// subsequent terraform plan produces no diff (acceptance condition 2).
func Test_CM_CipherTrust_CMDomain_MetaDataClear(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, map[string]string{"abc": "xyz", "newkey": "newval"}),
				Check: checkStep(t, "MetaDataClear: create",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.abc", "xyz"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.newkey", "newval"),
				),
			},
			{
				Config: domainConfigEmptyMeta(rName),
				Check: checkStep(t, "MetaDataClear: clear to {}",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.%", "0"),
				),
			},
			{
				Config:             domainConfigEmptyMeta(rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCipherTrust_CMDomain_MetaDataPartialRemove verifies that removing one key from
// meta_data deletes only that key on CM while preserving the remaining key, and that
// a subsequent terraform plan produces no diff (acceptance condition 3).
func Test_CM_CipherTrust_CMDomain_MetaDataPartialRemove(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, map[string]string{"abc": "xyz", "newkey": "newval"}),
				Check: checkStep(t, "MetaDataPartialRemove: create",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.abc", "xyz"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.newkey", "newval"),
				),
			},
			{
				Config: domainConfig(rName, []string{"admin"}, false, map[string]string{"abc": "xyz"}),
				Check: checkStep(t, "MetaDataPartialRemove: remove newkey",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.abc", "xyz"),
					resource.TestCheckNoResourceAttr("ciphertrust_domain.test", "meta_data.newkey"),
				),
			},
			{
				Config:             domainConfig(rName, []string{"admin"}, false, map[string]string{"abc": "xyz"}),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCipherTrust_CMDomain_MetaDataRemoveAttribute verifies that removing the meta_data
// attribute entirely from config (null) deletes all CM meta keys, leaves state as null
// (not {}), and produces no diff on a subsequent plan (acceptance condition 4).
func Test_CM_CipherTrust_CMDomain_MetaDataRemoveAttribute(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, map[string]string{"abc": "xyz"}),
				Check: checkStep(t, "MetaDataRemoveAttribute: create",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.abc", "xyz"),
				),
			},
			{
				// domainConfig with nil meta omits the meta_data attribute entirely (null).
				Config: domainConfig(rName, []string{"admin"}, false, nil),
				Check: checkStep(t, "MetaDataRemoveAttribute: remove attribute",
					resource.TestCheckNoResourceAttr("ciphertrust_domain.test", "meta_data.abc"),
					resource.TestCheckNoResourceAttr("ciphertrust_domain.test", "meta_data.%"),
				),
			},
			{
				Config:             domainConfig(rName, []string{"admin"}, false, nil),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCipherTrust_CMDomain_MetaDataDrift verifies that out-of-band addition of a key to
// meta on CM is detected on the next terraform refresh (acceptance condition 5).
func Test_CM_CipherTrust_CMDomain_MetaDataDrift(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-" + uuid.New().String()[:8]
	var domainID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config:    domainConfig(rName, []string{"admin"}, false, map[string]string{"abc": "xyz"}),
				Check: checkStep(t, "MetaDataDrift: create",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.abc", "xyz"),
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
				// Out-of-band: add a new key to meta on CM, then refresh.
				// Read() with !state.Meta.IsNull() guard active will detect the drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping OOB step")
						return
					}
					_, err := client.UpdateData(
						context.Background(),
						domainID,
						common.URL_DOMAIN,
						[]byte(`{"meta":{"oob":"val"}}`),
						"updatedAt",
					)
					if err != nil {
						t.Logf("OOB PATCH failed: %v — skipping", err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMDomain_MutableFieldUpdate verifies that Update() successfully PATCHes a
// mutable field (meta_data) after creation. The CM domain PATCH endpoint uses the
// domain name as the path key.
func Test_CM_AccCMDomain_MutableFieldUpdate(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-upd-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { "env" = "test" }
}
`, rName),
				Check: checkStep(t, "create with meta_data",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.env", "test"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { "env" = "prod" }
}
`, rName),
				Check: checkStep(t, "update meta_data",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.env", "prod"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { "env" = "prod" }
}
`, rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Domain_ParentCAId_Recreation_Idempotency verifies that omitting parent_ca_id
// and hsm_kek_label in the configuration does not trigger domain replacement or plan drift
// during subsequent plans/applies after state hydration.
func Test_CM_Domain_ParentCAId_Recreation_Idempotency(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	rName := "tf-domain-idemp-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: checkStep(t, "create domain without parent_ca_id",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckNoResourceAttr("ciphertrust_domain.test", "parent_ca_id"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Domain_ParentCAIdCreateDoesNotCrash verifies that creating a domain with
// parent_ca_id set no longer crashes with "Provider produced inconsistent result after
// apply" (TFIN-539). CM omits parent_ca_id from both the 201 and GET responses (write-only
// input); the provider must preserve the configured value rather than overwriting it with null.
// Requires CIPHERTRUST_TEST_PARENT_CA_ID to be set to a valid local CA ID on the CM instance.
func Test_CM_Domain_ParentCAIdCreateDoesNotCrash(t *testing.T) {
	RequireCM(t)
	requireDomainCreationLicensed(t)
	parentCAID := getEnvOrSkip(t, "CIPHERTRUST_TEST_PARENT_CA_ID")
	rName := "tf-domain-pca-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { domainSweep() },
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name         = %q
  admins       = ["admin"]
  parent_ca_id = %q
}
`, rName, parentCAID),
				Check: checkStep(t, "create with parent_ca_id — no crash",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "parent_ca_id", parentCAID),
				),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Domain_EmptyNameRejectedAtPlan verifies that name = "" is rejected at plan
// time by the LengthAtLeast(1) validator before reaching CM's API (TFIN-540).
func Test_CM_Domain_EmptyNameRejectedAtPlan(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_domain" "test" {
  name   = ""
  admins = ["admin"]
}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)at least 1`),
			},
		},
	})
}

// Test_CM_Domain_EmptyAdminsRejectedAtPlan verifies that admins = [] is rejected at
// plan time by the SizeAtLeast(1) validator before reaching CM's API (TFIN-540).
func Test_CM_Domain_EmptyAdminsRejectedAtPlan(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_domain" "test" {
  name   = "test-domain-empty-admins"
  admins = []
}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)at least 1`),
			},
		},
	})
}
