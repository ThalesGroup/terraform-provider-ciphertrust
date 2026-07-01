package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// cleanupTestCMDomains lists all sub-domains in CipherTrust Manager and deletes
// every one of them. This is called at the start of every domain test to reclaim
// domain license slots consumed by previous failed runs.
// This is only safe on a dedicated test CM instance (all sub-domains are test
// artifacts). Best-effort: errors are logged but do not fail the test.
func cleanupTestCMDomains() {
	client, ok := createCMClient()
	if !ok {
		fmt.Println("cleanupTestCMDomains: could not create CM client, skipping cleanup")
		return
	}
	ctx := context.Background()
	allDomains, err := client.GetAll(ctx, uuid.New().String(), common.URL_DOMAIN)
	if err != nil {
		fmt.Printf("cleanupTestCMDomains: failed to list domains: %v\n", err)
		return
	}
	results := gjson.Parse(allDomains).Array()
	fmt.Printf("cleanupTestCMDomains: found %d sub-domain(s) in CM\n", len(results))
	for _, domain := range results {
		name := domain.Get("name").String()
		id := domain.Get("id").String()
		if id == "" {
			fmt.Printf("cleanupTestCMDomains: skipping domain with empty id (name=%q)\n", name)
			continue
		}
		fmt.Printf("cleanupTestCMDomains: deleting domain name=%q id=%s\n", name, id)
		deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, id)
		_, delErr := client.DeleteByID(ctx, "DELETE", id, deleteURL, nil)
		if delErr != nil && !strings.Contains(delErr.Error(), "status: 404") {
			fmt.Printf("cleanupTestCMDomains: failed to delete domain '%s' (%s): %v\n", name, id, delErr)
		} else {
			fmt.Printf("cleanupTestCMDomains: deleted domain '%s' (%s)\n", name, id)
		}
	}
}

// requireSubDomainSupport skips the calling test when the CM instance's license
// does not permit sub-domain creation. It performs a probe create to distinguish
// a license restriction (409 "Operation not permitted by current license") from
// other errors. Call after cleanupTestCMDomains() so the probe name is not in use.
func requireSubDomainSupport(t *testing.T) {
	t.Helper()
	client, ok := createCMClient()
	if !ok {
		return // no client — test will fail later with a clear message
	}
	ctx := context.Background()
	probeName := "tf-domain-capability-check"
	payload, _ := json.Marshal(map[string]interface{}{
		"name":   probeName,
		"admins": []string{"admin"},
	})
	_, err := client.PostDataV2(ctx, uuid.New().String(), common.URL_DOMAIN, payload)
	if err != nil {
		if strings.Contains(err.Error(), "Operation not permitted by current license") {
			t.Skipf("skipping %s: CM license does not permit sub-domain creation (409 license restriction)", t.Name())
		}
		return // other error — let the test framework surface it
	}
	// Probe succeeded — delete it immediately to free the license slot.
	allDomains, listErr := client.GetAll(ctx, uuid.New().String(), common.URL_DOMAIN)
	if listErr == nil {
		for _, d := range gjson.Parse(allDomains).Array() {
			if d.Get("name").String() == probeName {
				probeID := d.Get("id").String()
				if probeID != "" {
					delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, probeID)
					_, _ = client.DeleteByID(ctx, "DELETE", probeID, delURL, nil)
				}
				break
			}
		}
	}
}

func TestResourceCMDomain(t *testing.T) {
	RequireCM(t)
	cleanupTestCMDomains()
	requireSubDomainSupport(t)
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
	cleanupTestCMDomains()
	requireSubDomainSupport(t)
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

func TestAccCipherTrustCMDomain_basic(t *testing.T) {
	RequireCM(t)
	cleanupTestCMDomains()
	requireSubDomainSupport(t)
	rName := "tf-test-domain-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "updated_at"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.#", "1"),
				),
			},
			{
				// Verify Read() returns the same values — no drift after create.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin", "admin2"]
}
`, rName),
				Check: checkStep(t, "update admins",
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "admins.#", "2"),
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
				),
			},
		},
	})
}

func TestAccCipherTrustCMDomain_outOfBandDelete(t *testing.T) {
	RequireCM(t)
	cleanupTestCMDomains()
	requireSubDomainSupport(t)
	rName := "tf-test-oob-delete-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name   = %q
  admins = ["admin"]
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band delete via CM client, then refresh.
				// Expected: Read() emits a warning, retains resource in state.
				// Plan shows recreation diff (ExpectNonEmptyPlan: true).
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					ctx := context.Background()
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_DOMAIN, capturedID)
					_, _ = client.DeleteByID(ctx, "DELETE", capturedID, url, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCipherTrustCMDomain_driftDetection(t *testing.T) {
	RequireCM(t)
	cleanupTestCMDomains()
	requireSubDomainSupport(t)
	rName := "tf-test-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name                 = %q
  admins               = ["admin"]
  allow_user_management = false
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "allow_user_management", "false"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change allow_user_management to true, then refresh.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					ctx := context.Background()
					patchPayload, _ := json.Marshal(map[string]interface{}{"allow_user_management": true})
					_, _ = client.UpdateData(ctx, capturedID, common.URL_DOMAIN, patchPayload, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCipherTrustCMDomain_metaDrift(t *testing.T) {
	RequireCM(t)
	cleanupTestCMDomains()
	requireSubDomainSupport(t)
	rName := "tf-test-meta-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "test" {
  name      = %q
  admins    = ["admin"]
  meta_data = { env = "test" }
}
`, rName),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_domain.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.test", "meta_data.env", "test"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_domain.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change meta out-of-band, then refresh.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					ctx := context.Background()
					patchPayload, _ := json.Marshal(map[string]interface{}{"meta": map[string]string{"env": "changed"}})
					_, _ = client.UpdateData(ctx, capturedID, common.URL_DOMAIN, patchPayload, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
