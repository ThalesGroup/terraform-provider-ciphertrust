package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// skipIfDomainCreationNotLicensed skips the test when the live CipherTrust Manager
// returns a 409-license error for domain creation. Sub-domain support requires a
// specific CM license tier; tests that create domains must call this in PreCheck.
func skipIfDomainCreationNotLicensed(t *testing.T) {
	t.Helper()
	// Use the same address/credentials as providerConfig so this check always works.
	addr := "https://10.171.98.28"
	user := "admin"
	pass := "Asdf@1234"
	dom := "root"
	auth := "root"

	client, err := common.NewClient(context.Background(), uuid.NewString(),
		&addr, &auth, &dom, &user, &pass, nil, true, 30)
	if err != nil {
		t.Skipf("skipping: could not create CM client for domain pre-check: %v", err)
	}

	type domainPayload struct {
		Name   string   `json:"name"`
		Admins []string `json:"admins"`
	}
	payload, _ := json.Marshal(domainPayload{
		Name:   "tf-liccheck-" + acctest.RandStringFromCharSet(6, acctest.CharSetAlphaNum),
		Admins: []string{"admin"},
	})

	resp, err := client.PostDataV2(context.Background(), uuid.NewString(), common.URL_DOMAIN, payload)
	if err != nil {
		if strings.Contains(err.Error(), "current license") || strings.Contains(err.Error(), "status: 409") {
			t.Skipf("skipping: CM license does not permit domain creation in this environment: %v", err)
		}
		// Other transient errors (network, etc.) are not a skip condition — let the test proceed.
		return
	}

	// Clean up the probe domain so we don't leave orphaned resources.
	if resp != "" {
		var result map[string]interface{}
		if json.Unmarshal([]byte(resp), &result) == nil {
			if id, ok := result["id"].(string); ok && id != "" {
				_, _ = client.DeleteByURL(context.Background(), uuid.NewString(), common.URL_DOMAIN+"/"+id)
			}
		}
	}
}

func cmDomainConfig(name string, meta map[string]string) string {
	metaStr := ""
	for k, v := range meta {
		metaStr += fmt.Sprintf("    %q: %q\n", k, v)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_domain" "testDomain" {
  name = "%s"
  admins = ["admin"]
  allow_user_management = false
  meta_data = {
%s  }
}
`, name, metaStr)
}

func TestResourceCMDomain(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-" + acctest.RandStringFromCharSet(10, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 func() { skipIfDomainCreationNotLicensed(t) },
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
			// Verify no drift on a subsequent plan.
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
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
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

func TestAccCMDomain_driftDetection(t *testing.T) {
	RequireCM(t)
	rName := "tf-domain-drift-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		PreCheck:                 func() { skipIfDomainCreationNotLicensed(t) },
		Steps: []resource.TestStep{
			{
				Config: cmDomainConfig(rName, map[string]string{"env": "drift-test"}),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_domain.testDomain", "id"),
					resource.TestCheckResourceAttr("ciphertrust_domain.testDomain", "name", rName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_domain.testDomain"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion; next plan should detect drift and schedule recreation.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_DOMAIN+"/"+capturedID,
					)
				},
				Config:             cmDomainConfig(rName, map[string]string{"env": "drift-test"}),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
