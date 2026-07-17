package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func Test_CM_ResourceCMRegToken(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}

output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}

resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify number of items
					//resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.reg_token", "items.#", "1"),
					// Verify first order item
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.quantity", "2"),
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.coffee.id", "1"),
					// Verify first coffee item has Computed attributes filled.
					//resource.TestCheckResourceAttr("hashicups_order.test", "items.0.coffee.description", ""),
					// Verify dynamic values have any value set in the state.
					//resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "token"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "id"),
				),
			},
			// ImportState testing
			//{
			//	ResourceName:      "ciphertrust_cm_reg_token.reg_token",
			//	ImportState:       true,
			//	ImportStateVerify: true,
			// The last_updated attribute does not exist in the HashiCups
			// API, therefore there is no value for it during import.
			//	ImportStateVerifyIgnore: []string{"last_updated"},
			//},
			// Update and Read testing
			{
				Config: providerConfig + `
data "ciphertrust_cm_local_ca_list" "groups_local_cas" {
  filters = {
    subject = "/C=US/ST=TX/L=Austin/O=Thales/CN=CipherTrust Root CA"
  }
}
output "casList" {
  value = data.ciphertrust_cm_local_ca_list.groups_local_cas
}
resource "ciphertrust_cm_reg_token" "reg_token" {
  ca_id = tolist(data.ciphertrust_cm_local_ca_list.groups_local_cas.cas)[0].id
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Verify first order item updated
					//resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "token"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.reg_token", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

func Test_CM_CipherTrust_CMRegToken_drift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  max_clients = 5
}
`,
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "max_clients", "5"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// OOB change: update max_clients to 10; Read() must surface the drift.
				// lifetime is intentionally excluded: CM does not echo lifetime in GET
				// responses, so it cannot be used to test drift detection.
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"max_clients": 10})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_REG_TOKEN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_CipherTrust_CMRegToken_deleteOOB(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "test-"
}
`,
				Check: checkStep(t, "deleteOOB: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), common.URL_REG_TOKEN+"/"+capturedID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "test-"
}
`,
				Check: checkStep(t, "deleteOOB: recreated",
					resource.TestCheckResourceAttrWith("ciphertrust_cm_reg_token.test", "id", func(val string) error {
						if val == capturedID {
							return fmt.Errorf("expected new id after OOB delete, got same id %s", val)
						}
						return nil
					}),
				),
			},
		},
	})
}

func Test_CM_CipherTrust_CMRegToken_labelCreate(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  label  = { KmipClientProfile = "default" }
  labels = { env = "test" }
}
`,
				Check: checkStep(t, "labelCreate: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "label.KmipClientProfile", "default"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.env", "test"),
				),
			},
			// Confirm no false drift on map attributes after Read() hydration.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func Test_CM_CipherTrust_CMRegToken_labelDrift(t *testing.T) {
	RequireCM(t)
	var tokenID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: regTokenLabelsConfig("prod"),
				Check: checkStep(t, "labelDrift: create reg token with labels",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.env", "prod"),
					resource.TestCheckResourceAttrWith("ciphertrust_cm_reg_token.test", "id", func(val string) error {
						tokenID = val
						return nil
					}),
				),
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client not available")
					}
					payload := []byte(`{"labels":{"env":"drifted"}}`)
					_, err := client.UpdateData(ctx, tokenID, common.URL_REG_TOKEN, payload, "id")
					if err != nil {
						t.Logf("OOB update warning: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config: regTokenLabelsConfig("prod"),
				Check: checkStep(t, "labelDrift: labels restored after drift convergence",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.env", "prod"),
				),
			},
		},
	})
}

func Test_CM_CipherTrust_CMRegToken_labelsDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  labels = { env = "staging" }
}
`,
				Check: checkStep(t, "labelsDrift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.env", "staging"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"labels": map[string]interface{}{"env": "production"}})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_REG_TOKEN, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_CipherTrust_CMRegToken_namePrefixDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "orig-"
}
`,
				Check: checkStep(t, "namePrefixDrift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "name_prefix", "orig-"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// name_prefix is immutable: after an OOB change the plan modifier fires an
				// error when Terraform tries to reconcile config "orig-" against the refreshed
				// state "changed-".
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"name_prefix": "changed-"})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_REG_TOKEN, patchPayload, "id")
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMRegToken_ImmutableFields verifies that name_prefix and label
// cannot be changed after registration token creation.
func Test_CM_CipherTrust_CMRegToken_ImmutableFields(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create baseline with name_prefix and label both set
			{
				Config: cmRegTokenBaseConfig(),
			},
			// Scenario A: name_prefix immutability
			{
				Config:      cmRegTokenConfigPrefix("prefix-b"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
			// Scenario B: label immutability (name_prefix unchanged; only label differs)
			{
				Config:      cmRegTokenConfigLabel("profile2"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

func regTokenLabelsConfig(envValue string) string {
	return fmt.Sprintf(providerConfig+`
resource "ciphertrust_cm_reg_token" "test" {
  labels = {
    "env" = %q
  }
}
`, envValue)
}

func cmRegTokenBaseConfig() string {
	return providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "prefix-a"
  label = {
    KmipClientProfile = "profile1"
  }
}`
}

func cmRegTokenConfigPrefix(prefix string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  label = {
    KmipClientProfile = "profile1"
  }
}`, prefix)
}

func cmRegTokenConfigLabel(profile string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "prefix-a"
  label = {
    KmipClientProfile = %q
  }
}`, profile)
}

// Test_CM_CMRegToken_LifetimeNoDrift verifies Fix (a): lifetime is not nulled by Read() after
// Create or Update. CM never returns lifetime in GET responses (write-only field).
func Test_CM_CMRegToken_LifetimeNoDrift(t *testing.T) {
	RequireCM(t)

	configCreate := providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  lifetime    = "10h"
  max_clients = 5
}
`
	configUpdate := providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  lifetime    = "10h"
  max_clients = 10
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Apply (Create)
			{
				Config: configCreate,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "lifetime", "10h"),
				),
			},
			// Step 2: No-op Apply after Create — primary regression gate for Fix (a).
			// If Read() nulls lifetime, Terraform proposes + lifetime = "10h" and this step fails.
			{
				Config: configCreate,
				Check: checkStep(t, "noop-after-create",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "lifetime", "10h"),
				),
			},
			// Step 3: Apply (Update — change max_clients)
			{
				Config: configUpdate,
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "lifetime", "10h"),
				),
			},
			// Step 4: No-op Apply after Update — second regression gate.
			{
				Config: configUpdate,
				Check: checkStep(t, "noop-after-update",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "lifetime", "10h"),
				),
			},
		},
	})
}

// Test_CM_CMRegToken_LabelsNoDrift verifies Fix (b): labels does not produce {} → null drift
// when config omits the field and CM returns labels:{} after PATCH.
func Test_CM_CMRegToken_LabelsNoDrift(t *testing.T) {
	RequireCM(t)

	configCreate := providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  max_clients = 5
}
`
	configUpdate := providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  max_clients = 10
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Apply (Create) omitting labels
			{
				Config: configCreate,
				Check: checkStep(t, "create",
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels.%"),
				),
			},
			// Step 2: Apply (Update — triggers PATCH; CM returns labels:{} after PATCH)
			{
				Config: configUpdate,
				Check: checkStep(t, "update",
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels.%"),
				),
			},
			// Step 3: No-op Apply after Update — primary regression gate for Fix (b).
			// If !state.Labels.IsNull() guard is absent, Read() writes {} into state,
			// plan proposes - labels = {} -> null, and this step fails.
			{
				Config: configUpdate,
				Check: checkStep(t, "noop-after-update",
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels.%"),
				),
			},
		},
	})
}
