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
				ExpectNonEmptyPlan: false,
			},
			{
				Config: providerConfig + `
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = "test-"
}
`,
				Check: checkStep(t, "deleteOOB: state preserved",
					resource.TestCheckResourceAttrWith("ciphertrust_cm_reg_token.test", "id", func(val string) error {
						if val != capturedID {
							return fmt.Errorf("expected state to be preserved (same id), got new id %s", val)
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

// Test_CM_CMRegToken_ValidatorMaxClients verifies that max_clients = -1 is rejected at
// plan time by the int64validator.AtLeast(0) constraint — no CM instance needed.
func Test_CM_CMRegToken_ValidatorMaxClients(t *testing.T) {
	name := "tftest-regtoken-" + uuid.New().String()[:8]
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  max_clients = -1
}`, name),
				ExpectError: regexp.MustCompile(`at least 0`),
			},
		},
	})
}

// Test_CM_CMRegToken_ValidatorLifetimeInvalid verifies that an invalid lifetime format is
// rejected at plan time — no CM instance needed.
func Test_CM_CMRegToken_ValidatorLifetimeInvalid(t *testing.T) {
	name := "tftest-regtoken-" + uuid.New().String()[:8]
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "garbage_format"
}`, name),
				ExpectError: regexp.MustCompile(`positive integer`),
			},
		},
	})
}

// Test_CM_CMRegToken_ValidatorLifetimeValid verifies that a valid lifetime format ("30d")
// applies successfully against a live CM.
func Test_CM_CMRegToken_ValidatorLifetimeValid(t *testing.T) {
	RequireCM(t)
	name := "tftest-regtoken-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30d"
}`, name),
				Check: checkStep(t, "valid lifetime applies",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "lifetime", "30d"),
				),
			},
		},
	})
}

// Test_CM_CMRegToken_TokenSensitive verifies that after apply, the token attribute is
// populated in state (Computed hydration not broken by Sensitive: true addition).
func Test_CM_CMRegToken_TokenSensitive(t *testing.T) {
	RequireCM(t)
	name := "tftest-regtoken-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
}`, name),
				Check: checkStep(t, "token is populated after apply",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "token"),
				),
			},
		},
	})
}

// Test_CM_CMRegToken_ClientMgmtProfileIDOutOfBandDrift verifies that an out-of-band PATCH
// setting client_management_profile_id on a token (which has it null in state) is detected
// as drift by Read() on the next RefreshState.
func Test_CM_CMRegToken_ClientMgmtProfileIDOutOfBandDrift(t *testing.T) {
	RequireCM(t)
	name := "tftest-regtoken-" + uuid.New().String()[:8]
	// profileUUID is any UUID — CM accepts any value for this field without validation.
	profileUUID := uuid.New().String()

	var tokenID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
}`, name),
				Check: checkStep(t, "out-of-band drift: create without profile id",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					func(s *terraform.State) error {
						tokenID = s.RootModule().Resources["ciphertrust_cm_reg_token.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping out-of-band PATCH")
						return
					}
					payload, _ := json.Marshal(map[string]string{
						"client_management_profile_id": profileUUID,
					})
					_, err := client.UpdateData(context.Background(), tokenID, common.URL_REG_TOKEN, payload, "id")
					if err != nil {
						t.Logf("out-of-band PATCH failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CMRegToken_ClientMgmtProfileIDTFDrivenDrift verifies that after a TF-driven
// "clear" (removing client_management_profile_id from config) which CM silently no-ops,
// a subsequent RefreshState surfaces the drift (null in state vs UUID in CM).
//
// CM validates client_management_profile_id on CREATE (400 for non-existent profile) but
// not on PATCH. So this test sets the field via Update (step 2), then removes it (step 3),
// then verifies drift is detected on the next RefreshState (step 4).
func Test_CM_CMRegToken_ClientMgmtProfileIDTFDrivenDrift(t *testing.T) {
	RequireCM(t)
	name := "tftest-regtoken-" + uuid.New().String()[:8]
	// profileUUID is any UUID — CM accepts any value in PATCH without existence validation.
	profileUUID := uuid.New().String()

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: create without client_management_profile_id (CM validates on POST).
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
}`, name),
				Check: checkStep(t, "TF-driven drift: create without profile id",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_reg_token.test", "id"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "client_management_profile_id"),
				),
			},
			{
				// Step 2: Update to set client_management_profile_id via PATCH (no existence validation).
				// CM stores the UUID; state is updated to match.
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix                  = %q
  client_management_profile_id = %q
}`, name, profileUUID),
				Check: checkStep(t, "TF-driven drift: update with profile id",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "client_management_profile_id", profileUUID),
				),
			},
			{
				// Step 3: remove client_management_profile_id from config and apply.
				// TF state drops the field to null; Update() sends "" to CM but CM retains the UUID.
				// After apply, the framework's internal post-apply refresh reads CM (still has UUID)
				// and detects drift (null → UUID), so ExpectNonEmptyPlan: true is required.
				Config: fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
}`, name),
				ExpectNonEmptyPlan: true,
			},
		},
	})
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
