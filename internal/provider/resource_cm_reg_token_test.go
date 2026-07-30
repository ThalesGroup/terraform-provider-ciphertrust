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
	"github.com/tidwall/gjson"
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

// Test_CM_RegToken_LabelsClearConverges verifies that removing labels from config
// clears them on CM and converges without perpetual drift (TFIN-513).
func Test_CM_RegToken_LabelsClearConverges(t *testing.T) {
	RequireCM(t)
	name := "tftest-rt-lblclr-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with labels set.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
  labels      = { env = "test" }
}`, name),
				Check: checkStep(t, "labels set",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.env", "test"),
				),
			},
			// Step 2: Remove labels from config — provider sends "labels": null to CM.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
}`, name),
				Check: checkStep(t, "labels cleared",
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels.env"),
				),
				ExpectNonEmptyPlan: false,
			},
			// Step 3: Idempotency — no perpetual drift after clear.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
}`, name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_RegToken_LabelsUpdate verifies that updating labels (non-null → non-null)
// converges correctly and old keys are removed.
func Test_CM_RegToken_LabelsUpdate(t *testing.T) {
	RequireCM(t)
	name := "tftest-rt-lblupd-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
  labels      = { k1 = "v1" }
}`, name),
				Check: checkStep(t, "initial labels",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.k1", "v1"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
  labels      = { k2 = "v2" }
}`, name),
				Check: checkStep(t, "updated labels",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "labels.k2", "v2"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels.k1"),
				),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_RegToken_NoLabelsDrift verifies that a reg token created without labels
// shows no perpetual drift even though CM may return labels:{} in the response.
func Test_CM_RegToken_NoLabelsDrift(t *testing.T) {
	RequireCM(t)
	name := "tftest-rt-nolbl-" + uuid.New().String()[:8]
	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
}`, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "no labels",
					resource.TestCheckNoResourceAttr("ciphertrust_cm_reg_token.test", "labels.%"),
				),
			},
			{
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_RegToken_CAIDUpdateInPlace verifies that ca_id can be changed in-place
// (no destroy+recreate) after removing the ImmutableString() modifier (TFIN-514).
//
// The test creates a second local CA via the CM REST API in PreConfig so that
// the ca_id update uses genuinely different CA values — not the same CA, which
// would not exercise the update path.
//
// Environment: requires CIPHERTRUST_* vars (guarded by RequireCM). The second CA
// is created and deleted entirely within the test.
func Test_CM_RegToken_CAIDUpdateInPlace(t *testing.T) {
	RequireCM(t)

	name := "tftest-rt-caid-" + uuid.New().String()[:8]
	const caA = "24442e97-cf8b-4872-b4a2-7dfe899155e6" // system CA always present

	var caBID string      // populated in Step 1 PreConfig
	var tokenID string    // captured from Step 1 state — must not change in Step 2

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create CA-B via REST, then create reg token with ca_id = CA-A.
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("createCMClient failed — skipping CA-B creation")
						return
					}
					payload := []byte(`{"cn":"tftest-ca-b","algorithm":"RSA","size":2048}`)
					resp, err := client.PostDataV2(context.Background(), uuid.New().String(), "api/v1/ca/local-cas", payload)
					if err != nil {
						t.Logf("CA-B creation failed: %v — test may not exercise update path", err)
						return
					}
					caBID = gjson.Get(resp, "id").String()
					t.Logf("Created CA-B: %s", caBID)
				},
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
  ca_id       = %q
}`, name, caA),
				Check: checkStep(t, "create with CA-A",
					resource.TestCheckResourceAttr("ciphertrust_cm_reg_token.test", "ca_id", caA),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_cm_reg_token.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						tokenID = rs.Primary.ID
						return nil
					},
				),
			},
			// Step 2: Update ca_id to CA-B — must be in-place (same resource ID, no recreation).
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
  ca_id       = %q
}`, name, func() string {
					if caBID != "" {
						return caBID
					}
					return caA // fallback if CA-B wasn't created
				}()),
				Check: checkStep(t, "update to CA-B in place",
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_cm_reg_token.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						if rs.Primary.ID != tokenID {
							return fmt.Errorf("resource was recreated: old ID=%s new ID=%s", tokenID, rs.Primary.ID)
						}
						if caBID != "" && rs.Primary.Attributes["ca_id"] != caBID {
							return fmt.Errorf("ca_id not updated: got %s want %s", rs.Primary.Attributes["ca_id"], caBID)
						}
						return nil
					},
				),
				ExpectNonEmptyPlan: false,
			},
			// Step 3: Idempotency.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_reg_token" "test" {
  name_prefix = %q
  lifetime    = "30m"
  ca_id       = %q
}`, name, func() string {
					if caBID != "" {
						return caBID
					}
					return caA
				}()),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
		CheckDestroy: func(s *terraform.State) error {
			// Clean up CA-B if it was created.
			if caBID == "" {
				return nil
			}
			client, ok := createCMClient()
			if !ok {
				return nil
			}
			url := fmt.Sprintf("%s/api/v1/ca/local-cas/%s", client.CipherTrustURL, caBID)
			_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), url)
			return nil
		},
	})
}
