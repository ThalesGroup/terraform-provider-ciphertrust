package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// aesKeyConfig returns a minimal ciphertrust_cm_key config for an AES key.
func aesKeyConfig(name string, keySize int) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "aes"
  key_size  = %d
}
`, name, keySize)
}

func Test_CM_AccCMKey_undeletableDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-undel-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  unexportable = false
}
`, keyName),
				Check: checkStep(t, "undeletable drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "unexportable", "false"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"unexportable": true})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_AccCMKey_xtsDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-xts-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  xts       = false
}
`, keyName),
				Check: checkStep(t, "xts drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "xts", "false"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{"xts": true})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_AccCMKey_aliasHydration(t *testing.T) {
	RequireCM(t)

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-alias-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  aliases   = [
    {
      alias = "test-alias"
      type  = "string"
    }
  ]
}
`, keyName),
				Check: checkStep(t, "alias hydration: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.0.alias", "test-alias"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "aliases.0.index"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
				Check: checkStep(t, "alias hydration: no drift after refresh",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.0.alias", "test-alias"),
				),
			},
		},
	})
	_ = capturedID
}

// Test_CM_AccCMKey_aliasAddition verifies that adding a new alias to an already-existing
// key via Update() succeeds — regression test for the "Provider produced inconsistent
// result after apply" crash caused by the per-item `index` field's positional
// UseStateForUnknown() incorrectly resolving to null for a genuinely new list element.
func Test_CM_AccCMKey_aliasAddition(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-aliasadd-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  aliases = [
    { alias = "alias-first", type = "string" },
  ]
}
`, keyName),
				Check: checkStep(t, "alias addition: initial create",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.0.alias", "alias-first"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "aliases.0.index"),
				),
			},
			{
				// Add a second alias to the already-existing key — must not crash with
				// "Provider produced inconsistent result after apply".
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  aliases = [
    { alias = "alias-first", type = "string" },
    { alias = "alias-second", type = "string" },
  ]
}
`, keyName),
				Check: checkStep(t, "alias addition: second alias added in place",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.#", "2"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "aliases.1.index"),
				),
			},
		},
	})
}

func Test_CM_AccCMKey_metaHydration(t *testing.T) {
	RequireCM(t)

	ownerID := os.Getenv("TEST_CM_KEY_OWNER_ID")
	if ownerID == "" {
		t.Skip("TEST_CM_KEY_OWNER_ID not set")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-meta-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  meta = {
    owner_id = %q
  }
}
`, keyName, ownerID),
				Check: checkStep(t, "meta hydration: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "meta.owner_id", ownerID),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
				Check: checkStep(t, "meta hydration: no drift after refresh",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "meta.owner_id", ownerID),
				),
			},
		},
	})
	_ = capturedID
}

func Test_CM_AccCMKey_metaDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	ownerIDA := os.Getenv("TEST_CM_KEY_OWNER_ID_A")
	ownerIDB := os.Getenv("TEST_CM_KEY_OWNER_ID_B")
	if ownerIDA == "" || ownerIDB == "" {
		t.Skip("TEST_CM_KEY_OWNER_ID_A or TEST_CM_KEY_OWNER_ID_B not set")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-metadrift-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  meta = {
    owner_id = %q
  }
}
`, keyName, ownerIDA),
				Check: checkStep(t, "meta drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "meta.owner_id", ownerIDA),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{
						"meta": map[string]interface{}{
							"owner_id": ownerIDB,
						},
					})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_AccCMKey_labelsDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-labels-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  labels    = { "env" = "test" }
}
`, keyName),
				Check: checkStep(t, "labels drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "labels.env", "test"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{
						"labels": map[string]interface{}{"env": "prod"},
					})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_AccCMKey_aliasDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-aldrift-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  aliases   = [
    {
      alias = "alias-a"
      type  = "string"
    }
  ]
}
`, keyName),
				Check: checkStep(t, "alias drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.0.alias", "alias-a"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					patchPayload, _ := json.Marshal(map[string]interface{}{
						"aliases": []map[string]interface{}{
							{"alias": "alias-a", "type": "string"},
							{"alias": "alias-b", "type": "string"},
						},
					})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, patchPayload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AccCMKey_aliasDeletion verifies that removing an alias from config
// causes the PATCH to emit a delta-delete entry ({"index": N}) and the alias
// is removed from the server.
func Test_CM_AccCMKey_aliasDeletion(t *testing.T) {
	RequireCM(t)

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-aliasdel-" + suffix

	twoAliasConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  aliases = [
    { alias = "alias-keep", type = "string" },
    { alias = "alias-drop", type = "string" },
  ]
}
`, keyName)

	oneAliasConfig := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  aliases = [
    { alias = "alias-keep", type = "string" },
  ]
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: twoAliasConfig,
				Check: checkStep(t, "alias deletion: create with two aliases",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.#", "2"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.0.alias", "alias-keep"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.1.alias", "alias-drop"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "aliases.0.index"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "aliases.1.index"),
				),
			},
			{
				// Remove alias-drop from config; PATCH must emit delete entry for its index.
				Config: oneAliasConfig,
				Check: checkStep(t, "alias deletion: after removing alias-drop",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "aliases.0.alias", "alias-keep"),
				),
			},
			{
				// Refresh confirms server has only one alias (no ghost alias-drop).
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMKey_undeletableExplicitFalse verifies that setting
// undeletable=false (after true) actually sends the value to the API.
// Previously the boolean-false gate swallowed it.
func Test_CM_AccCMKey_undeletableExplicitFalse(t *testing.T) {
	RequireCM(t)

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-undelfale-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name         = %q
  algorithm    = "aes"
  key_size     = 256
  undeletable  = true
}
`, keyName),
				Check: checkStep(t, "undeletable false: create with undeletable=true",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "undeletable", "true"),
				),
			},
			{
				// Change undeletable to false. The PATCH must explicitly send
				// {"undeletable": false} — the previous bug would have omitted it.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name                    = %q
  algorithm               = "aes"
  key_size                = 256
  undeletable             = false
  remove_from_state_on_destroy = true
}
`, keyName),
				Check: checkStep(t, "undeletable false: after setting undeletable=false",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "undeletable", "false"),
				),
			},
			{
				// Refresh: server should reflect undeletable=false now.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMKey_rotationFrequencyDays covers the rotation_frequency_days
// lifecycle: create, update, out-of-band drift detection, and disabling via
// "0" (which the server normalises to "" but state must preserve as "0").
func Test_CM_AccCMKey_rotationFrequencyDays(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-rotfreq-" + suffix

	var capturedID string

	cfgWith := func(days string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name                   = %q
  algorithm              = "aes"
  key_size               = 256
  rotation_frequency_days = %q
}
`, keyName, days)
	}

	cfgDisabled := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name                   = %q
  algorithm              = "aes"
  key_size               = 256
  rotation_frequency_days = "0"
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create with rotation = 30 days
			{
				Config: cfgWith("30"),
				Check: checkStep(t, "rotfreq: create with 30",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "rotation_frequency_days", "30"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: update to 7 days — Terraform must PATCH the server
			{
				Config: cfgWith("7"),
				Check: checkStep(t, "rotfreq: update to 7",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "rotation_frequency_days", "7"),
				),
			},
			// Step 3: out-of-band drift — change to 90 days directly on server
			{
				PreConfig: func() {
					payload, _ := json.Marshal(map[string]interface{}{"rotationFrequencyDays": "90"})
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, payload, "id")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true, // Read() detects the 90 vs 7 discrepancy
			},
			// Step 4: re-apply desired state (7)
			{
				Config: cfgWith("7"),
				Check: checkStep(t, "rotfreq: restored to 7",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "rotation_frequency_days", "7"),
				),
			},
			// Step 5: disable rotation by setting "0"
			// The server converts "0" → "" internally. State must preserve "0" to avoid
			// perpetual diff on subsequent refreshes.
			{
				Config: cfgDisabled,
				Check: checkStep(t, "rotfreq: disabled (0)",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "rotation_frequency_days", "0"),
				),
			},
			// Step 6: refresh — state must remain stable (no diff between "0" in config and "" on server)
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMKey_templateId verifies that a key can be created from a
// template. Set CIPHERTRUST_TEST_TEMPLATE_ID to an existing key template's
// ID/name; the test is skipped when unset.
func Test_CM_AccCMKey_templateId(t *testing.T) {
	RequireCM(t)

	templateID := os.Getenv("CIPHERTRUST_TEST_TEMPLATE_ID")
	if templateID == "" {
		t.Skip("CIPHERTRUST_TEST_TEMPLATE_ID not set; skipping template_id test")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-tmpl-" + suffix

	// CDSPaaS restricted-user flow: only owner_id may be supplied in meta alongside template_id.
	// On plain CM this is still valid; extra meta fields are just merged normally.
	ownerSelf := os.Getenv("CIPHERTRUST_USERNAME")
	if ownerSelf == "" {
		ownerSelf = "admin"
	}

	// We don't know which fields the template will populate, so we only assert
	// that the key was created (has an id). Checking algorithm/size would require
	// knowing the template contents, which differ across environments.
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name        = %q
  template_id = %q
  assign_self_as_owner = true
}
`, keyName, templateID),
				Check: checkStep(t, "templateId: key created from template",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "name", keyName),
				),
			},
			// Confirm stable state — no drift introduced by the template-driven creation.
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMKey_import verifies that an existing key can be brought under
// Terraform management with `terraform import`, and that a subsequent plan
// produces no diff (state matches server).
func Test_CM_AccCMKey_import(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-import-" + suffix

	// Create the key directly (not via Terraform) so we can import it.
	var importedID string
	createPayload, _ := json.Marshal(map[string]interface{}{
		"name":      keyName,
		"algorithm": "aes",
		"size":      256,
	})
	rawID, createErr := client.PostDataV2(context.Background(), uuid.New().String(), common.URL_KEY_MANAGEMENT, createPayload)
	if createErr != nil {
		t.Skipf("could not create key for import test: %v", createErr)
	}
	importedID = gjson.Get(rawID, "id").String()
	if importedID == "" {
		t.Skip("could not parse key id from create response")
	}
	t.Cleanup(func() {
		url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_KEY_MANAGEMENT, importedID)
		_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), url)
	})

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Import the key created out-of-band.
				ResourceName:  "ciphertrust_cm_key.imported",
				ImportState:   true,
				ImportStateId: importedID,
				// Minimal config: algorithm and key_size are Optional fields with
				// !state.IsNull() guards in Read(), so they are not hydrated on import
				// (state starts null after ImportState). Only name is unconditionally
				// hydrated and must match the config to avoid a post-import plan diff.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "imported" {
  name = %q
}
`, keyName),
				ImportStatePersist: true,
			},
			{
				// After import, plan must produce no diff.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "imported" {
  name = %q
}
`, keyName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMKey_labelsEmptyMapDrift verifies that a key created without
// labels does not develop perpetual drift when the server returns "labels":
// {} in the GET response (previously read as a non-null empty map).
func Test_CM_AccCMKey_labelsEmptyMapDrift(t *testing.T) {
	RequireCM(t)

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-lbldrift-" + suffix

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "labels empty-map: create without labels",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.k", "labels"),
				),
			},
			// Refresh: server may return "labels":{} — Read() must NOT turn that into
			// a non-null empty map in state (which would cause a perpetual diff).
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func Test_CM_AccCMKey_readNotFound(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed")
	}

	suffix := uuid.New().String()[:8]
	keyName := "tf-acc-key-notfound-" + suffix

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
}
`, keyName),
				Check: checkStep(t, "read not found: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.k"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					_, _ = client.DeleteByURL(context.Background(), uuid.New().String(), common.URL_KEY_MANAGEMENT+"/"+capturedID)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_ResourceCMKey(t *testing.T) {
	suffix := uuid.New().String()[:8]
	keyName := "terraform-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "cte_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  usage_mask  = 76
  undeletable = false
  unexportable = false
}
`, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.cte_key", "id"),
				),
			},
			// Update and Read testing — same name (immutable), only patch usage_mask + description
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "cte_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  usage_mask  = 13
  undeletable = false
  unexportable = false
  description = "updated via terraform"
}
`, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.cte_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.cte_key", "description", "updated via terraform"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// Test_CM_CMKeyBasicCRUD creates an AES key, verifies it, then updates a mutable
// field (description) and verifies the update was applied.
func Test_CM_CMKeyBasicCRUD(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: aesKeyConfig(rName, 256),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "name", rName),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "algorithm", "aes"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "key_size", "256"),
				),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  description = "updated"
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "description", "updated"),
				),
			},
		},
	})
}

// Test_CM_CMKeyNameImmutable verifies that attempting to rename a key after creation
// produces a clear, actionable plan-time error rather than silent state drift
// (where Terraform state updates but CM retains the original name).
func Test_CM_CMKeyNameImmutable(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config:      aesKeyConfig(rName+"-renamed", 256),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// Test_CM_CMKeyAlgorithmImmutable verifies that attempting to change the 'algorithm'
// field after creation produces a clear, actionable plan-time error.
func Test_CM_CMKeyAlgorithmImmutable(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: create.
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			// Step 2: attempt to change algorithm — must fail at plan time.
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "rsa"
  key_size  = 2048
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// Test_CM_CMKeyKeySizeImmutable verifies that changing 'key_size' after creation
// produces a clear plan-time error.
func Test_CM_CMKeyKeySizeImmutable(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "aes"
  key_size  = 128
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// Test_CM_CMKeyObjectTypeImmutable verifies that changing 'object_type' after
// creation produces a clear plan-time error.
func Test_CM_CMKeyObjectTypeImmutable(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  object_type = "Symmetric Key"
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  object_type = "Secret Data"
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// Test_CM_CMKeyCurveidImmutable verifies that changing 'curveid' after creation
// produces a clear plan-time error.
func Test_CM_CMKeyCurveidImmutable(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "ec"
  curveid   = "prime256v1"
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "ec"
  curveid   = "secp384r1"
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// Test_CM_CMKeyOutOfBandDeletion verifies that when a key is deleted directly on
// CipherTrust Manager (out-of-band), the next terraform refresh surfaces a hard
// error diagnostic (state preserved) so the operator is clearly informed of the
// drift. The operator must run 'terraform state rm' to clean up.
func Test_CM_CMKeyOutOfBandDeletion(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	client, ok := createCMClient()
	if !ok {
		t.Skip("Skipping out-of-band deletion test: CM client could not be created (check CIPHERTRUST_* env vars)")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key normally; capture its ID for the OOB delete.
			{
				Config: aesKeyConfig(rName, 256),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.test_key"].Primary.ID
						return nil
					},
				),
			},
			// Step 2: Delete the key out-of-band, then refresh.
			// Read() detects the 404 and returns an error (state preserved).
			{
				PreConfig: func() {
					endpoint := common.URL_KEY_MANAGEMENT + "/" + capturedID
					if _, err := client.DeleteByURL(context.Background(), capturedID, endpoint); err != nil {
						t.Logf("out-of-band delete failed (key may already be gone): %s", err)
					}
				},
				RefreshState: true,
				ExpectError:  regexp.MustCompile(`CM Key Not Found`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableBool_xts verifies that changing xts after creation
// produces a plan-time "Attribute is immutable" error from modifiers.ImmutableBool().
func Test_CM_CipherTrust_CMKey_ImmutableBool_xts(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  xts       = false
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  xts       = true
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableObject_wrapPbe verifies that changing wrap_pbe after
// creation produces a plan-time "Attribute is immutable" error from modifiers.ImmutableObject().
func Test_CM_CipherTrust_CMKey_ImmutableObject_wrapPbe(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  wrap_pbe = {
    hash_algorithm = "hmac-sha256"
    iteration      = 1000
    dklen          = 32
    password       = "changeme123"
    salt           = "aabbccddeeff00112233445566778899"
  }
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  wrap_pbe = {
    hash_algorithm = "hmac-sha512"
    iteration      = 1000
    dklen          = 32
    password       = "changeme123"
    salt           = "aabbccddeeff00112233445566778899"
  }
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableInt64_keySize validates the ImmutableInt64 contract
// via modifiers.ImmutableInt64() on key_size.
func Test_CM_CipherTrust_CMKey_ImmutableInt64_keySize(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config:      aesKeyConfig(rName, 128),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_MutableFieldsUnaffected confirms that mutable fields
// (description, rotation_frequency_days, usage_mask) produce no immutable-field error.
func Test_CM_CipherTrust_CMKey_MutableFieldsUnaffected(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name                    = %q
  algorithm               = "aes"
  key_size                = 256
  description             = "v1"
  rotation_frequency_days = "30"
  usage_mask              = 4
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.k", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "k" {
  name                    = %q
  algorithm               = "aes"
  key_size                = 256
  description             = "v2"
  rotation_frequency_days = "60"
  usage_mask              = 12
}
`, rName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "description", "v2"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "rotation_frequency_days", "60"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.k", "usage_mask", "12"),
				),
			},
		},
	})
}

// TestCMKeyMaterialImmutable verifies that changing 'material' (key material)
// Test_CM_CMKeyMaterialImmutable verifies that changing 'material' (key material)
// after creation produces a clear plan-time error.
func Test_CM_CMKeyMaterialImmutable(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  material  = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  material  = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`cannot be changed`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableAlgorithm verifies that changing algorithm after
// creation produces a plan-time "Attribute is immutable" error.
func Test_CM_CipherTrust_CMKey_ImmutableAlgorithm(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "rsa"
  key_size  = 2048
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableKeySize verifies that changing key_size after
// creation produces a plan-time "Attribute is immutable" error.
func Test_CM_CipherTrust_CMKey_ImmutableKeySize(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config:      aesKeyConfig(rName, 128),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableName verifies that changing name after creation
// produces a plan-time "Attribute is immutable" error containing both current and
// proposed values.
func Test_CM_CipherTrust_CMKey_ImmutableName(t *testing.T) {
	RequireCM(t)
	rName := "test-key-immutable-name-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				// Use an inline config with the same resource label (test_key) and a fixed new
				// name so the framework clearly sees a modification to the existing resource,
				// not a new resource at a different address.
				Config: providerConfig + `
resource "ciphertrust_cm_key" "test_key" {
  name      = "test-key-renamed"
  algorithm = "aes"
  key_size  = 256
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableCurveid verifies that changing curveid after
// creation produces a plan-time "Attribute is immutable" error.
func Test_CM_CipherTrust_CMKey_ImmutableCurveid(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "ec"
  curveid   = "prime256v1"
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name      = %q
  algorithm = "ec"
  curveid   = "secp384r1"
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_ImmutableObjectType verifies that changing object_type after
// creation produces a plan-time "Attribute is immutable" error.
func Test_CM_CipherTrust_CMKey_ImmutableObjectType(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  object_type = "Symmetric Key"
}
`, rName),
				Check: resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  object_type = "Opaque Object"
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)Attribute is immutable`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_MutableFieldsUpdate confirms that changing mutable fields
// (description) does not produce an immutable error and terraform apply succeeds.
func Test_CM_CipherTrust_CMKey_MutableFieldsUpdate(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  description = "initial"
}
`, rName),
				Check: resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "description", "initial"),
			},
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test_key" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  description = "updated"
}
`, rName),
				Check: resource.TestCheckResourceAttr("ciphertrust_cm_key.test_key", "description", "updated"),
			},
		},
	})
}

// Test_CM_CMKey_UsageMaskUpperBound validates the Between(0, 4194303) validator on usage_mask.
// All steps are PlanOnly — no Apply is issued.
func Test_CM_CMKey_UsageMaskUpperBound(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// usage_mask = 4194304 is one above the documented max — must be rejected at plan time.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name       = %q
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 4194304
}
`, rName),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)4,?194,?303|must be between`),
			},
			{
				// usage_mask = 0 is the lower boundary — validator must accept it (no error).
				// Plan shows a create (no prior state from Step 1 error); ExpectNonEmptyPlan:true.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name       = %q
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 0
}
`, rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				// usage_mask = 4194303 is the upper boundary — validator must accept it (no error).
				// Plan shows a create (no prior state); ExpectNonEmptyPlan:true.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name       = %q
  algorithm  = "aes"
  key_size   = 256
  usage_mask = 4194303
}
`, rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CMKey_AlgorithmKnownAfterApply verifies that algorithm and key_size are concrete
// known values in state after apply, not "known after apply".
func Test_CM_CMKey_AlgorithmKnownAfterApply(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  object_type = "Symmetric Key"
}
`, rName)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					// algorithm may be stored lowercase ("aes") after Read() normalization.
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "algorithm"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "key_size", "256"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "object_type"),
				),
			},
			{
				// Second plan must be empty — no (known after apply) regression.
				Config:             cfg,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CMKey_EmptyMaterialHydration verifies that empty_material = true is preserved
// in state after apply and that a second plan produces no diff.
func Test_CM_CMKey_EmptyMaterialHydration(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name           = %q
  algorithm      = "aes"
  key_size       = 256
  empty_material = true
}
`, rName)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "empty_material", "true"),
				),
			},
			{
				// Second plan must be empty — empty_material preserved from prior state.
				Config:             cfg,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CMKey_MetaOwnerIdConvergence verifies meta.owner_id lifecycle and documents
// the known CM PATCH-merge limitation.
//
// DEVIATION: CM PATCH-merge retains meta.ownerId server-side after
// a PATCH with meta omitted. Read() hydrates meta.ownerId unconditionally when the server
// returns it, creating a permanent diff between nil-config and non-nil-state.
// Step 2 is PlanOnly + ExpectNonEmptyPlan:true to document this limitation without applying.
func Test_CM_CMKey_MetaOwnerIdConvergence(t *testing.T) {
	RequireCM(t)
	ownerID := os.Getenv("TF_ACC_CM_KEY_OWNER_USER_ID")
	if ownerID == "" {
		t.Skip("TF_ACC_CM_KEY_OWNER_USER_ID not set")
	}
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
  meta {
    owner_id = %q
  }
}
`, rName, ownerID),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "meta.0.owner_id", ownerID),
				),
			},
			{
				// DEVIATION: CM PATCH-merge prevents meta convergence.
				// After clearing meta from config, server still returns meta.ownerId so Read()
				// produces a diff. Document as known limitation: PlanOnly+ExpectNonEmptyPlan:true.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
}
`, rName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CMKey_Idempotency verifies that a second plan after apply produces no diff.
// Asserts key Computed fields (id, uuid) and Optional+Computed fields (usage_mask) are stable.
func Test_CM_CMKey_Idempotency(t *testing.T) {
	RequireCM(t)
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name         = %q
  algorithm    = "aes"
  key_size     = 256
  usage_mask   = 76
  undeletable  = false
  unexportable = false
}
`, rName)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "usage_mask", "76"),
					// state and object_type are Optional fields guarded by !state.X.IsNull() in Read().
					// They are not hydrated when absent from config, so no assertion here.
					// uuid is also Optional with the same guard — not in config, not asserted.
				),
			},
			{
				// Second plan must be empty — all computed fields stable after create.
				Config:             cfg,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CMKey_DescriptionDrift verifies that an out-of-band description change is
// detected as drift (RefreshState: true, ExpectNonEmptyPlan: true).
func Test_CM_CMKey_DescriptionDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed — CM not configured")
	}

	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name        = %q
  algorithm   = "aes"
  key_size    = 256
  description = "original"
}
`, rName),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "description", "original"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Modify description out-of-band then refresh — drift must be detected.
				PreConfig: func() {
					payload := []byte(`{"description":"changed-out-of-band"}`)
					// UpdateDataV2 builds URL as <baseURL>/<endpoint>/<capturedID> internally.
					if _, err := client.UpdateDataV2(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, payload); err != nil {
						t.Fatalf("OOB description update failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func Test_CM_CipherTrust_CMKey_AlgorithmDriftCorrection(t *testing.T) {
	RequireCM(t)
	var capturedID string
	keyName := "tftest-algo-drift-" + acctest.RandString(8)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name      = %q
  algorithm = "rsa"
  key_size  = 2048
}
`, keyName),
				Check: checkStep(t, "create RSA key",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "algorithm", "rsa"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.test"].Primary.ID
						return nil
					},
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM not configured — skipping OOB step")
						return
					}
					ctx := context.Background()
					payload, _ := json.Marshal(map[string]interface{}{"description": "drift-test"})
					client.UpdateData(ctx, capturedID, common.URL_KEY_MANAGEMENT, payload, "updatedAt")
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
				Check: checkStep(t, "algorithm casing preserved after refresh",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "algorithm", "rsa"),
				),
			},
		},
	})
}

// TestAccCMKey_EmptyMaterialReadback verifies that empty_material = true is
// preserved in Terraform state after apply and that a second plan with identical
// config produces no spurious drift.
func Test_CM_AccCMKey_EmptyMaterialReadback(t *testing.T) {
	RequireCM(t)
	name := "tf-test-em-" + uuid.New().String()[:8]

	createCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name           = %q
  algorithm      = "aes"
  key_size       = 256
  empty_material = true
}`, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with empty_material = true; confirm Read() returns it.
			{
				Config: createCfg,
				Check: checkStep(t, "create+readback",
					resource.TestCheckResourceAttr(
						"ciphertrust_cm_key.test", "empty_material", "true"),
				),
			},
			// Step 2: Re-apply identical config; confirm no spurious drift.
			{
				Config: createCfg,
				Check: checkStep(t, "no-drift",
					resource.TestCheckResourceAttr(
						"ciphertrust_cm_key.test", "empty_material", "true"),
				),
			},
		},
	})
}

func Test_CM_CipherTrust_CMKey_AlgorithmNullTemplateKey(t *testing.T) {
	RequireCM(t)
	templateID := os.Getenv("CM_KEY_TEMPLATE_ID")
	if templateID == "" {
		t.Skip("CM_KEY_TEMPLATE_ID not set — skipping template key test")
	}
	keyName := "tftest-tmpl-algo-" + acctest.RandString(8)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name        = %q
  template_id = %q
}
`, keyName, templateID),
				Check: checkStep(t, "template key has no algorithm in state",
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.test", "algorithm"),
				),
			},
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
				Check: checkStep(t, "null algorithm preserved after refresh",
					resource.TestCheckNoResourceAttr("ciphertrust_cm_key.test", "algorithm"),
				),
			},
		},
	})
}

// TestCipherTrust_CMKey_MetaClearRejected verifies that attempting to remove meta from
// config after it was set produces a hard AddError diagnostic instead of a false success.
func Test_CM_CipherTrust_CMKey_MetaClearRejected(t *testing.T) {
	RequireCM(t)
	name := "tf-test-meta-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
  meta = {
    owner_id = "admin"
  }
}`, name),
				Check: checkStep(t, "meta set",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "meta.owner_id", "admin"),
				),
			},
			{
				// Remove meta entirely — must produce AddError, not succeed.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
}`, name),
				ExpectError: regexp.MustCompile(`(?i)cannot clear field`),
			},
		},
	})
}

// TestCipherTrust_CMKey_MetaSetAndStable verifies that a key created with meta.owner_id
// does not exhibit spurious drift when the identical config is re-applied.
func Test_CM_CipherTrust_CMKey_MetaSetAndStable(t *testing.T) {
	RequireCM(t)
	name := "tf-test-metastable-" + uuid.New().String()[:8]
	config := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
  meta = {
    owner_id = "admin"
  }
}`, name)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "meta set",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "meta.owner_id", "admin"),
				),
			},
			{
				// Re-apply identical config; no plan changes expected.
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_MetaOwnerIdUpdate verifies that changing meta.owner_id to a new
// non-null value after creation succeeds in place: CM's merge-PATCH replaces a present key's
// value fully (it only fails to converge when a key is omitted from the PATCH body entirely).
func Test_CM_CipherTrust_CMKey_MetaOwnerIdUpdate(t *testing.T) {
	RequireCM(t)
	name := "tf-test-metaupd-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
  meta = {
    owner_id = "admin"
  }
}`, name),
				Check: checkStep(t, "initial meta",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "meta.owner_id", "admin"),
				),
			},
			{
				// owner_id changes from one non-null value to another — must apply in place.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
  meta = {
    owner_id = "admin2"
  }
}`, name),
				Check: checkStep(t, "owner_id updated in place",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "meta.owner_id", "admin2"),
				),
			},
		},
	})
}

// TestCipherTrust_CMKey_MetaOwnerIdDrift verifies that out-of-band changes to meta.owner_id
// on the CM server are detected by terraform plan (surfaced as a non-empty plan after RefreshState).
func Test_CM_CipherTrust_CMKey_MetaOwnerIdDrift(t *testing.T) {
	RequireCM(t)
	client, ok := createCMClient()
	if !ok {
		t.Skip("createCMClient failed — CM not configured")
	}

	name := "tf-test-metadrift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
  meta = {
    owner_id = "admin"
  }
}`, name),
				Check: checkStep(t, "initial meta",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "meta.owner_id", "admin"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_cm_key.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change: update owner_id to "driftuser" via CM API directly.
				// PreConfig fires before Terraform refresh/plan.
				PreConfig: func() {
					if capturedID == "" {
						t.Logf("capturedID empty — skipping OOB patch")
						return
					}
					patchPayload, err := json.Marshal(map[string]interface{}{
						"meta": map[string]interface{}{"owner_id": "driftuser"},
					})
					if err != nil {
						t.Logf("OOB patch marshal failed: %v", err)
						return
					}
					if _, err := client.UpdateDataV2(context.Background(), capturedID, common.URL_KEY_MANAGEMENT, patchPayload); err != nil {
						t.Logf("OOB meta patch failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_DescriptionClearRejected verifies that removing description
// from config after it was set produces a hard AddError diagnostic instead of a false
// success — CM's PATCH endpoint would otherwise silently leave the live value unchanged
// while Terraform reported the clear as applied.
func Test_CM_CipherTrust_CMKey_DescriptionClearRejected(t *testing.T) {
	RequireCM(t)
	name := "tf-test-desc-clear-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm   = "aes"
  key_size    = 256
  name        = %q
  description = "initial desc"
}`, name),
				Check: checkStep(t, "description set",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "description", "initial desc"),
				),
			},
			{
				// Remove description entirely — must produce AddError, not succeed.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
}`, name),
				ExpectError: regexp.MustCompile(`(?i)cannot clear field`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_UsageMaskClearRejected verifies that removing usage_mask
// from config after it was set produces a hard AddError diagnostic instead of a false
// success.
func Test_CM_CipherTrust_CMKey_UsageMaskClearRejected(t *testing.T) {
	RequireCM(t)
	name := "tf-test-mask-clear-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm  = "aes"
  key_size   = 256
  name       = %q
  usage_mask = 12
}`, name),
				Check: checkStep(t, "usage_mask set",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "usage_mask", "12"),
				),
			},
			{
				// Remove usage_mask entirely — must produce AddError, not succeed.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
}`, name),
				ExpectError: regexp.MustCompile(`(?i)cannot clear field`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_RotationFrequencyDaysClearRejected verifies that removing
// rotation_frequency_days from config after it was set produces a hard AddError
// diagnostic instead of a false success.
func Test_CM_CipherTrust_CMKey_RotationFrequencyDaysClearRejected(t *testing.T) {
	RequireCM(t)
	name := "tf-test-rotation-clear-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm               = "aes"
  key_size                = 256
  name                    = %q
  rotation_frequency_days = "30"
}`, name),
				Check: checkStep(t, "rotation_frequency_days set",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "rotation_frequency_days", "30"),
				),
			},
			{
				// Remove rotation_frequency_days entirely — must produce AddError, not succeed.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
}`, name),
				ExpectError: regexp.MustCompile(`(?i)cannot clear field`),
			},
		},
	})
}

// Test_CM_CipherTrust_CMKey_LabelsClearRejected verifies that removing labels from
// config after it was set produces a hard AddError diagnostic instead of a false
// success.
func Test_CM_CipherTrust_CMKey_LabelsClearRejected(t *testing.T) {
	RequireCM(t)
	name := "tf-test-labels-clear-" + uuid.New().String()[:8]
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
  labels = {
    env = "test"
  }
}`, name),
				Check: checkStep(t, "labels set",
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "labels.env", "test"),
				),
			},
			{
				// Remove labels entirely — must produce AddError, not succeed.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  algorithm = "aes"
  key_size  = 256
  name      = %q
}`, name),
				ExpectError: regexp.MustCompile(`(?i)cannot clear field`),
			},
		},
	})
}
