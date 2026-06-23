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

func TestAccCMKey_undeletableDrift(t *testing.T) {
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

func TestAccCMKey_xtsDrift(t *testing.T) {
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

func TestAccCMKey_aliasHydration(t *testing.T) {
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

func TestAccCMKey_metaHydration(t *testing.T) {
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

func TestAccCMKey_metaDrift(t *testing.T) {
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

func TestAccCMKey_labelsDrift(t *testing.T) {
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

func TestAccCMKey_aliasDrift(t *testing.T) {
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

// TestAccCMKey_aliasDeletion verifies that removing an alias from config causes the
// PATCH to emit a delta-delete entry ({"index": N}) and the alias is removed from the server.
func TestAccCMKey_aliasDeletion(t *testing.T) {
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

// TestAccCMKey_undeletableExplicitFalse verifies that setting undeletable=false (after true)
// actually sends the value to the API. Previously the boolean-false gate swallowed it.
func TestAccCMKey_undeletableExplicitFalse(t *testing.T) {
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

// TestAccCMKey_rotationFrequencyDays covers the full rotation_frequency_days lifecycle:
//  1. Create with a numeric rotation window → state stores that value.
//  2. Update to a different window → change reaches the server.
//  3. Drift: out-of-band PATCH changes the window → Read() detects the change.
//  4. Disable rotation by setting "0" → server stores ""; state preserves "0"
//     to avoid the perpetual diff caused by the API normalisation.
func TestAccCMKey_rotationFrequencyDays(t *testing.T) {
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

// TestAccCMKey_templateId verifies that a key can be created from a template.
// Set CIPHERTRUST_TEST_TEMPLATE_ID to the ID or name of an existing key template on the
// target CM / CDSPaaS instance before running. The test is skipped when the variable is unset.
//
// CDSPaaS restricted-user flow: on CDSPaaS, Restricted Key Users must supply a
// template_id and may only include owner_id in meta. To exercise that enforcement,
// also set CDSPAAS=true, CIPHERTRUST_TENANT, and use a restricted-user credential pair
// (CIPHERTRUST_USERNAME / CIPHERTRUST_PASSWORD). When run with admin credentials the
// test still validates that template_id propagates to the API and the key is created.
func TestAccCMKey_templateId(t *testing.T) {
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

// TestAccCMKey_import verifies that an existing key can be brought under Terraform
// management with `terraform import`. The test creates a key out-of-band via the CM
// client, then imports it into a Terraform config by ID, and finally confirms that
// a subsequent plan produces no diff (state matches server).
func TestAccCMKey_import(t *testing.T) {
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
				// Minimal config that matches what Read() will populate.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "imported" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
}
`, keyName),
				ImportStatePersist: true,
			},
			{
				// After import, plan must produce no diff.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_key" "imported" {
  name      = %q
  algorithm = "aes"
  key_size  = 256
}
`, keyName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestAccCMKey_labelsEmptyMapDrift verifies that a key created without labels does not
// develop perpetual drift when the server returns "labels": {} in the GET response.
// Previously, Read() turned {} into an empty map in state, which differed from
// the null value expected when no labels are configured.
func TestAccCMKey_labelsEmptyMapDrift(t *testing.T) {
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

func TestAccCMKey_readNotFound(t *testing.T) {
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

func TestResourceCMKey(t *testing.T) {
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

// TestCMKeyBasicCRUD creates an AES key, verifies it, then updates a mutable
// field (description) and verifies the update was applied.
func TestCMKeyBasicCRUD(t *testing.T) {
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

// TestCMKeyNameImmutable verifies that attempting to rename a key after creation
// produces a clear, actionable plan-time error rather than silent state drift
// (where Terraform state updates but CM retains the original name).
func TestCMKeyNameImmutable(t *testing.T) {
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

// TestCMKeyAlgorithmImmutable verifies that attempting to change the 'algorithm'
// field after creation produces a clear, actionable plan-time error.
func TestCMKeyAlgorithmImmutable(t *testing.T) {
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

// TestCMKeyKeySizeImmutable verifies that changing 'key_size' after creation
// produces a clear plan-time error.
func TestCMKeyKeySizeImmutable(t *testing.T) {
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

// TestCMKeyObjectTypeImmutable verifies that changing 'object_type' after
// creation produces a clear plan-time error.
func TestCMKeyObjectTypeImmutable(t *testing.T) {
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

// TestCMKeyCurveidImmutable verifies that changing 'curveid' after creation
// produces a clear plan-time error.
func TestCMKeyCurveidImmutable(t *testing.T) {
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

// TestCMKeyOutOfBandDeletion verifies that when a key is deleted directly on
// CipherTrust Manager (out-of-band), the next terraform plan/refresh removes it
// from state gracefully instead of returning a hard error.
func TestCMKeyOutOfBandDeletion(t *testing.T) {
	rName := "tf-key-" + acctest.RandStringFromCharSet(8, acctest.CharSetAlphaNum)

	client, ok := createCMClient()
	if !ok {
		t.Skip("Skipping out-of-band deletion test: CM client could not be created (check CIPHERTRUST_* env vars)")
	}

	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key normally. Capture its ID for use in Step 2.
			// The post-apply refresh here succeeds (key still exists on CM) so the
			// plan is empty and the step passes cleanly.
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
			// Step 2: Delete the key out-of-band in PreConfig, then RefreshState.
			// Read() detects the 404 and removes the resource from state, so the
			// plan shows +create (ExpectNonEmptyPlan: true).
			{
				PreConfig: func() {
					endpoint := common.URL_KEY_MANAGEMENT + "/" + capturedID
					if _, err := client.DeleteByURL(context.Background(), capturedID, endpoint); err != nil {
						t.Logf("out-of-band delete failed (key may already be gone): %s", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			// Step 3: Re-apply — Terraform recreates the key from scratch, proving
			// the resource can be recovered after an out-of-band deletion.
			{
				Config: aesKeyConfig(rName, 256),
				Check:  resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test_key", "id"),
			},
		},
	})
}

// TestCMKeyMaterialImmutable verifies that changing 'material' (key material)
// after creation produces a clear plan-time error.
func TestCMKeyMaterialImmutable(t *testing.T) {
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
