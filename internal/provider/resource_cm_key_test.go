package provider

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// TestResourceCMKey verifies basic create, read, update, and delete lifecycle.
func TestResourceCMKey(t *testing.T) {
	keyName := fmt.Sprintf("tf-test-key-%d", time.Now().Unix())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create an AES-256 key
			{
				Config: testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name         = "%s"
  algorithm    = "AES"
  key_size     = 256
  usage_mask   = 12
  description  = "Test key for acceptance tests"
  undeletable  = false
  unexportable = false
}
`, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "name", keyName),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "algorithm", "AES"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "description", "Test key for acceptance tests"),
				),
			},
			// Step 2: Update description and verify Read picks up the change
			{
				Config: testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "test" {
  name         = "%s"
  algorithm    = "AES"
  key_size     = 256
  usage_mask   = 12
  description  = "Updated description"
  undeletable  = false
  unexportable = false
}
`, keyName),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.test", "description", "Updated description"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadDriftDetection verifies that Read() detects out-of-band
// deletion of a key on CipherTrust Manager and triggers recreation.
func TestResourceCMKeyReadDriftDetection(t *testing.T) {
	keyName := fmt.Sprintf("tf-drift-key-%d", time.Now().Unix())
	var createdKeyID string

	// Helper to delete the key directly on CM (simulating out-of-band deletion)
	deleteKeyOutOfBand := func() {
		client := createTestClient(t)
		url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_KEY_MANAGEMENT, createdKeyID)
		_, err := client.DeleteByID(context.Background(), "DELETE", createdKeyID, url, nil)
		if err != nil {
			t.Fatalf("Failed to delete key out-of-band: %s", err)
		}
	}

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "drift_test" {
  name         = "%s"
  algorithm    = "AES"
  key_size     = 256
  usage_mask   = 12
  description  = "Drift detection test"
  undeletable  = false
  unexportable = false
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.drift_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift_test", "name", keyName),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift_test", "algorithm", "AES"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift_test", "description", "Drift detection test"),
					// Capture the ID for out-of-band deletion
					resource.TestCheckResourceAttrWith("ciphertrust_cm_key.drift_test", "id", func(value string) error {
						createdKeyID = value
						return nil
					}),
				),
			},
			// Step 2: Delete the key out-of-band, then re-apply same config.
			// Read() should detect 404 and remove from state, triggering recreation.
			{
				PreConfig: deleteKeyOutOfBand,
				Config:    config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.drift_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift_test", "name", keyName),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.drift_test", "description", "Drift detection test"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadAttributeDrift verifies that Read() detects out-of-band
// attribute modification on CipherTrust Manager and Terraform corrects the drift.
func TestResourceCMKeyReadAttributeDrift(t *testing.T) {
	keyName := fmt.Sprintf("tf-attr-drift-key-%d", time.Now().Unix())
	var createdKeyID string

	// Helper to modify the key description directly on CM
	modifyKeyOutOfBand := func() {
		client := createTestClient(t)
		payload := []byte(`{"description":"Modified outside Terraform"}`)
		_, err := client.UpdateData(context.Background(), createdKeyID, common.URL_KEY_MANAGEMENT, payload, "id")
		if err != nil {
			t.Fatalf("Failed to modify key out-of-band: %s", err)
		}
	}

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "attr_drift_test" {
  name         = "%s"
  algorithm    = "AES"
  key_size     = 256
  usage_mask   = 12
  description  = "Original description"
  undeletable  = false
  unexportable = false
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.attr_drift_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.attr_drift_test", "name", keyName),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.attr_drift_test", "description", "Original description"),
					// Capture the ID for out-of-band modification
					resource.TestCheckResourceAttrWith("ciphertrust_cm_key.attr_drift_test", "id", func(value string) error {
						createdKeyID = value
						return nil
					}),
				),
			},
			// Step 2: Modify description out-of-band, then re-apply same config.
			// Read() should detect the drift and Update() should correct it.
			{
				PreConfig: modifyKeyOutOfBand,
				Config:    config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.attr_drift_test", "name", keyName),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.attr_drift_test", "description", "Original description"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadLabelDrift verifies that Read() detects out-of-band
// label modification on CipherTrust Manager.
func TestResourceCMKeyReadLabelDrift(t *testing.T) {
	keyName := fmt.Sprintf("tf-label-drift-key-%d", time.Now().Unix())
	var createdKeyID string

	// Helper to modify labels directly on CM
	modifyLabelsOutOfBand := func() {
		client := createTestClient(t)
		payload := []byte(`{"labels":{"environment":"production","team":"devops"}}`)
		_, err := client.UpdateData(context.Background(), createdKeyID, common.URL_KEY_MANAGEMENT, payload, "id")
		if err != nil {
			t.Fatalf("Failed to modify key labels out-of-band: %s", err)
		}
	}

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "label_drift_test" {
  name         = "%s"
  algorithm    = "AES"
  key_size     = 256
  usage_mask   = 12
  description  = "Label drift test"
  undeletable  = false
  unexportable = false
  labels = {
    environment = "staging"
    team        = "security"
  }
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key with labels
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.label_drift_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.label_drift_test", "labels.environment", "staging"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.label_drift_test", "labels.team", "security"),
					// Capture the ID
					resource.TestCheckResourceAttrWith("ciphertrust_cm_key.label_drift_test", "id", func(value string) error {
						createdKeyID = value
						return nil
					}),
				),
			},
			// Step 2: Modify labels out-of-band, then re-apply same config.
			// Read() should detect the label drift and Update() should correct it.
			{
				PreConfig: modifyLabelsOutOfBand,
				Config:    config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.label_drift_test", "labels.environment", "staging"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.label_drift_test", "labels.team", "security"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadPlanStability verifies that consecutive plans produce
// no changes when no modifications have been made (no spurious drift).
func TestResourceCMKeyReadPlanStability(t *testing.T) {
	keyName := fmt.Sprintf("tf-stable-key-%d", time.Now().Unix())

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "stability_test" {
  name         = "%s"
  algorithm    = "AES"
  key_size     = 256
  usage_mask   = 12
  description  = "Stability test"
  undeletable  = false
  unexportable = false
  labels = {
    purpose = "testing"
  }
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.stability_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.stability_test", "name", keyName),
				),
			},
			// Step 2: Re-apply same config — should produce no changes
			{
				Config:             config,
				ExpectNonEmptyPlan: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.stability_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.stability_test", "name", keyName),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadMinimalConfig verifies that a minimal key config
// (only name, algorithm, key_size) produces no spurious drift.
func TestResourceCMKeyReadMinimalConfig(t *testing.T) {
	keyName := fmt.Sprintf("tf-minimal-key-%d", time.Now().Unix())

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "minimal_test" {
  name      = "%s"
  algorithm = "AES"
  key_size  = 128
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with minimal config
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.minimal_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.minimal_test", "name", keyName),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.minimal_test", "algorithm", "AES"),
				),
			},
			// Step 2: Re-apply — no drift should occur
			{
				Config:             config,
				ExpectNonEmptyPlan: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.minimal_test", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadRSA verifies Read() plan stability for RSA keys.
func TestResourceCMKeyReadRSA(t *testing.T) {
	keyName := fmt.Sprintf("tf-rsa-key-%d", time.Now().Unix())

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "rsa_test" {
  name         = "%s"
  algorithm    = "RSA"
  key_size     = 2048
  usage_mask   = 12
  description  = "RSA stability test"
  undeletable  = false
  unexportable = false
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create RSA key
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.rsa_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.rsa_test", "algorithm", "RSA"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.rsa_test", "description", "RSA stability test"),
				),
			},
			// Step 2: Re-apply — no drift should occur
			{
				Config:             config,
				ExpectNonEmptyPlan: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.rsa_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.rsa_test", "algorithm", "RSA"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadEC verifies Read() works for EC elliptic curve keys.
func TestResourceCMKeyReadEC(t *testing.T) {
	keyName := fmt.Sprintf("tf-ec-key-%d", time.Now().Unix())

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "ec_test" {
  name         = "%s"
  algorithm    = "EC"
  curveid      = "prime256v1"
  usage_mask   = 12
  description  = "EC key test"
  undeletable  = false
  unexportable = false
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create EC key
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.ec_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.ec_test", "algorithm", "EC"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.ec_test", "curveid", "prime256v1"),
				),
			},
			// Step 2: Re-apply — no drift should occur
			{
				Config:             config,
				ExpectNonEmptyPlan: false,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.ec_test", "id"),
				),
			},
			// Delete testing automatically occurs in TestCase
		},
	})
}

// TestResourceCMKeyReadUndeletableBooleanDrift verifies Read() detects OOB boolean flag changes.
func TestResourceCMKeyReadUndeletableBooleanDrift(t *testing.T) {
	keyName := fmt.Sprintf("tf-bool-drift-key-%d", time.Now().Unix())
	var createdKeyID string

	// Helper to change undeletable to false out-of-band
	modifyKeyOutOfBand := func() {
		client := createTestClient(t)
		payload := []byte(`{"undeletable":false}`)
		_, err := client.UpdateData(context.Background(), createdKeyID, common.URL_KEY_MANAGEMENT, payload, "id")
		if err != nil {
			t.Fatalf("Failed to modify key undeletable flag out-of-band: %s", err)
		}
	}

	config := testProviderConfig() + fmt.Sprintf(`
resource "ciphertrust_cm_key" "bool_drift_test" {
  name                         = "%s"
  algorithm                    = "AES"
  key_size                     = 256
  usage_mask                   = 12
  description                  = "Boolean drift test"
  undeletable                  = true
  unexportable                 = false
  remove_from_state_on_destroy = true
}
`, keyName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create the key with undeletable=true
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_key.bool_drift_test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_cm_key.bool_drift_test", "undeletable", "true"),
					resource.TestCheckResourceAttrWith("ciphertrust_cm_key.bool_drift_test", "id", func(value string) error {
						createdKeyID = value
						return nil
					}),
				),
			},
			// Step 2: Change undeletable to false OOB, re-apply to correct drift.
			// Read() detects undeletable=false from API, Update() sends undeletable=true.
			{
				PreConfig: modifyKeyOutOfBand,
				Config:    config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_key.bool_drift_test", "undeletable", "true"),
				),
			},
			// Delete testing: uses remove_from_state_on_destroy since key is undeletable
		},
	})
}

// createTestClient creates a CM API client for out-of-band operations in tests.
func createTestClient(t *testing.T) *common.Client {
	t.Helper()
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	if address == "" {
		address = "https://192.168.2.135"
		username = "admin"
		password = "ChangeIt01!"
	}
	domain := "root"
	client, err := common.NewClient(context.Background(), uuid.NewString(), &address, &domain, &domain, &username, &password, true, 180)
	if err != nil {
		t.Fatalf("Failed to create CM client: %s", err)
	}
	return client
}
