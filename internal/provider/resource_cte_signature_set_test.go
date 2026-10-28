package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteSignatureSetConfig renders a ciphertrust_cte_signature_set. type is held
// constant ("Application") because it is immutable. When secondSource is true a
// second source path is appended for the update step.
func cteSignatureSetConfig(name, description string, secondSource bool) string {
	sources := `"/usr/bin"`
	if secondSource {
		sources += `, "/usr/sbin"`
	}
	desc := ""
	if description != "" {
		desc = fmt.Sprintf("  description = %q\n", description)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "signature_set" {
  name = %q
%s  type = "Application"
  source_list = [%s]
}
`, name, desc, sources)
}

func TestCTESignatureSetResource(t *testing.T) {
	name := "tf-sigset-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSignatureSetConfig(name, "Created via TF", true),
				Check: checkStep(t, "signature_set: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cte_signature_set.signature_set", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_signature_set.signature_set", "uri"),
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "type", "Application"),
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "source_list.#", "2"),
				),
			},
			{
				Config:             cteSignatureSetConfig(name, "Created via TF", true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cteSignatureSetConfig(name, "Updated via TF", false),
				Check: checkStep(t, "signature_set: update",
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "description", "Updated via TF"),
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "source_list.#", "1"),
				),
			},
			{
				Config:             cteSignatureSetConfig(name, "Updated via TF", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				ResourceName:      "ciphertrust_cte_signature_set.signature_set",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestCTESignatureSetResource_nameImmutable verifies a name change is rejected.
func TestCTESignatureSetResource_nameImmutable(t *testing.T) {
	name := "tf-sigset-imm-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSignatureSetConfig(name, "Original", false),
				Check: checkStep(t, "signature_set immutable: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "name", name),
				),
			},
			{
				Config:      cteSignatureSetConfig(name+"-renamed", "Original", false),
				ExpectError: regexp.MustCompile(`(?i)cannot change signature set name|immutable`),
			},
		},
	})
}

// cteSignatureSetTypedConfig renders a signature set with an explicit type, used
// by the type-immutability test.
func cteSignatureSetTypedConfig(name, typ string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "signature_set" {
  name        = %q
  type        = %q
  source_list = ["/usr/bin"]
}
`, name, typ)
}

// TestCTESignatureSetResource_typeImmutable verifies the provider rejects a
// change to the (immutable) type field after creation.
func TestCTESignatureSetResource_typeImmutable(t *testing.T) {
	name := "tf-sigset-typeimm-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSignatureSetTypedConfig(name, "Application"),
				Check: checkStep(t, "signature_set type immutable: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "type", "Application"),
				),
			},
			{
				Config:      cteSignatureSetTypedConfig(name, "Container-Image"),
				ExpectError: regexp.MustCompile(`(?i)cannot change signature set type|immutable`),
			},
		},
	})
}

// TestCTESignatureSetResource_labels verifies that the labels attribute
// actually reaches CM: setting it, changing it, and clearing it each produce
// the expected state and no permanent plan loop (TFIN-589).
func TestCTESignatureSetResource_labels(t *testing.T) {
	name := "tf-sigset-labels-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_signature_set.signature_set"

	withLabel := func(name, value string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "signature_set" {
  name        = %q
  type        = "Application"
  source_list = ["/usr/bin"]
  labels = {
    env = %q
  }
}
`, name, value)
	}
	withoutLabels := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_signature_set" "signature_set" {
  name        = %q
  type        = "Application"
  source_list = ["/usr/bin"]
}
`, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with labels set
			{
				Config: withLabel(name, "test"),
				Check: checkStep(t, "signature_set labels: create",
					resource.TestCheckResourceAttr(rn, "labels.env", "test"),
				),
			},
			// Plan again should show no changes
			{
				Config:             withLabel(name, "test"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Change labels value
			{
				Config: withLabel(name, "changed"),
				Check: checkStep(t, "signature_set labels: update",
					resource.TestCheckResourceAttr(rn, "labels.env", "changed"),
				),
			},
			// Remove labels from config entirely
			{
				Config: withoutLabels,
				Check: checkStep(t, "signature_set labels: clear",
					resource.TestCheckResourceAttr(rn, "labels.%", "0"),
				),
			},
			// Plan again should show no changes (no clear-loop)
			{
				Config:             withoutLabels,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTESignatureSetResource_drift mutates the description out-of-band and
// asserts the next plan is non-empty (drift detection for the signature set).
func TestCTESignatureSetResource_drift(t *testing.T) {
	name := "tf-sigset-drift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteSignatureSetConfig(name, "Drift original", false),
				Check: checkStep(t, "signature_set drift: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_signature_set.signature_set", "description", "Drift original"),
					cteCaptureID("ciphertrust_cte_signature_set.signature_set", &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_SIGNATURE_SET, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteSignatureSetConfig(name, "Drift original", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
