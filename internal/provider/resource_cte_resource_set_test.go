package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteResourceSetConfig renders a ciphertrust_cte_resource_set. type is held
// constant ("Directory") across steps because it is immutable. A second resource
// entry is appended when secondResource is true so the update step can assert a
// list-length change.
func cteResourceSetConfig(name, description string, secondResource bool) string {
	resources := `
    {
      directory          = "/tmp"
      file               = "*"
      hdfs               = false
      include_subfolders = false
    }`
	if secondResource {
		resources += `,
    {
      directory          = "/home/testUser"
      file               = "*"
      hdfs               = false
      include_subfolders = false
    }`
	}
	desc := ""
	if description != "" {
		desc = fmt.Sprintf("  description = %q\n", description)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = %q
%s  type = "Directory"
  resources = [%s
  ]
}
`, name, desc, resources)
}

func TestCTEResourceSetResource(t *testing.T) {
	name := "tf-resset-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteResourceSetConfig(name, "Created via TF", false),
				Check: checkStep(t, "resource_set: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cte_resource_set.resource_set", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_resource_set.resource_set", "uri"),
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "type", "Directory"),
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "resources.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "resources.0.directory", "/tmp"),
				),
			},
			{
				Config:             cteResourceSetConfig(name, "Created via TF", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cteResourceSetConfig(name, "Updated via TF", true),
				Check: checkStep(t, "resource_set: update",
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "description", "Updated via TF"),
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "resources.#", "2"),
				),
			},
			{
				Config:             cteResourceSetConfig(name, "Updated via TF", true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				ResourceName:      "ciphertrust_cte_resource_set.resource_set",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestCTEResourceSetResource_nameImmutable verifies a name change is rejected.
func TestCTEResourceSetResource_nameImmutable(t *testing.T) {
	name := "tf-resset-imm-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteResourceSetConfig(name, "Original", false),
				Check: checkStep(t, "resource_set immutable: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "name", name),
				),
			},
			{
				Config:      cteResourceSetConfig(name+"-renamed", "Original", false),
				ExpectError: regexp.MustCompile(`(?i)cannot change resource set name|immutable`),
			},
		},
	})
}

// TestCTEResourceSetResource_drift mutates the description out-of-band and asserts
// the next plan is non-empty.
func TestCTEResourceSetResource_drift(t *testing.T) {
	name := "tf-resset-drift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteResourceSetConfig(name, "Drift original", false),
				Check: checkStep(t, "resource_set drift: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "description", "Drift original"),
					cteCaptureID("ciphertrust_cte_resource_set.resource_set", &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_RESOURCE_SET, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteResourceSetConfig(name, "Drift original", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestCTEResourceSetResource_readNotFoundErrors verifies TFIN-623: deleting
// the resource set out-of-band and refreshing must now fail loudly (hard
// error) via the shared handleReadNotFound() helper, rather than the
// previous AddWarning-only severity, while still keeping the resource in
// Terraform state (handleReadNotFound never removes it on a 404).
func TestCTEResourceSetResource_readNotFoundErrors(t *testing.T) {
	name := "tf-resset-404-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteResourceSetConfig(name, "", false),
				Check: checkStep(t, "resource_set 404: create",
					cteCaptureID("ciphertrust_cte_resource_set.resource_set", &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandDelete(common.URL_CTE_RESOURCE_SET, capturedID)
				},
				Config:      cteResourceSetConfig(name, "", false),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)CTE Resource Set .* not found`),
			},
		},
	})
}

// TestCTEResourceSetResource_labelsClearing verifies that removing labels from config
// actually clears them in CM and does not create a permanent plan loop (TFIN-506).
func TestCTEResourceSetResource_labelsClearing(t *testing.T) {
	name := "tf-resset-labels-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with labels
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = %q
  type = "Directory"
  labels = {
    env = "drift-test"
  }
  resources = [
    {
      directory          = "/tmp"
      file               = "*"
      hdfs               = false
      include_subfolders = false
    }
  ]
}
`, name),
				Check: checkStep(t, "resource_set labels: create with labels",
					resource.TestCheckResourceAttr("ciphertrust_cte_resource_set.resource_set", "labels.env", "drift-test"),
				),
			},
			// Remove labels from config
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = %q
  type = "Directory"
  resources = [
    {
      directory          = "/tmp"
      file               = "*"
      hdfs               = false
      include_subfolders = false
    }
  ]
}
`, name),
				Check: checkStep(t, "resource_set labels: remove labels",
					resource.TestCheckNoResourceAttr("ciphertrust_cte_resource_set.resource_set", "labels.env"),
				),
			},
			// Plan again should show no changes (fixes TFIN-506)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_resource_set" "resource_set" {
  name = %q
  type = "Directory"
  resources = [
    {
      directory          = "/tmp"
      file               = "*"
      hdfs               = false
      include_subfolders = false
    }
  ]
}
`, name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
