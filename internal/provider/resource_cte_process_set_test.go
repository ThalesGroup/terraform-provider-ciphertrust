package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteProcessSetConfig renders a ciphertrust_cte_process_set. When secondProcess
// is true a second process entry is appended for the update step.
func cteProcessSetConfig(name, description string, secondProcess bool) string {
	processes := `
    {
      signature = ""
      directory = "/home/testUser"
      file      = "*"
    }`
	if secondProcess {
		processes += `,
    {
      signature = ""
      directory = "/tmp"
      file      = "*"
    }`
	}
	desc := ""
	if description != "" {
		desc = fmt.Sprintf("  description = %q\n", description)
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_process_set" "process_set" {
  name = %q
%s  processes = [%s
  ]
}
`, name, desc, processes)
}

func TestResourceCTEProcessSet(t *testing.T) {
	name := "tf-procset-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteProcessSetConfig(name, "Created via TF", false),
				Check: checkStep(t, "process_set: create",
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_cte_process_set.process_set", "uri"),
					resource.TestCheckResourceAttr("ciphertrust_cte_process_set.process_set", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_cte_process_set.process_set", "processes.#", "1"),
					resource.TestCheckResourceAttr("ciphertrust_cte_process_set.process_set", "processes.0.directory", "/home/testUser"),
				),
			},
			{
				Config:             cteProcessSetConfig(name, "Created via TF", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cteProcessSetConfig(name, "Updated via TF", true),
				Check: checkStep(t, "process_set: update",
					resource.TestCheckResourceAttr("ciphertrust_cte_process_set.process_set", "description", "Updated via TF"),
					resource.TestCheckResourceAttr("ciphertrust_cte_process_set.process_set", "processes.#", "2"),
				),
			},
			{
				Config:             cteProcessSetConfig(name, "Updated via TF", true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				ResourceName:      "ciphertrust_cte_process_set.process_set",
				ImportState:       true,
				ImportStateVerify: true,
			},
		},
	})
}

// TestResourceCTEProcessSet_nameImmutable verifies a name change is rejected.
func TestResourceCTEProcessSet_nameImmutable(t *testing.T) {
	name := "tf-procset-imm-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteProcessSetConfig(name, "Original", false),
				Check: checkStep(t, "process_set immutable: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_process_set.process_set", "name", name),
				),
			},
			{
				Config:      cteProcessSetConfig(name+"-renamed", "Original", false),
				ExpectError: regexp.MustCompile(`(?i)cannot change process set name|immutable`),
			},
		},
	})
}

// TestResourceCTEProcessSet_drift mutates the description out-of-band and asserts
// the next plan is non-empty.
func TestResourceCTEProcessSet_drift(t *testing.T) {
	name := "tf-procset-drift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteProcessSetConfig(name, "Drift original", false),
				Check: checkStep(t, "process_set drift: create",
					resource.TestCheckResourceAttr("ciphertrust_cte_process_set.process_set", "description", "Drift original"),
					cteCaptureID("ciphertrust_cte_process_set.process_set", &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_PROCESS_SET, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteProcessSetConfig(name, "Drift original", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
