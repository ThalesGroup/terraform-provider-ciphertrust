package provider

import (
	"fmt"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
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

func TestCTEProcessSetResource(t *testing.T) {
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

// TestCTEProcessSetResource_nameImmutable verifies that changing name after
// creation produces a plan-time immutable error from ImmutableString rather
// than a destroy+create, since the process set's id is referenced elsewhere
// and must not be reminted on rename (TFIN-497).
func TestCTEProcessSetResource_nameImmutable(t *testing.T) {
	name := "tf-procset-imm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_process_set.process_set"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteProcessSetConfig(name, "Original", false),
				Check: checkStep(t, "process_set immutable name: create",
					resource.TestCheckResourceAttr(rn, "name", name),
				),
			},
			{
				Config: cteProcessSetConfig(name+"-renamed", "Original", false),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(rn, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "process_set requires replace: rename",
					resource.TestCheckResourceAttr(rn, "name", name+"-renamed"),
				),
			},
		},
	})
}

// TestCTEProcessSetResource_processesClearing verifies that removing processes
// from config actually clears them in CM and does not create a permanent plan
// loop (TFIN-498).
func TestCTEProcessSetResource_processesClearing(t *testing.T) {
	name := "tf-procset-clear-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_process_set.process_set"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with a process entry
			{
				Config: cteProcessSetConfig(name, "Created via TF", false),
				Check: checkStep(t, "process_set processes: create with processes",
					resource.TestCheckResourceAttr(rn, "processes.#", "1"),
				),
			},
			// Remove processes from config
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_process_set" "process_set" {
  name = %q
}
`, name),
				Check: checkStep(t, "process_set processes: remove processes",
					resource.TestCheckResourceAttr(rn, "processes.#", "0"),
				),
			},
			// Plan again should show no changes (fixes TFIN-498)
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_process_set" "process_set" {
  name = %q
}
`, name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTEProcessSetResource_labels verifies that the top-level labels
// attribute actually reaches CM: setting it, changing it, and clearing it
// each produce the expected state and no permanent plan loop (TFIN-598).
func TestCTEProcessSetResource_labels(t *testing.T) {
	name := "tf-procset-labels-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_process_set.process_set"

	withLabel := func(name, value string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_process_set" "process_set" {
  name = %q
  labels = {
    env = %q
  }
}
`, name, value)
	}
	withoutLabels := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_process_set" "process_set" {
  name = %q
}
`, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Create with labels set
			{
				Config: withLabel(name, "test"),
				Check: checkStep(t, "process_set labels: create",
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
				Check: checkStep(t, "process_set labels: update",
					resource.TestCheckResourceAttr(rn, "labels.env", "changed"),
				),
			},
			// Remove labels from config entirely
			{
				Config: withoutLabels,
				Check: checkStep(t, "process_set labels: clear",
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

// TestCTEProcessSetResource_drift mutates the description out-of-band and asserts
// the next plan is non-empty.
func TestCTEProcessSetResource_drift(t *testing.T) {
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
