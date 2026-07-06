package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// cteCSIGroupFullConfig renders a csigroup with explicit namespace and storage
// class, used by the immutability tests.
func cteCSIGroupFullConfig(name, namespace, storageClass string, update bool) string {
	op := ""
	if update {
		op = "  op_type = \"update\"\n"
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = %q
  kubernetes_namespace     = %q
  kubernetes_storage_class = %q
%s  description = "csi immutable"
}
`, name, namespace, storageClass, op)
}

// cteCSIGroupConfig renders a ciphertrust_cte_csigroup. name, namespace and
// storage_class are immutable, so only description changes across steps (via the
// "update" op_type the provider requires for attribute edits).
func cteCSIGroupConfig(name, description string, update bool) string {
	op := ""
	if update {
		op = "  op_type = \"update\"\n"
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = %q
  kubernetes_namespace     = "default"
  kubernetes_storage_class = "standard"
%s  description = %q
}
`, name, op, description)
}

func TestCTECSIGroupResource(t *testing.T) {
	name := "tf-csi-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_csigroup.csigroup"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteCSIGroupConfig(name, "initial description", false),
				Check: checkStep(t, "csigroup: create",
					resource.TestCheckResourceAttrSet(rn, "id"),
					resource.TestCheckResourceAttr(rn, "name", name),
					resource.TestCheckResourceAttr(rn, "description", "initial description"),
				),
			},
			{
				Config: cteCSIGroupConfig(name, "updated description", true),
				Check: checkStep(t, "csigroup: update",
					resource.TestCheckResourceAttr(rn, "description", "updated description"),
				),
			},
			{
				ResourceName:     rn,
				ImportState:      true,
				ImportStateCheck: importStateCheckAttrsSet("id", "name"),
			},
		},
	})
}

// TestResourceCTECSIGroup_nameImmutable verifies a name change is rejected.
func TestResourceCTECSIGroup_nameImmutable(t *testing.T) {
	name := "tf-csi-imm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_csigroup.csigroup"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteCSIGroupConfig(name, "initial", false),
				Check: checkStep(t, "csigroup immutable: create",
					resource.TestCheckResourceAttr(rn, "name", name),
				),
			},
			{
				Config:      cteCSIGroupConfig(name+"-renamed", "initial", true),
				ExpectError: regexp.MustCompile(`(?i)cannot change csi group name|immutable`),
			},
		},
	})
}

// TestResourceCTECSIGroup_namespaceImmutable verifies a change to the (immutable)
// kubernetes_namespace is rejected.
func TestResourceCTECSIGroup_namespaceImmutable(t *testing.T) {
	name := "tf-csi-nsimm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_csigroup.csigroup"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteCSIGroupFullConfig(name, "default", "standard", false),
				Check: checkStep(t, "csigroup namespace immutable: create",
					resource.TestCheckResourceAttr(rn, "kubernetes_namespace", "default"),
				),
			},
			{
				Config:      cteCSIGroupFullConfig(name, "other-ns", "standard", true),
				ExpectError: regexp.MustCompile(`(?i)cannot change csi group namespace|immutable`),
			},
		},
	})
}

// TestResourceCTECSIGroup_storageClassImmutable verifies a change to the
// (immutable) kubernetes_storage_class is rejected.
func TestResourceCTECSIGroup_storageClassImmutable(t *testing.T) {
	name := "tf-csi-scimm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_csigroup.csigroup"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteCSIGroupFullConfig(name, "default", "standard", false),
				Check: checkStep(t, "csigroup storage_class immutable: create",
					resource.TestCheckResourceAttr(rn, "kubernetes_storage_class", "standard"),
				),
			},
			{
				Config:      cteCSIGroupFullConfig(name, "default", "fast", true),
				ExpectError: regexp.MustCompile(`(?i)cannot change csi group storage class|immutable`),
			},
		},
	})
}

// TestResourceCTECSIGroup_drift mutates the description out-of-band and asserts
// the next plan is non-empty.
func TestResourceCTECSIGroup_drift(t *testing.T) {
	name := "tf-csi-drift-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_csigroup.csigroup"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteCSIGroupConfig(name, "Drift original", false),
				Check: checkStep(t, "csigroup drift: create",
					resource.TestCheckResourceAttr(rn, "description", "Drift original"),
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_CSIGROUP, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteCSIGroupConfig(name, "Drift original", false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
