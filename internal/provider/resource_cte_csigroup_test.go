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

// TestCTECSIGroupResource_descriptionQuoteNotCorrupted is a regression test
// for TFIN-636 Scenario 1: Create()/Update() built the outgoing payload with
// common.TrimString(plan.X.String()) instead of plan.X.ValueString() for
// description (among other fields, e.g. client_profile -- not exercised here
// since client_profile must reference an existing CM CTE Client Profile
// rather than accept an arbitrary string). types.String.String() returns a
// Go %q-quoted debug representation (adds outer quotes, escapes internal "
// as \"), and TrimString only strips the outer quote pair, leaving the
// escaped backslash in the value sent to CM -- permanently corrupting any
// value containing a literal " character. If the value were corrupted on
// the way to CM, Read would keep reporting a mangled value, so the
// follow-up PlanOnly steps would show a perpetual diff instead of "No
// changes".
func TestCTECSIGroupResource_descriptionQuoteNotCorrupted(t *testing.T) {
	name := "tf-csi-quote-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_csigroup.csigroup"
	const wantCreateDescription = `He said "hello" to me`
	const wantUpdateDescription = `Updated: she said "goodbye" now`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteCSIGroupConfig(name, wantCreateDescription, false),
				Check: checkStep(t, "csigroup quote: create",
					resource.TestCheckResourceAttr(rn, "description", wantCreateDescription),
				),
			},
			{
				Config:             cteCSIGroupConfig(name, wantCreateDescription, false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cteCSIGroupConfig(name, wantUpdateDescription, true),
				Check: checkStep(t, "csigroup quote: update",
					resource.TestCheckResourceAttr(rn, "description", wantUpdateDescription),
				),
			},
			{
				Config:             cteCSIGroupConfig(name, wantUpdateDescription, true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTECSIGroupResource_addGuardPolicyNoCrash is a regression test for
// TFIN-636 Scenario 2: guard_policies[*].gp_id used
// stringplanmodifier.UseStateForUnknown() instead of
// UseNonNullStateForUnknown(). For a brand-new guard_policies map key with no
// prior state, UseStateForUnknown() planned a concrete null (not "unknown")
// for gp_id, so Terraform's plan-consistency check rejected the apply once
// Update() resolved it to a real UUID -- crashing with "Provider produced
// inconsistent result after apply" on every first-time addition of a guard
// policy via op_type = "update-guard-policies".
func TestCTECSIGroupResource_addGuardPolicyNoCrash(t *testing.T) {
	name := "tf-csi-gp-" + uuid.New().String()[:8]
	policyName := "tf-csi-gp-policy-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_csigroup.csigroup"

	policyCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_policy" "csi_policy" {
  name           = %q
  policy_type    = "CSI"
  never_deny     = true
  security_rules = [{ effect = "permit" }]
  description    = "Created via TF test"
}
`, policyName)

	createCfg := policyCfg + fmt.Sprintf(`
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = %q
  kubernetes_namespace     = "default"
  kubernetes_storage_class = "standard"
}
`, name)

	addGuardPolicyCfg := policyCfg + fmt.Sprintf(`
resource "ciphertrust_cte_csigroup" "csigroup" {
  name                     = %q
  kubernetes_namespace     = "default"
  kubernetes_storage_class = "standard"
  op_type                  = "update-guard-policies"
  guard_policies = {
    (ciphertrust_cte_policy.csi_policy.name) = {}
  }
}
`, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "csigroup guard policy: create",
					resource.TestCheckResourceAttrSet(rn, "id"),
				),
			},
			{
				// The regression: this apply used to crash with "Provider
				// produced inconsistent result after apply" instead of
				// completing.
				Config: addGuardPolicyCfg,
				Check: checkStep(t, "csigroup guard policy: add (no crash)",
					resource.TestCheckResourceAttrSet(rn, "guard_policies."+policyName+".gp_id"),
					resource.TestCheckResourceAttr(rn, "guard_policies."+policyName+".guard_enabled", "true"),
				),
			},
			{
				Config:             addGuardPolicyCfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTECSIGroupResource_nameImmutable verifies a name change is rejected.
func TestCTECSIGroupResource_nameImmutable(t *testing.T) {
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

// TestCTECSIGroupResource_namespaceImmutable verifies a change to the (immutable)
// kubernetes_namespace is rejected.
func TestCTECSIGroupResource_namespaceImmutable(t *testing.T) {
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

// TestCTECSIGroupResource_storageClassImmutable verifies a change to the
// (immutable) kubernetes_storage_class is rejected.
func TestCTECSIGroupResource_storageClassImmutable(t *testing.T) {
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

// TestCTECSIGroupResource_drift mutates the description out-of-band and asserts
// the next plan is non-empty.
func TestCTECSIGroupResource_drift(t *testing.T) {
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
