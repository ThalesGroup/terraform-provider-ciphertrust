package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func cteLDTGroupCommsConfig(name, description string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_ldtgroupcomms" "ldt" {
  name        = %q
  description = %q
}
`, name, description)
}

func TestCTELDTGroupCommResource(t *testing.T) {
	name := "tf-ldtgc-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_ldtgroupcomms.ldt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteLDTGroupCommsConfig(name, "Initial LDT group comm service"),
				Check: checkStep(t, "ldtgroupcomms: create",
					resource.TestCheckResourceAttrSet(rn, "id"),
					resource.TestCheckResourceAttr(rn, "name", name),
					resource.TestCheckResourceAttr(rn, "description", "Initial LDT group comm service"),
				),
			},
			{
				Config: cteLDTGroupCommsConfig(name, "Updated LDT group comm service"),
				Check: checkStep(t, "ldtgroupcomms: update",
					resource.TestCheckResourceAttr(rn, "description", "Updated LDT group comm service"),
				),
			},
			{
				Config:             cteLDTGroupCommsConfig(name, "Updated LDT group comm service"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				ResourceName:     rn,
				ImportState:      true,
				ImportStateCheck: importStateCheckAttrsSet("id", "name"),
			},
		},
	})
}

// TestCTELDTGroupCommResource_nameImmutable verifies a name change is rejected.
func TestCTELDTGroupCommResource_nameImmutable(t *testing.T) {
	name := "tf-ldtgc-imm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_ldtgroupcomms.ldt"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteLDTGroupCommsConfig(name, "Initial"),
				Check: checkStep(t, "ldtgroupcomms immutable: create",
					resource.TestCheckResourceAttr(rn, "name", name),
				),
			},
			{
				Config:      cteLDTGroupCommsConfig(name+"-renamed", "Initial"),
				ExpectError: regexp.MustCompile(`(?i)cannot change name once the ldt comm group|immutable`),
			},
		},
	})
}

// TestCTELDTGroupCommResource_drift mutates the description out-of-band and
// asserts the next plan is non-empty.
func TestCTELDTGroupCommResource_drift(t *testing.T) {
	name := "tf-ldtgc-drift-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_ldtgroupcomms.ldt"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteLDTGroupCommsConfig(name, "Drift original"),
				Check: checkStep(t, "ldtgroupcomms drift: create",
					resource.TestCheckResourceAttr(rn, "description", "Drift original"),
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_LDT_GROUP_COMM_SVC, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteLDTGroupCommsConfig(name, "Drift original"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
