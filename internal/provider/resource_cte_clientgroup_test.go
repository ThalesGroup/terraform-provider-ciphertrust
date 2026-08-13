package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
)

// TestCTEClientGroupResource walks a client group through create -> attribute
// update -> add-clients -> remove-clients -> import. name and cluster_type are
// immutable; attribute edits use op_type = "update".
func TestCTEClientGroupResource(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-" + suffix
	c1 := "tf-cg-c1-" + suffix
	c2 := "tf-cg-c2-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"

	createCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, cgName)

	updateCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Updated via TF"
  op_type               = "update"
  communication_enabled = true
  client_locked         = true
}
`, cgName)

	clientsBlock := fmt.Sprintf(`
resource "ciphertrust_cte_client" "c1" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
  communication_enabled    = true
  client_locked            = true
}

resource "ciphertrust_cte_client" "c2" {
  name                     = %q
  password_creation_method = "GENERATE"
  registration_allowed     = true
  communication_enabled    = true
  client_locked            = true
}
`, c1, c2)

	addCfg := providerConfig + clientsBlock + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Updated via TF"
  communication_enabled = true
  client_locked         = true
  op_type               = "add-client"
  client_list           = [ciphertrust_cte_client.c1.name, ciphertrust_cte_client.c2.name]
  inherit_attributes    = true
}
`, cgName)

	removeCfg := providerConfig + clientsBlock + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Updated via TF"
  communication_enabled = true
  client_locked         = true
  op_type               = "remove-client"
  client_list           = []
}
`, cgName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "client_group: create",
					resource.TestCheckResourceAttrSet(rn, "id"),
					resource.TestCheckResourceAttr(rn, "name", cgName),
					resource.TestCheckResourceAttr(rn, "description", "Initial create"),
				),
			},
			{
				Config: updateCfg,
				Check: checkStep(t, "client_group: update attributes",
					resource.TestCheckResourceAttr(rn, "description", "Updated via TF"),
				),
			},
			{
				Config: addCfg,
				Check: checkStep(t, "client_group: add clients",
					resource.TestCheckResourceAttr(rn, "client_list.#", "2"),
				),
			},
			{
				Config: removeCfg,
				Check: checkStep(t, "client_group: remove clients",
					resource.TestCheckResourceAttr(rn, "client_list.#", "0"),
				),
			},
			// Import: passthrough id; op_type/client_list are action fields not
			// returned by Read, so ImportStateCheck is used instead of Verify.
			{
				ResourceName:     rn,
				ImportState:      true,
				ImportStateCheck: importStateCheckAttrsSet("id", "name"),
			},
		},
	})
}

// TestCTEClientGroupResource_nameRequiresReplace verifies a name change is
// planned as a destroy+create rather than an in-place update (TFIN-489).
func TestCTEClientGroupResource_nameRequiresReplace(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-imm-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"

	renamed := func(name string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
  op_type      = "update"
}
`, name)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, cgName),
				Check: checkStep(t, "client_group requires replace: create",
					resource.TestCheckResourceAttr(rn, "name", cgName),
				),
			},
			{
				Config: renamed(cgName + "-renamed"),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction(rn, plancheck.ResourceActionDestroyBeforeCreate),
					},
				},
				Check: checkStep(t, "client_group requires replace: rename",
					resource.TestCheckResourceAttr(rn, "name", cgName+"-renamed"),
				),
			},
		},
	})
}

// TestCTEClientGroupResource_clusterTypeImmutable verifies a change to the
// (immutable) cluster_type is rejected.
func TestCTEClientGroupResource_clusterTypeImmutable(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-ctimm-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"

	cfg := func(clusterType, op string) string {
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = %q
  description  = "ct immutable"
%s}
`, cgName, clusterType, op)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg("NON-CLUSTER", ""),
				Check: checkStep(t, "client_group cluster_type immutable: create",
					resource.TestCheckResourceAttr(rn, "cluster_type", "NON-CLUSTER"),
				),
			},
			{
				Config:      cfg("HDFS", "  op_type = \"update\"\n"),
				ExpectError: regexp.MustCompile(`(?i)cannot change client group cluster_type|immutable`),
			},
		},
	})
}

// TestCTEClientGroupResource_ldtPauseFieldGuard verifies op_type = "ldt-pause"
// rejects a config that also changes an unrelated field in the same apply
// (TFIN-625). Before the fix, the ldt-pause branch had no field-change
// guard at all: the apply would succeed, only the paused flag would be sent
// to CM, but the unrelated field's new value would still be recorded in
// state -- a false value only caught on the next refresh. Also verifies
// normal ldt-pause-only usage (toggling paused with no other field change)
// still succeeds and produces no follow-up plan diff.
func TestCTEClientGroupResource_ldtPauseFieldGuard(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-ldtpause-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"

	createCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, cgName)

	// op_type = ldt-pause with an unrelated field (description) also changed
	// in the same apply -- must be rejected.
	pauseWithSneakedFieldCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "sneaked-in-via-ldt-pause"
  op_type      = "ldt-pause"
  paused       = true
}
`, cgName)

	// op_type = ldt-pause with only paused changed -- must succeed.
	pauseOnlyCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
  op_type      = "ldt-pause"
  paused       = true
}
`, cgName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "client_group ldt-pause guard: create",
					resource.TestCheckResourceAttr(rn, "description", "Initial create"),
				),
			},
			{
				Config:      pauseWithSneakedFieldCfg,
				ExpectError: regexp.MustCompile(`description cannot be changed with op_type 'ldt-pause'`),
			},
			{
				Config: pauseOnlyCfg,
				Check: checkStep(t, "client_group ldt-pause guard: pause only",
					resource.TestCheckResourceAttr(rn, "description", "Initial create"),
					resource.TestCheckResourceAttr(rn, "paused", "true"),
				),
			},
			{
				Config:             pauseOnlyCfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTEClientGroupResource_drift mutates the description out-of-band and asserts
// the next plan is non-empty.
func TestCTEClientGroupResource_drift(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-drift-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Drift original"
}
`, cgName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "client_group drift: create",
					resource.TestCheckResourceAttr(rn, "description", "Drift original"),
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_CLIENT_GROUP, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
