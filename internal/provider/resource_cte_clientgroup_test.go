package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
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

// TestCTEClientGroupResource_descriptionQuoteNotCorrupted is a regression
// test for TFIN-624: Create()/Update() built the outgoing payload with
// common.TrimString(plan.Description.String()) instead of
// plan.Description.ValueString(). types.String.String() returns a Go
// %q-quoted debug representation (adds outer quotes, escapes internal " as
// \"), and TrimString only strips the outer quote pair, leaving the escaped
// backslash in the value sent to CM -- permanently corrupting any
// description containing a literal " character. If the value were corrupted
// on the way to CM, Read would keep reporting a different (mangled) value
// than the configured one, so the follow-up PlanOnly step would show a
// perpetual diff instead of "No changes".
func TestCTEClientGroupResource_descriptionQuoteNotCorrupted(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-quote-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"
	const wantCreateDescription = `He said "hello" to me`
	const wantUpdateDescription = `Updated: she said "goodbye" now`

	cfg := func(description string, update bool) string {
		op := ""
		if update {
			op = "  op_type      = \"update\"\n"
		}
		return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = %q
%s}
`, cgName, description, op)
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg(wantCreateDescription, false),
				Check: checkStep(t, "client_group quote: create",
					resource.TestCheckResourceAttr(rn, "description", wantCreateDescription),
				),
			},
			{
				Config:             cfg(wantCreateDescription, false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cfg(wantUpdateDescription, true),
				Check: checkStep(t, "client_group quote: update",
					resource.TestCheckResourceAttr(rn, "description", wantUpdateDescription),
				),
			},
			{
				Config:             cfg(wantUpdateDescription, true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTEClientGroupResource_nameImmutable verifies that changing name after
// creation produces a plan-time immutable error from ImmutableString rather
// than a destroy+create, since the client group's id is referenced elsewhere
// via client_group_id on ciphertrust_cte_clientgroup_designatedprimaryset and
// ciphertrust_cte_clientgroup_guardpoint, and must not be reminted on rename
// (TFIN-642 Scenario 2).
func TestCTEClientGroupResource_nameImmutable(t *testing.T) {
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
				Check: checkStep(t, "client_group immutable name: create",
					resource.TestCheckResourceAttr(rn, "name", cgName),
				),
			},
			{
				Config:      renamed(cgName + "-renamed"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable`),
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

// TestCTEClientGroupResource_explicitFalseReachesCM verifies TFIN-640: setting
// re_sign explicitly to false (after it was true) actually reaches CipherTrust
// Manager rather than being silently dropped. Before the fix, the guard
// `plan.ReSign.ValueBool() != types.BoolNull().ValueBool()` could never
// distinguish "explicitly false" from "unset" (types.BoolNull().ValueBool()
// is always false, the Go zero value), so the assignment to payload.ReSign
// was skipped whenever the desired value was false. For ReSign specifically
// this was compounded by the `,omitempty` tag on CTEClientGroupJSON.ReSign:
// even after fixing the guard to `!plan.ReSign.IsNull()`, a plain (non-pointer)
// bool with `omitempty` still drops the field whenever its value is false,
// with no way to distinguish "explicitly assigned false" from "left at zero
// value" -- so the full fix required both the guard fix and dropping
// `omitempty` from that field. Terraform state alone can't catch this
// regression (Update() writes state from plan unconditionally), so this test
// reads the live CM object directly via cteGetByID/gjson rather than relying
// on resource.TestCheckResourceAttr against state.
func TestCTEClientGroupResource_explicitFalseReachesCM(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-falsedrop-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"
	var capturedID string

	createCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, cgName)

	reSignTrueCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
  op_type      = "auth-binaries"
  re_sign      = true
}
`, cgName)

	reSignFalseCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
  op_type      = "auth-binaries"
  re_sign      = false
}
`, cgName)

	checkCMEnabledCapabilities := func(want string) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			body, ok := cteGetByID(common.URL_CTE_CLIENT_GROUP, capturedID)
			if !ok {
				return fmt.Errorf("could not fetch live CTE client group %s from CM", capturedID)
			}
			got := gjson.Get(body, "enabled_capabilities").String()
			if got != want {
				return fmt.Errorf("live CM enabled_capabilities = %q, want %q (body: %s)", got, want, body)
			}
			return nil
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "client_group explicit-false: create",
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				// enabled_capabilities is Computed (TFIN-640) and driven entirely
				// by CM as a side effect of re_sign under op_type=auth-binaries --
				// it plans as unknown here (never configured) and resolves cleanly
				// to CM's actual value with no drift.
				Config: reSignTrueCfg,
				Check: checkStep(t, "client_group explicit-false: re_sign=true reaches CM",
					resource.TestCheckResourceAttr(rn, "re_sign", "true"),
					resource.TestCheckResourceAttr(rn, "enabled_capabilities", "RESIGN"),
					checkCMEnabledCapabilities("RESIGN"),
				),
			},
			{
				Config: reSignFalseCfg,
				Check: checkStep(t, "client_group explicit-false: re_sign=false reaches CM (TFIN-640)",
					resource.TestCheckResourceAttr(rn, "re_sign", "false"),
					resource.TestCheckNoResourceAttr(rn, "enabled_capabilities"),
					checkCMEnabledCapabilities(""),
				),
			},
		},
	})
}

// TestCTEClientGroupResource_explicitFalseBooleanFields verifies the same
// TFIN-640 guard fix for the remaining boolean fields that share the broken
// `ValueBool() != types.BoolNull().ValueBool()` pattern: client_locked,
// communication_enabled, enable_domain_sharing, system_locked, and paused.
// Unlike ReSign, these fields' JSON tags never had `omitempty`, so Go's zero
// value for bool (false) was already marshaled as an explicit `false` even
// when the buggy guard skipped the assignment -- meaning these fields did not
// actually exhibit an observable drop of the false value before this fix,
// only the (harmless in this case, but fragile) code smell. This test locks
// in that true/false behavior via the corrected null-check so a future change
// to these fields' JSON tags doesn't silently reintroduce the same class of
// bug ReSign had.
func TestCTEClientGroupResource_explicitFalseBooleanFields(t *testing.T) {
	suffix := uuid.New().String()[:8]
	cgName := "tf-cg-falsebool-" + suffix
	const rn = "ciphertrust_cte_client_group.cg"
	var capturedID string

	createCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name         = %q
  cluster_type = "NON-CLUSTER"
  description  = "Initial create"
}
`, cgName)

	boolsTrueCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Initial create"
  op_type               = "update"
  client_locked         = true
  communication_enabled = true
  enable_domain_sharing = true
  system_locked         = true
}
`, cgName)

	boolsFalseCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Initial create"
  op_type               = "update"
  client_locked         = false
  communication_enabled = false
  enable_domain_sharing = false
  system_locked         = false
}
`, cgName)

	pauseTrueCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Initial create"
  op_type               = "ldt-pause"
  paused                = true
}
`, cgName)

	pauseFalseCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client_group" "cg" {
  name                  = %q
  cluster_type          = "NON-CLUSTER"
  description           = "Initial create"
  op_type               = "ldt-pause"
  paused                = false
}
`, cgName)

	checkCMBools := func(want bool) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			body, ok := cteGetByID(common.URL_CTE_CLIENT_GROUP, capturedID)
			if !ok {
				return fmt.Errorf("could not fetch live CTE client group %s from CM", capturedID)
			}
			for _, field := range []string{"client_locked", "communication_enabled", "enable_domain_sharing", "system_locked"} {
				got := gjson.Get(body, field).Bool()
				if got != want {
					return fmt.Errorf("live CM %s = %v, want %v (body: %s)", field, got, want, body)
				}
			}
			return nil
		}
	}

	checkCMLdtStatus := func(wantPaused bool) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			body, ok := cteGetByID(common.URL_CTE_CLIENT_GROUP, capturedID)
			if !ok {
				return fmt.Errorf("could not fetch live CTE client group %s from CM", capturedID)
			}
			status := gjson.Get(body, "ldt_status").String()
			isPaused := status == "Paused"
			if isPaused != wantPaused {
				return fmt.Errorf("live CM ldt_status = %q (paused=%v), want paused=%v (body: %s)", status, isPaused, wantPaused, body)
			}
			return nil
		}
	}

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "client_group explicit-false bools: create",
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				Config: boolsTrueCfg,
				Check: checkStep(t, "client_group explicit-false bools: true reaches CM",
					checkCMBools(true),
				),
			},
			{
				Config: boolsFalseCfg,
				Check: checkStep(t, "client_group explicit-false bools: false reaches CM (TFIN-640)",
					checkCMBools(false),
				),
			},
			{
				Config: pauseTrueCfg,
				Check: checkStep(t, "client_group explicit-false paused: true reaches CM",
					checkCMLdtStatus(true),
				),
			},
			{
				Config: pauseFalseCfg,
				Check: checkStep(t, "client_group explicit-false paused: false reaches CM (TFIN-640)",
					checkCMLdtStatus(false),
				),
			},
		},
	})
}
