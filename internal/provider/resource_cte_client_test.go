package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
)

// cteClientConfig renders a ciphertrust_cte_client. When updated is true the
// mutable fields (description, client_locked, registration_allowed) are set so
// the update step can read them back.
func cteClientConfig(name string, updated bool) string {
	extra := ""
	if updated {
		extra = `  description          = "Updated via TF"
  client_locked        = true
  registration_allowed = true
`
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
%s}
`, name, extra)
}

// cteClientDescriptionConfig renders a ciphertrust_cte_client with an explicit
// description, letting callers pass values that need to round-trip verbatim
// (e.g. a literal double quote).
func cteClientDescriptionConfig(name, description string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
  description              = %q
}
`, name, description)
}

// TestCTEClientResource_descriptionQuoteNotCorrupted is a regression test for
// TFIN-639: Create()/Update() built the outgoing payload with
// common.TrimString(plan.Description.String()) instead of
// plan.Description.ValueString(). types.String.String() returns a Go
// %q-quoted debug representation (adds outer quotes, escapes internal " as
// \"), and TrimString only strips the outer quote pair, leaving the escaped
// backslash in the value sent to CM -- permanently corrupting any description
// containing a literal " character. If the value were corrupted on the way
// to CM, Read would keep reporting a different (mangled) value than the
// configured one, so the follow-up PlanOnly step would show a perpetual
// diff instead of "No changes".
func TestCTEClientResource_descriptionQuoteNotCorrupted(t *testing.T) {
	name := "tf-client-quote-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"
	const wantCreateDescription = `He said "hello" to me`
	const wantUpdateDescription = `Updated: she said "goodbye" now`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientDescriptionConfig(name, wantCreateDescription),
				Check: checkStep(t, "client quote: create",
					resource.TestCheckResourceAttr(rn, "description", wantCreateDescription),
				),
			},
			{
				Config:             cteClientDescriptionConfig(name, wantCreateDescription),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			{
				Config: cteClientDescriptionConfig(name, wantUpdateDescription),
				Check: checkStep(t, "client quote: update",
					resource.TestCheckResourceAttr(rn, "description", wantUpdateDescription),
				),
			},
			{
				Config:             cteClientDescriptionConfig(name, wantUpdateDescription),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestCTEClientResource(t *testing.T) {
	name := "tf-client-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientConfig(name, false),
				Check: checkStep(t, "client: create",
					resource.TestCheckResourceAttrSet(rn, "id"),
					resource.TestCheckResourceAttr(rn, "name", name),
				),
			},
			// Unrelated change (description/client_locked/registration_allowed). The
			// PreApply checks assert the computed profile_id/profile_name stay known
			// values in the plan instead of flipping to "(known after apply)".
			{
				Config: cteClientConfig(name, true),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectKnownValue(
							rn,
							tfjsonpath.New("profile_id"),
							knownvalue.StringRegexp(regexp.MustCompile(`.+`)),
						),
						plancheck.ExpectKnownValue(
							rn,
							tfjsonpath.New("profile_name"),
							knownvalue.StringRegexp(regexp.MustCompile(`.+`)),
						),
					},
				},
				Check: checkStep(t, "client: update",
					resource.TestCheckResourceAttr(rn, "description", "Updated via TF"),
					resource.TestCheckResourceAttr(rn, "client_locked", "true"),
				),
			},
			{
				Config:             cteClientConfig(name, true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Import: passthrough id. password_creation_method is a write-only
			// action field not returned by Read, so ImportStateCheck (not
			// ImportStateVerify) is used to keep the round-trip robust.
			{
				ResourceName:     rn,
				ImportState:      true,
				ImportStateCheck: importStateCheckAttrsSet("id", "name"),
			},
		},
	})
}

// TestCTEClientResource_nameImmutable verifies a name change is rejected.
func TestCTEClientResource_nameImmutable(t *testing.T) {
	name := "tf-client-imm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientConfig(name, false),
				Check: checkStep(t, "client immutable: create",
					resource.TestCheckResourceAttr(rn, "name", name),
				),
			},
			{
				Config:      cteClientConfig(name+"-renamed", false),
				ExpectError: regexp.MustCompile(`(?i)cannot change client name|immutable`),
			},
		},
	})
}

// cteClientTypedConfig renders a client with an explicit client_type, used by the
// client_type-immutability test.
func cteClientTypedConfig(name, clientType string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  client_type              = %q
  password_creation_method = "GENERATE"
}
`, name, clientType)
}

// TestCTEClientResource_typeImmutable verifies a change to the (immutable)
// client_type is rejected.
func TestCTEClientResource_typeImmutable(t *testing.T) {
	name := "tf-client-typeimm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientTypedConfig(name, "FS"),
				Check: checkStep(t, "client type immutable: create",
					resource.TestCheckResourceAttr(rn, "client_type", "FS"),
				),
			},
			{
				Config:      cteClientTypedConfig(name, "CTE-U"),
				ExpectError: regexp.MustCompile(`(?i)cannot change client_type|immutable`),
			},
		},
	})
}

// cteClientProtectionModeConfig renders a client whose config asks for a
// protection mode.
func cteClientProtectionModeConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
  protection_mode          = "CTE RWP"
}
`, name)
}

// TestCTEClientResource_protectionModeReadBack asserts protection_mode is refreshed
// from the live client instead of being trusted from config. Create never sends
// protection_mode to CipherTrust Manager, so a client created with
// protection_mode = "CTE RWP" in its config is really still in CM's default "CTE"
// mode, and Read must report that.
func TestCTEClientResource_protectionModeReadBack(t *testing.T) {
	name := "tfin464-pm-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientProtectionModeConfig(name),
				Check: checkStep(t, "client protection_mode: create",
					resource.TestCheckResourceAttr(rn, "protection_mode", "CTE RWP"),
				),
				// The post-apply refresh replaces the configured value with the live
				// one, so the follow-up plan is legitimately non-empty here.
				ExpectNonEmptyPlan: true,
			},
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "client protection_mode: refresh",
					resource.TestCheckResourceAttr(rn, "protection_mode", "CTE"),
				),
			},
		},
	})
}

// cteClientCacheLogConfig renders a client that explicitly configures
// max_num_cache_log/max_space_cache_log, both of which CipherTrust Manager
// silently ignores at the client level (TFIN-467).
func cteClientCacheLogConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
  max_num_cache_log        = 200
  max_space_cache_log      = 100
}
`, name)
}

// TestCTEClientResource_cacheLogNonFunctional verifies that configuring
// max_num_cache_log/max_space_cache_log is rejected up front with an explicit
// error, instead of silently no-oping against CipherTrust Manager and
// producing a perpetual, unresolvable plan diff (TFIN-467).
func TestCTEClientResource_cacheLogNonFunctional(t *testing.T) {
	name := "tf-client-cachelog-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:      cteClientCacheLogConfig(name),
				ExpectError: regexp.MustCompile(`(?i)non-functional field for cte client`),
			},
		},
	})
}

// TestCTEClientResource_drift mutates the description out-of-band and asserts the
// next plan is non-empty.
func TestCTEClientResource_drift(t *testing.T) {
	name := "tf-client-drift-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientConfig(name, true),
				Check: checkStep(t, "client drift: create",
					resource.TestCheckResourceAttr(rn, "description", "Updated via TF"),
					cteCaptureID(rn, &capturedID),
				),
			},
			{
				PreConfig: func() {
					cteOutOfBandPatch(common.URL_CTE_CLIENT, capturedID, `{"description":"Out-of-band modified"}`)
				},
				Config:             cteClientConfig(name, true),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// cteClientLabelsConfig renders a ciphertrust_cte_client with labels set when
// withLabels is true, and no labels attribute at all when false.
func cteClientLabelsConfig(name string, withLabels bool) string {
	labels := ""
	if withLabels {
		labels = `  labels = {
    env = "drift-test"
  }
`
	}
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
%s}
`, name, labels)
}

// TestCTEClientResource_labelsClearing verifies TFIN-463: Update() sends an
// explicit null (not {}) when labels is cleared. Create() never sends labels
// to CM (the same gap documented for protection_mode above; also confirmed
// separately via direct, provider-independent API calls: CM's
// transparent-encryption/clients endpoint never persists a non-empty "labels"
// value regardless of write path on this appliance), so the refresh in step 2
// legitimately diverges from the configured value.
//
// labels is now Optional+Computed with an empty-map default (TFIN-619), so
// the "cleared" value the resource converges to is a concrete empty map, not
// null - see TestCTEClientResource_labelsExplicitEmptyConverges for the
// explicit labels = {} convergence check this schema change was for.
func TestCTEClientResource_labelsClearing(t *testing.T) {
	name := "tfin463-labels-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cteClientLabelsConfig(name, true),
				Check: checkStep(t, "client labels: create",
					resource.TestCheckResourceAttr(rn, "labels.env", "drift-test"),
				),
				ExpectNonEmptyPlan: true,
			},
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "client labels: refresh converges to an empty map instead of getting stuck (TFIN-463)",
					resource.TestCheckNoResourceAttr(rn, "labels.env"),
					resource.TestCheckResourceAttr(rn, "labels.%", "0"),
				),
			},
			{
				Config: cteClientLabelsConfig(name, false),
				Check: checkStep(t, "client labels: config catches up to empty",
					resource.TestCheckNoResourceAttr(rn, "labels.env"),
					resource.TestCheckResourceAttr(rn, "labels.%", "0"),
				),
			},
			{
				Config:             cteClientLabelsConfig(name, false),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTEClientResource_labelsExplicitEmptyConverges verifies TFIN-619: after
// labels has held a value, switching config to an explicit labels = {} (as
// opposed to omitting the attribute entirely) converges to "No changes" on
// the next plan instead of looping forever. labels is Optional+Computed with
// an empty-map default (see schema), so both the omitted case (already
// covered by TestCTEClientResource_labelsClearing) and this explicit-{} case
// resolve to the same state value.
func TestCTEClientResource_labelsExplicitEmptyConverges(t *testing.T) {
	name := "tfin619-labels-empty-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"

	explicitEmptyCfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_cte_client" "client" {
  name                     = %q
  password_creation_method = "GENERATE"
  labels                   = {}
}
`, name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config:             cteClientLabelsConfig(name, true),
				ExpectNonEmptyPlan: true,
				Check: checkStep(t, "client labels: create with labels.env=drift-test",
					resource.TestCheckResourceAttr(rn, "labels.env", "drift-test"),
				),
			},
			{
				Config: explicitEmptyCfg,
				Check: checkStep(t, "client labels: switch to explicit labels = {}",
					resource.TestCheckResourceAttr(rn, "labels.%", "0"),
				),
			},
			// Plan again with the same explicit labels = {} - fixes TFIN-619:
			// must show "No changes", not a perpetual diff.
			{
				Config:             explicitEmptyCfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCTEClientResource_emptyDescriptionConverges verifies TFIN-619: after
// description has held a value, switching config to an explicit
// description = "" converges to "No changes" on the next plan, instead of
// looping forever proposing a description change. description is now
// Optional+Computed with a "" default (see schema), so setCTEClientState no
// longer needs to normalize an empty API response to null - it just always
// reflects the API's actual value into state.
func TestCTEClientResource_emptyDescriptionConverges(t *testing.T) {
	name := "tfin619-desc-empty-" + uuid.New().String()[:8]
	const rn = "ciphertrust_cte_client.client"

	withDescription := cteClientDescriptionConfig(name, "non-empty description")
	emptyDescription := cteClientDescriptionConfig(name, "")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: withDescription,
				Check: checkStep(t, "client description: create with non-empty description",
					resource.TestCheckResourceAttr(rn, "description", "non-empty description"),
				),
			},
			{
				Config: emptyDescription,
				Check: checkStep(t, "client description: switch to explicit description = \"\"",
					resource.TestCheckResourceAttr(rn, "description", ""),
				),
			},
			// Plan again with the same explicit description = "" - fixes
			// TFIN-619: must show "No changes", not a perpetual diff.
			{
				Config:             emptyDescription,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
