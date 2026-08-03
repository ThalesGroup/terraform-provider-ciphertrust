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
// explicit null (not {}) when labels is cleared, and Read() normalizes an
// absent/empty labels response to null so the resource can converge once
// labels has ever been set. Create() never sends labels to CM (the same gap
// documented for protection_mode above), so the refresh in step 2 legitimately
// diverges from the configured value and exercises Read()'s normalization.
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
				Check: checkStep(t, "client labels: refresh converges to null instead of getting stuck (TFIN-463)",
					resource.TestCheckNoResourceAttr(rn, "labels.env"),
				),
			},
			{
				Config: cteClientLabelsConfig(name, false),
				Check: checkStep(t, "client labels: config catches up to null",
					resource.TestCheckNoResourceAttr(rn, "labels.env"),
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
