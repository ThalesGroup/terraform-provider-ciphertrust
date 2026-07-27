package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"testing"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/tidwall/gjson"
)

// interfaceSweep deletes all interfaces at the given port, ignoring errors.
// Used as PreConfig sweep to clean up orphaned interfaces from prior failed runs.
func interfaceSweep(port int64) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	ctx := context.Background()
	id := "sweep"
	raw, err := client.GetAll(ctx, id, common.URL_INTERFACE)
	if err != nil {
		return
	}
	gjson.Parse(raw).ForEach(func(_, iface gjson.Result) bool {
		if iface.Get("port").Int() == port {
			// CM's interface API uses NAME (not UUID) for DELETE operations.
			ifaceName := iface.Get("name").String()
			if ifaceName != "" {
				delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_INTERFACE, ifaceName)
				_, _ = client.DeleteByID(ctx, "DELETE", ifaceName, delURL, nil)
			}
		}
		return true
	})
}

// Test_CM_AccCMInterface_Basic verifies basic create/read with zero drift on refresh.
func Test_CM_AccCMInterface_Basic(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9009) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9009
  interface_type = "nae"
  mode           = "no-tls-pw-opt"
}
`,
				Check: checkStep(t, "basic: create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "created_at"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "mode", "no-tls-pw-opt"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "interface_type", "nae"),
				),
			},
			{
				// No out-of-band change; Read() must produce no diff.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMInterface_Update verifies that Update() uses the interface name as the PATCH path key
// and that the resource ID is stable across updates.
func Test_CM_AccCMInterface_Update(t *testing.T) {
	RequireCM(t)
	var interfaceID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9010) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9010
  interface_type = "nae"
  mode           = "no-tls-pw-opt"
}
`,
				Check: checkStep(t, "update: create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "mode", "no-tls-pw-opt"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_interface.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						interfaceID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9010
  interface_type = "nae"
  mode           = "tls-pw-opt"
}
`,
				Check: checkStep(t, "update: mode change",
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_interface.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						if rs.Primary.ID != interfaceID {
							return fmt.Errorf("expected id %q, got %q", interfaceID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "updated_at"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "mode", "tls-pw-opt"),
				),
			},
		},
	})
}

// Test_CM_AccCMInterface_ImmutableName verifies that ImmutableString() rejects name changes at plan time.
// CM auto-assigns a name on creation; the test verifies that attempting to set a different name
// in a subsequent plan is rejected by the ImmutableString() modifier.
func Test_CM_AccCMInterface_ImmutableName(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9011) },
				// Create without specifying name — CM auto-assigns one (e.g. "nae_all_9011").
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9011
  interface_type = "nae"
}
`,
				Check: checkStep(t, "immutable name: create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "name"),
				),
			},
			{
				// Attempting to change the auto-assigned name must be rejected at plan time.
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)cannot be changed`),
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9011
  interface_type = "nae"
  name           = "nae-renamed-9011"
}
`,
			},
		},
	})
}

// Test_CM_AccCMInterface_ImmutableInterfaceType verifies that ImmutableString() rejects interface_type changes at plan time.
func Test_CM_AccCMInterface_ImmutableInterfaceType(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9012) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9012
  interface_type = "nae"
}
`,
				Check: checkStep(t, "immutable interface_type: create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "interface_type", "nae"),
				),
			},
			{
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)cannot be changed`),
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9012
  interface_type = "kmip"
}
`,
			},
		},
	})
}

// Test_CM_AccCMInterface_Drift verifies that an out-of-band mode change is surfaced as drift.
func Test_CM_AccCMInterface_Drift(t *testing.T) {
	RequireCM(t)
	// CM's interface API uses NAME (not UUID) as the path key — capture name, not ID.
	var interfaceName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9013) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9013
  interface_type = "nae"
  mode           = "no-tls-pw-opt"
}
`,
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "mode", "no-tls-pw-opt"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_interface.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						interfaceName = rs.Primary.Attributes["name"]
						return nil
					},
				),
			},
			{
				// Change mode out-of-band; Read() must surface it as a non-empty plan.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client")
					}
					payload := []byte(`{"mode":"tls-pw-opt"}`)
					_, _ = client.UpdateData(
						context.Background(),
						interfaceName,
						common.URL_INTERFACE,
						payload,
						"updatedAt",
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_Interface_Idempotency verifies that after applying a KMIP interface, a second plan
// with no config changes produces an empty diff (no spurious attribute drift).
func Test_CM_Interface_Idempotency(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create without specifying name — CM rejects an explicit name on
				// KMIP interface create (same restriction as NAE) and auto-assigns one.
				PreConfig: func() { interfaceSweep(9015) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9015
  interface_type = "kmip"
}`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "name"),
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "created_at"),
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "updated_at"),
				),
			},
			{
				// Refresh state from CM without any config change.
				// No PATCH was issued so Read() must return the same values; plan must be empty.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMInterface_OOBDelete verifies that Read() calls RemoveResource on 404 so Terraform plans to recreate.
func Test_CM_AccCMInterface_OOBDelete(t *testing.T) {
	RequireCM(t)
	// CM's interface API uses NAME (not UUID) as the path key — capture name, not ID.
	var interfaceName string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9014) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9014
  interface_type = "nae"
}
`,
				Check: checkStep(t, "oob delete: create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_interface.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						interfaceName = rs.Primary.Attributes["name"]
						return nil
					},
				),
			},
			{
				// Delete out-of-band; Read() must remove from state so Terraform plans to recreate.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						t.Fatal("could not create CM client")
					}
					delURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_INTERFACE, interfaceName)
					_, _ = client.DeleteByID(
						context.Background(),
						"DELETE",
						interfaceName,
						delURL,
						nil,
					)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_Interface_Port_Immutable verifies that changing the port attribute
// of ciphertrust_interface triggers a plan-time validation error because the port is immutable.
func Test_CM_Interface_Port_Immutable(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9088) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9088
  interface_type = "nae"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "port", "9088"),
				),
			},
			{
				// Changing the port must emit a plan-time diagnostic error and fail.
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9089
  interface_type = "nae"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Attribute is immutable"),
			},
		},
	})
}

// Test_CM_Interface_TrustedCasExternalEmptySliceConverges verifies that trusted_cas.external=[]
// does not cause a perpetual plan diff after apply (TFIN-426a regression check).
func Test_CM_Interface_TrustedCasExternalEmptySliceConverges(t *testing.T) {
	RequireCM(t)

	// Discover a real local CA ID — CM requires at least one CA in the trusted_cas block.
	client, ok := createCMClient()
	if !ok {
		t.Skip("CM client unavailable — skipping")
	}
	resp, err := client.GetAll(context.Background(), uuid.New().String(), "api/v1/ca/local-cas")
	if err != nil || gjson.Get(resp, "resources.0.id").String() == "" {
		t.Skip("no local CAs available on this CM — skipping trusted_cas test")
	}
	localCAID := gjson.Get(resp, "resources.0.id").String()

	trustedCAsConfig := fmt.Sprintf(`
  trusted_cas = {
    external = []
    local    = [%q]
  }`, localCAID)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: baseline NAE interface with no trusted_cas block.
				PreConfig: func() { interfaceSweep(9870) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9870
  interface_type = "nae"
}`,
				Check: checkStep(t, "baseline apply succeeded",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "interface_type", "nae"),
				),
			},
			{
				// Step 2: add trusted_cas with external = [] and a real local CA.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_interface" "test" {
  port           = 9870
  interface_type = "nae"
%s
}`, trustedCAsConfig),
				Check: checkStep(t, "trusted_cas applied",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "trusted_cas.external.#", "0"),
				),
			},
			{
				// Step 3: identical config — must reach "No changes" (TFIN-426a regression check).
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_interface" "test" {
  port           = 9870
  interface_type = "nae"
%s
}`, trustedCAsConfig),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Interface_LocalAutoGenUIDConverges verifies that local_auto_gen_attributes.uid
// is preserved in state across Read() calls (TFIN-426b regression check).
//
// CM does not return 'uid' in GET responses, so the provider must preserve the configured
// value from prior state. Before the fix, Read() cleared uid to null on every refresh,
// causing a perpetual diff. After the fix, uid survives repeated Read() calls.
//
// Note: CM overrides other local_auto_gen_attributes fields (cn, dns_names, etc.) with
// auto-generated values, so ExpectNonEmptyPlan for those fields is expected. The specific
// regression being tested is that uid does NOT appear in that diff.
func Test_CM_Interface_LocalAutoGenUIDConverges(t *testing.T) {
	RequireCM(t)

	uid := "tfin426-uid-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Apply with uid in local_auto_gen_attributes.
				// CM may override cn/dns_names/email_addresses with auto-generated defaults, so a
				// non-empty plan is expected for those fields. The Check verifies uid IS preserved
				// in state after apply+Read() (the key regression for TFIN-426b).
				PreConfig: func() { interfaceSweep(9871) },
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_interface" "test" {
  port           = 9871
  interface_type = "nae"
  local_auto_gen_attributes = {
    cn              = "test.local"
    dns_names       = ["test.local"]
    email_addresses = ["test@example.com"]
    ip_addresses    = ["10.0.0.1"]
    uid             = %q
  }
}`, uid),
				Check: checkStep(t, "uid applied and preserved in state",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "local_auto_gen_attributes.uid", uid),
				),
				// CM overrides other local_auto_gen_attributes fields with auto-generated values.
				ExpectNonEmptyPlan: true,
			},
			{
				// Step 2: Refresh from CM. uid must still be in state (TFIN-426b regression).
				// Before the fix: state.uid would be null here (Read() cleared it).
				// After the fix: state.uid = "tfin426-uid-xxx" (preserved from prior state).
				RefreshState:       true,
				ExpectNonEmptyPlan: true, // Other local_auto_gen_attributes fields still differ
				Check:              resource.TestCheckResourceAttr("ciphertrust_interface.test", "local_auto_gen_attributes.uid", uid),
			},
		},
	})
}

// Test_CM_Interface_CertificateClearDoesNotCrash verifies that removing the certificate block
// from config succeeds without a provider inconsistency error (TFIN-427 regression check).
func Test_CM_Interface_CertificateClearDoesNotCrash(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: baseline NAE interface with no certificate block.
				PreConfig: func() { interfaceSweep(9872) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9872
  interface_type = "nae"
}`,
				Check: checkStep(t, "baseline apply succeeded",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "interface_type", "nae"),
				),
			},
			{
				// Step 2: add a certificate block (generate=false, empty chain — minimal block).
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9872
  interface_type = "nae"
  certificate = {
    certificate_chain = ""
    generate          = false
    format            = "PEM"
    password          = ""
  }
}`,
				Check: checkStep(t, "certificate block applied",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "certificate.format", "PEM"),
				),
			},
			{
				// Step 3: remove certificate block — must succeed without "Provider produced
				// inconsistent result" error (TFIN-427 regression check).
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9872
  interface_type = "nae"
}`,
				Check: checkStep(t, "certificate cleared",
					resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "certificate.certificate_chain"),
				),
			},
		},
	})
}

// Test_CM_Interface_AutoRegistrationClearDoesNotCrash verifies that Update() correctly sends
// explicit clearing values for boolean fields (TFIN-427 regression check).
//
// CM requires a CM-generated registration_token when auto_registration=true, which is not
// available in this test environment. This test exercises the same Update() clearing code path
// using allow_unregistered (a boolean that can be set/cleared without tokens) to verify that
// Update() sends explicit false when the user removes a previously-set boolean field.
func Test_CM_Interface_AutoRegistrationClearDoesNotCrash(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with allow_unregistered=true.
				PreConfig: func() { interfaceSweep(9873) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port               = 9873
  interface_type     = "nae"
  allow_unregistered = true
}`,
				Check: checkStep(t, "allow_unregistered set",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "allow_unregistered", "true"),
				),
			},
			{
				// Step 2: Remove allow_unregistered from config. Update() must send explicit
				// false to CM so the value is cleared rather than preserved (TFIN-427 pattern).
				// After clear: allow_unregistered is null in state; plan shows no diff.
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9873
  interface_type = "nae"
}`,
				Check: checkStep(t, "allow_unregistered cleared",
					resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "allow_unregistered"),
				),
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Interface_KmipInterfaceTypeCreate verifies that a kmip interface can be created
// without an HTTP 400 from a spurious empty meta object (TFIN-429 regression check).
func Test_CM_Interface_KmipInterfaceTypeCreate(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: kmip interface — must not receive HTTP 400 from spurious empty meta.
				PreConfig: func() { interfaceSweep(9874) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9874
  interface_type = "kmip"
}`,
				Check: checkStep(t, "kmip created",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "interface_type", "kmip"),
					resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "meta.nae.mask_system_groups"),
				),
			},
			{
				// Step 2: identical config — must reach "No changes."
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_Interface_NaeWithMetaRoundTrips verifies that NAE interfaces with a meta block
// round-trip correctly after the pointer-type change (TFIN-429 pointer regression check).
func Test_CM_Interface_NaeWithMetaRoundTrips(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: NAE interface with meta block — verifies meta pointer-type path works.
				PreConfig: func() { interfaceSweep(9875) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9875
  interface_type = "nae"
  meta = {
    nae = {
      mask_system_groups = true
    }
  }
}`,
				Check: checkStep(t, "meta applied",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "meta.nae.mask_system_groups", "true"),
				),
			},
			{
				// Step 2: identical config — must reach "No changes."
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_CMInterface_ClearCertificate verifies the full clear lifecycle for the certificate block:
// create without certificate → add certificate → remove certificate block →
// TF state shows certificate absent and apply succeeds without inconsistency error (TFIN-427).
func Test_CM_CMInterface_ClearCertificate(t *testing.T) {
	RequireCM(t)
	port := 9876 + rand.New(rand.NewSource(time.Now().UnixNano())).Intn(100)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: baseline NAE interface with no certificate block.
				PreConfig: func() { interfaceSweep(int64(port)) },
				Config: fmt.Sprintf(providerConfig+`
resource "ciphertrust_interface" "test" {
  port           = %d
  interface_type = "nae"
}`, port),
				Check: checkStep(t, "create-no-cert",
					resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "certificate"),
				),
			},
			{
				// Step 2: add certificate block with generate=true, format="PEM".
				Config: fmt.Sprintf(providerConfig+`
resource "ciphertrust_interface" "test" {
  port           = %d
  interface_type = "nae"
  certificate = {
    certificate_chain = ""
    generate          = true
    format            = "PEM"
    password          = ""
  }
}`, port),
				Check: checkStep(t, "add-cert",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "certificate.generate", "true"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "certificate.format", "PEM"),
				),
			},
			{
				// Step 3: remove certificate block entirely — must succeed without
				// "Provider produced inconsistent result" error (TFIN-427 fix).
				Config: fmt.Sprintf(providerConfig+`
resource "ciphertrust_interface" "test" {
  port           = %d
  interface_type = "nae"
}`, port),
				Check: checkStep(t, "clear-cert",
					resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "certificate"),
				),
			},
		},
	})
}

// Test_CM_CMInterface_ClearRegistrationToken verifies the full clear lifecycle for
// auto_registration + registration_token: create interface → provision a real CM reg token →
// set auto_registration=true + registration_token → remove both → verify TF state shows both
// absent and CM-side GET confirms registration_token is cleared (TFIN-427).
func Test_CM_CMInterface_ClearRegistrationToken(t *testing.T) {
	RequireCM(t)

	// capturedName holds the CM-assigned interface name from Step 1 for CM-side assertion in Step 3.
	var capturedName string

	c, ok := createCMClient()
	if !ok {
		t.Skip("CM client unavailable — skipping registration token pre-provisioning")
	}

	// Pre-provision a real CM registration token.
	// CM rejects freeform strings as registration_token — a real token from the reg-token API is required.
	regTokenPayload, _ := json.Marshal(map[string]interface{}{
		"name_prefix":   "test",
		"lifetime":      "10h",
		"cert_duration": 730,
		"max_clients":   100,
	})
	regTokenResp, err := c.PostDataV2(context.Background(), uuid.New().String(), common.URL_REG_TOKEN, regTokenPayload)
	if err != nil {
		t.Fatalf("Failed to pre-provision registration token: %v", err)
	}
	regToken := gjson.Get(regTokenResp, "token").String()
	if regToken == "" {
		t.Fatalf("Pre-provisioned registration token is empty — cannot continue")
	}

	port := 9400 + rand.New(rand.NewSource(time.Now().UnixNano())).Intn(400)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Step 1: baseline NAE interface without auto_registration/registration_token.
				PreConfig: func() { interfaceSweep(int64(port)) },
				Config: fmt.Sprintf(providerConfig+`
resource "ciphertrust_interface" "test" {
  port           = %d
  interface_type = "nae"
}`, port),
				Check: func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources["ciphertrust_interface.test"]
					if !ok {
						return fmt.Errorf("resource not found in state")
					}
					capturedName = rs.Primary.Attributes["name"]
					if err := resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "registration_token")(s); err != nil {
						return err
					}
					return resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "auto_registration")(s)
				},
			},
			{
				// Step 2: set auto_registration=true and registration_token.
				// CM requires a real token when auto_registration=true.
				// The token is injected via TF_VAR_registration_token so it never appears
				// in the HCL config string (and therefore never in test framework logs).
				PreConfig: func() {
					t.Setenv("TF_VAR_registration_token", regToken)
				},
				Config: fmt.Sprintf(providerConfig+`
variable "registration_token" {}
resource "ciphertrust_interface" "test" {
  port               = %d
  interface_type     = "nae"
  auto_registration  = true
  registration_token = var.registration_token
}`, port),
				Check: checkStep(t, "add-token",
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "auto_registration", "true"),
				),
			},
			{
				// Step 3: remove both fields — must succeed and CM must reflect the clear (TFIN-427 fix).
				Config: fmt.Sprintf(providerConfig+`
resource "ciphertrust_interface" "test" {
  port           = %d
  interface_type = "nae"
}`, port),
				Check: func(s *terraform.State) error {
					// Assert TF state shows both fields absent.
					if err := resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "registration_token")(s); err != nil {
						return err
					}
					if err := resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "auto_registration")(s); err != nil {
						return err
					}
					// CM-side assertion: verify registration_token is actually cleared on CM.
					if capturedName == "" {
						t.Logf("capturedName not captured from Step 1 — skipping CM-side assertion")
						return nil
					}
					cmClient, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable in Step 3 Check — skipping CM-side assertion")
						return nil
					}
					resp, err := cmClient.ReadDataByParam(context.Background(), uuid.New().String(), capturedName, common.URL_INTERFACE)
					if err != nil {
						return fmt.Errorf("CM-side GET failed: %v", err)
					}
					token := gjson.Get(resp, "registration_token").String()
					if token != "" {
						return fmt.Errorf("expected registration_token to be absent/empty on CM after clear, got: %q", token)
					}
					return nil
				},
			},
		},
	})
}

// Test_CM_Interface_Clear_Optional_Fields asserts that clearing a previously
// set optional field properly resets its state on the server.
func Test_CM_Interface_Clear_Optional_Fields(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PreConfig: func() { interfaceSweep(9090) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port               = 9090
  interface_type     = "nae"
  allow_unregistered = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_interface.test", "allow_unregistered", "true"),
				),
			},
			{
				// Removing allow_unregistered from configuration should clear it from state and reset it on the server.
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9090
  interface_type = "nae"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckNoResourceAttr("ciphertrust_interface.test", "allow_unregistered"),
				),
			},
		},
	})
}
