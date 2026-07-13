package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/tidwall/gjson"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
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
				PreConfig: func() { interfaceSweep(9100) },
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9100
  name           = "kmip-test-9100"
  interface_type = "kmip"
}`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "created_at"),
					resource.TestCheckResourceAttrSet("ciphertrust_interface.test", "updated_at"),
				),
			},
			{
				// Identical config — no PATCH issued, so updated_at is stable.
				// Verifies no spurious diff from any attribute.
				Config: providerConfig + `
resource "ciphertrust_interface" "test" {
  port           = 9100
  name           = "kmip-test-9100"
  interface_type = "kmip"
}`,
				PlanOnly:           true,
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
