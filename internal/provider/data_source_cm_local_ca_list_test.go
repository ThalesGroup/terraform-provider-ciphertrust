package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// Test_CM_LocalCAList_ReadAccuracy verifies the data source returns at least one CA
// with all expected attributes populated. Requires at least one local CA in the target
// CM instance.
func Test_CM_LocalCAList_ReadAccuracy(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
data "ciphertrust_cm_local_ca_list" "test" {}
`,
				Check: checkStep(t, "ReadAccuracy",
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.id"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.name"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.state"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.cert"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.serial_number"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.subject"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.issuer"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_local_ca_list.test", "cas.0.uri"),
				),
			},
		},
	})
}

// Test_CM_LocalCAList_Idempotency verifies that consecutive reads produce no plan diff.
func Test_CM_LocalCAList_Idempotency(t *testing.T) {
	RequireCM(t)

	cfg := providerConfig + `
data "ciphertrust_cm_local_ca_list" "test" {}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
			},
			{
				Config:             cfg,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_LocalCAList_FilterByName verifies a filtered query returns exactly one result
// matching the given CA name. Requires env var CIPHERTRUST_CM_LOCAL_CA_NAME.
func Test_CM_LocalCAList_FilterByName(t *testing.T) {
	RequireCM(t)

	caName := os.Getenv("CIPHERTRUST_CM_LOCAL_CA_NAME")
	if caName == "" {
		t.Skip("CIPHERTRUST_CM_LOCAL_CA_NAME not set")
	}

	cfg := providerConfig + fmt.Sprintf(`
data "ciphertrust_cm_local_ca_list" "test" {
  filters = { name = %q }
}
`, caName)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "FilterByName",
					resource.TestCheckResourceAttr("data.ciphertrust_cm_local_ca_list.test", "cas.#", "1"),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_local_ca_list.test", "cas.0.name", caName),
				),
			},
		},
	})
}
