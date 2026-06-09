package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

const cmGroupResource = "ciphertrust_cm_group.test"

func TestAccCMGroup_CreateReadIdempotent(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_group" "test" {
  name = "TFAccGroupIdempotent"
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr(cmGroupResource, "name", "TFAccGroupIdempotent"),
					resource.TestCheckResourceAttrSet(cmGroupResource, "id"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_cm_group" "test" {
  name = "TFAccGroupIdempotent"
}
`,
				PlanOnly: true,
			},
		},
	})
}

func TestAccCMGroup_OutOfBandDelete(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("CIPHERTRUST_ADDRESS / CIPHERTRUST_USERNAME / CIPHERTRUST_PASSWORD not set; skipping drift test")
	}

	const groupName = "TFAccGroupOOBDelete"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_group" "test" {
  name = %q
}
`, groupName),
				Check: checkStep(t, "create before out-of-band delete",
					resource.TestCheckResourceAttr(cmGroupResource, "name", groupName),
				),
			},
			{
				PreConfig: func() {
					deleteURL := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_CM_GROUPS, groupName)
					_, _ = client.DeleteByID(context.Background(), "DELETE", groupName, deleteURL, nil)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCMGroup_AttributeDrift(t *testing.T) {
	client, ok := createCMClient()
	if !ok {
		t.Skip("CIPHERTRUST_ADDRESS / CIPHERTRUST_USERNAME / CIPHERTRUST_PASSWORD not set; skipping drift test")
	}

	const groupName = "TFAccGroupAttrDrift"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_group" "test" {
  name        = %q
  description = "original"
}
`, groupName),
				Check: checkStep(t, "create with original description",
					resource.TestCheckResourceAttr(cmGroupResource, "description", "original"),
				),
			},
			{
				PreConfig: func() {
					payload, _ := json.Marshal(map[string]string{"description": "drift-modified"})
					_, _ = client.UpdateData(context.Background(), groupName, common.URL_CM_GROUPS, payload, "name")
				},
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_cm_group" "test" {
  name        = %q
  description = "original"
}
`, groupName),
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCMGroup_Import(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_group" "test" {
  name        = "TFAccGroupImport"
  description = "import test group"
}
`,
				Check: checkStep(t, "create before import",
					resource.TestCheckResourceAttr(cmGroupResource, "name", "TFAccGroupImport"),
					resource.TestCheckResourceAttr(cmGroupResource, "description", "import test group"),
				),
			},
			{
				ResourceName:      cmGroupResource,
				ImportState:       true,
				ImportStateVerify: true,
				ImportStateIdFunc: getResourceAttr(cmGroupResource, "id"),
			},
		},
	})
}

func TestAccCMGroup_UpdateInPlace(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_group" "test" {
  name        = "TFAccGroupUpdate"
  description = "initial description"
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr(cmGroupResource, "description", "initial description"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_cm_group" "test" {
  name        = "TFAccGroupUpdate"
  description = "updated description"
}
`,
				Check: checkStep(t, "update description",
					resource.TestCheckResourceAttr(cmGroupResource, "name", "TFAccGroupUpdate"),
					resource.TestCheckResourceAttr(cmGroupResource, "description", "updated description"),
				),
			},
		},
	})
}

func TestAccCMGroup_InvalidConfig(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_group" "test" {
}
`,
				ExpectError: regexp.MustCompile(`The argument "name" is required`),
			},
		},
	})
}
