package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const testGroupName = "TFTestGroup"

func cmGroupConfig(name, description, appMeta string) string {
	cfg := fmt.Sprintf(`
resource "ciphertrust_groups" "testGroup" {
  name = %q
`, name)
	if description != "" {
		cfg += fmt.Sprintf("  description = %q\n", description)
	}
	if appMeta != "" {
		cfg += fmt.Sprintf("  app_metadata = %q\n", appMeta)
	}
	cfg += "}\n"
	return providerConfig + cfg
}

func TestAccCMGroup_basicCreate(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig(testGroupName, "Created via TF", `{"env":"test"}`),
				Check: checkStep(t, "basic create",
				resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "id"),
				resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "name", testGroupName),
				resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "Created via TF"),
				resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "app_metadata"),
				),
			},
			// Verify no drift on a subsequent plan.
			{
				Config:             cmGroupConfig(testGroupName, "Created via TF", `{"env":"test"}`),
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCMGroup_driftDetection(t *testing.T) {
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig(testGroupName+"Drift", "Drift test", ""),
			Check: checkStep(t, "drift detection: create",
				resource.TestCheckResourceAttrSet("ciphertrust_groups.testGroup", "id"),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources["ciphertrust_groups.testGroup"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion; next plan should detect drift and recreate.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_GROUP+"/"+capturedID,
					)
				},
				Config:             cmGroupConfig(testGroupName+"Drift", "Drift test", ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCMGroup_RenameError(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig("TFTestGroupRename", "Rename test", ""),
				Check: resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "name", "TFTestGroupRename"),
			},
			{
				Config:      cmGroupConfig("TFTestGroupRenameNew", "Rename test", ""),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("Attribute 'name' cannot be changed after creation"),
			},
		},
	})
}

func TestAccCMGroup_UpdateInPlace(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig("TFTestGroupInplace", "initial", ""),
				Check: resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "initial"),
			},
			{
				Config: cmGroupConfig("TFTestGroupInplace", "updated", ""),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "updated"),
					resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "name", "TFTestGroupInplace"),
				),
			},
		},
	})
}

func TestAccCMGroup_attributeDrift(t *testing.T) {
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cmGroupConfig(testGroupName+"AttrDrift", "Original description", ""),
			Check: checkStep(t, "attribute drift: create",
				resource.TestCheckResourceAttr("ciphertrust_groups.testGroup", "description", "Original description"),
				func(s *terraform.State) error {
					rs, ok := s.RootModule().Resources["ciphertrust_groups.testGroup"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band description change; next plan should detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload := []byte(`{"description":"Out-of-band modified"}`)
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_GROUP,
						patchPayload,
						"name",
					)
				},
				Config:             cmGroupConfig(testGroupName+"AttrDrift", "Original description", ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}
