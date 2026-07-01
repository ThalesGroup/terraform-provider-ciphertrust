package provider

import (
	"context"
	"encoding/json"
	"regexp"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestResourceCMProperty(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "ALLOW_UNKNOWN_FIELDS"
    value = "false"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "false"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name = "ALLOW_UNKNOWN_FIELDS"
    value = "true"
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_property.property_1", "value", "true"),
				),
			},
			// Step 3: Attempt to rename — must fail at plan time with a clear error.
			{
				Config: providerConfig + `
resource "ciphertrust_property" "property_1" {
    name  = "ALLOW_UNKNOWN_FIELDS_RENAMED"
    value = "true"
}
`,
				ExpectError: regexp.MustCompile(`Name cannot be changed`),
				PlanOnly:    true,
			},
		},
		// Delete testing automatically occurs in TestCase
	})
}

func TestAccCipherTrustProperty_drift(t *testing.T) {
	RequireCM(t)
	const propertyName = "ALLOW_UNKNOWN_FIELDS"

	config := providerConfig + `
resource "ciphertrust_property" "test" {
    name  = "` + propertyName + `"
    value = "false"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "initial apply",
					resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "false"),
					resource.TestCheckResourceAttrSet("ciphertrust_property.test", "description"),
				),
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					corrID := uuid.New().String()
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					payloadJSON, err := json.Marshal(map[string]string{"value": "true"})
					if err != nil {
						t.Fatalf("failed to marshal payload: %v", err)
					}
					_, err = client.UpdateDataFullURL(
						ctx,
						corrID,
						common.URL_CM_PROPERTIES+"/"+propertyName,
						payloadJSON,
						"name",
					)
					if err != nil {
						t.Fatalf("out-of-band update failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccCipherTrustProperty_basicApplyNoDrift(t *testing.T) {
	RequireCM(t)
	const propertyName = "ALLOW_UNKNOWN_FIELDS"

	config := providerConfig + `
resource "ciphertrust_property" "test" {
    name  = "` + propertyName + `"
    value = "false"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "apply",
					resource.TestCheckResourceAttrSet("ciphertrust_property.test", "description"),
					resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "false"),
				),
			},
			{
				Config:             config,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

func TestAccCipherTrustProperty_destroyOutOfBand(t *testing.T) {
	RequireCM(t)
	const propertyName = "ALLOW_UNKNOWN_FIELDS"

	config := providerConfig + `
resource "ciphertrust_property" "test" {
    name  = "` + propertyName + `"
    value = "true"
}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: checkStep(t, "apply",
					resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "true"),
				),
			},
			{
				PreConfig: func() {
					ctx := context.Background()
					corrID := uuid.New().String()
					client, ok := createCMClient()
					if !ok {
						t.Skip("CM client unavailable")
					}
					_, _ = client.PostDataV2(
						ctx,
						corrID,
						common.URL_CM_PROPERTIES+"/"+propertyName+"/reset",
						nil,
					)
				},
				Config:  config,
				Destroy: true,
			},
		},
	})
}
