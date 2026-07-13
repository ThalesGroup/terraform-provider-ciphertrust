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

func Test_CM_ResourceCMProperty(t *testing.T) {
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

// TestCMPropertyCreateAndUpdate is blocked pending confirmation of a valid writable
// CM system property name and values from a live CM instance.
// Uncomment and fill in propertyName, initialValue, updatedValue before activating.
// Note: "ALLOW_UNKNOWN_FIELDS" with values "false"/"true" is a known working example
// (see Test_CM_ResourceCMProperty above).
//
// func TestCMPropertyCreateAndUpdate(t *testing.T) {
//     RequireCM(t)
//     const propertyName = "" // TODO: confirm from live CM (e.g. "ALLOW_UNKNOWN_FIELDS")
//     const initialValue = "" // TODO: confirm from live CM (e.g. "false")
//     const updatedValue = "" // TODO: confirm from live CM (e.g. "true")
//     resource.Test(t, resource.TestCase{
//         ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
//         Steps: []resource.TestStep{
//             {
//                 Config: fmt.Sprintf(providerConfig+`resource "ciphertrust_property" "test" {
//                     name  = %q
//                     value = %q
//                 }`, propertyName, initialValue),
//                 Check: checkStep(t, "create",
//                     resource.TestCheckResourceAttr("ciphertrust_property.test", "name", propertyName),
//                     resource.TestCheckResourceAttr("ciphertrust_property.test", "value", initialValue),
//                     resource.TestCheckResourceAttrSet("ciphertrust_property.test", "description"),
//                 ),
//             },
//             {
//                 Config: fmt.Sprintf(providerConfig+`resource "ciphertrust_property" "test" {
//                     name  = %q
//                     value = %q
//                 }`, propertyName, updatedValue),
//                 Check: checkStep(t, "update",
//                     resource.TestCheckResourceAttr("ciphertrust_property.test", "value", updatedValue),
//                     resource.TestCheckResourceAttrSet("ciphertrust_property.test", "description"),
//                 ),
//             },
//         },
//     })
// }

func Test_CM_AccCipherTrustProperty_drift(t *testing.T) {
	RequireCM(t)
	const propertyName = "ALLOW_UNKNOWN_FIELDS"

	config := providerConfig + `
resource "ciphertrust_property" "test_drift" {
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
					resource.TestCheckResourceAttr("ciphertrust_property.test_drift", "value", "false"),
					resource.TestCheckResourceAttrSet("ciphertrust_property.test_drift", "description"),
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

func Test_CM_AccCipherTrustProperty_basicApplyNoDrift(t *testing.T) {
	RequireCM(t)
	const propertyName = "ALLOW_UNKNOWN_FIELDS"

	config := providerConfig + `
resource "ciphertrust_property" "test_no_drift" {
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
					resource.TestCheckResourceAttrSet("ciphertrust_property.test_no_drift", "description"),
					resource.TestCheckResourceAttr("ciphertrust_property.test_no_drift", "value", "false"),
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

func Test_CM_AccCipherTrustProperty_destroyOutOfBand(t *testing.T) {
	RequireCM(t)
	const propertyName = "ALLOW_UNKNOWN_FIELDS"

	config := providerConfig + `
resource "ciphertrust_property" "test_oob_destroy" {
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
					resource.TestCheckResourceAttr("ciphertrust_property.test_oob_destroy", "value", "true"),
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
				Config: config,
				Destroy: true,
			},
		},
	})
}
