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
						t.Logf("CM client unavailable")
						return
					}
					payloadJSON, err := json.Marshal(map[string]string{"value": "true"})
					if err != nil {
						t.Logf("failed to marshal payload: %v", err)
						return
					}
					_, err = client.UpdateDataFullURL(
						ctx,
						corrID,
						common.URL_CM_PROPERTIES+"/"+propertyName,
						payloadJSON,
						"name",
					)
					if err != nil {
						t.Logf("out-of-band update failed: %v", err)
						return
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
						t.Logf("CM client unavailable")
						return
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

func Test_CM_Property_EmptyNameRejected(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = ""
  value = "true"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("string length must be at least 1"),
			},
		},
	})
}

func Test_CM_Property_EmptyValueRejected(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ENABLE_REST_CRYPTO_RECORDS"
  value = ""
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("string length must be at least 1"),
			},
		},
	})
}

func Test_CM_Property_NullValueReset(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: apply with explicit value
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ENABLE_REST_CRYPTO_RECORDS"
  value = "true"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "true"),
			},
			// Step 2: omit value — triggers /reset
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name = "ENABLE_REST_CRYPTO_RECORDS"
}
`,
				Check: resource.TestCheckNoResourceAttr("ciphertrust_property.test", "value"),
			},
			// Step 3: refresh-only after reset — state stays null, no diff
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
			// Step 4: restore explicit value
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ENABLE_REST_CRYPTO_RECORDS"
  value = "true"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "true"),
			},
		},
	})
}

func Test_CM_Property_UpdateValue(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ENABLE_REST_CRYPTO_RECORDS"
  value = "true"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "true"),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ENABLE_REST_CRYPTO_RECORDS"
  value = "false"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "false"),
			},
		},
	})
}

func Test_CM_Property_ValueDrift(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: apply with explicit value
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ENABLE_REST_CRYPTO_RECORDS"
  value = "true"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "true"),
			},
			// Step 2: simulate out-of-band change, then refresh to detect drift
			{
				PreConfig: func() {
					ctx := context.Background()
					client, ok := createCMClient()
					if !ok {
						t.Logf("CM client unavailable — skipping drift simulation")
						return
					}
					payload := []byte(`{"value":"false"}`)
					_, err := client.UpdateDataFullURL(
						ctx,
						"drift-setup",
						common.URL_CM_PROPERTIES+"/ENABLE_REST_CRYPTO_RECORDS",
						payload,
						"name",
					)
					if err != nil {
						t.Logf("PreConfig: failed to set CM property out-of-band: %v", err)
						return
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			// Step 3: reconcile — re-apply to restore CM state
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
  name  = "ENABLE_REST_CRYPTO_RECORDS"
  value = "true"
}
`,
				Check: resource.TestCheckResourceAttr("ciphertrust_property.test", "value", "true"),
			},
		},
	})
}

func Test_CM_Property_ImmutableName(t *testing.T) {
	RequireCM(t)
	t.Cleanup(func() {
		client, ok := createCMClient()
		if !ok {
			return
		}
		ctx := context.Background()
		traceID := uuid.New().String()
		var payload []byte
		_, _ = client.PostDataV2(ctx, traceID,
			common.URL_CM_PROPERTIES+"/ALLOW_UNKNOWN_FIELDS/reset", payload)
	})
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
    name  = "ALLOW_UNKNOWN_FIELDS"
    value = "false"
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_property.test", "name", "ALLOW_UNKNOWN_FIELDS"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_property" "test" {
    name  = "ALLOW_CERT_KEY_USAGE_VALIDATION"
    value = "false"
}
`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("(?i)immutable"),
			},
		},
	})
}
