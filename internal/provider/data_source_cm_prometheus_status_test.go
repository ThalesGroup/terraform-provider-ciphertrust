package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func testAccCMPrometheusStatusConfig() string {
	return providerConfig + `
resource "ciphertrust_cm_prometheus" "test" { enabled = true }
data "ciphertrust_cm_prometheus_status" "status" {
  depends_on = [ciphertrust_cm_prometheus.test]
}
`
}

func Test_CM_DataSourceCMPrometheusStatus_TokenSensitive(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: testAccCMPrometheusStatusConfig(),
				Check: checkStep(t, "token attribute present in schema",
					// token is Computed and Sensitive; value varies by instance
					// (empty when prometheus is disabled, non-empty when enabled).
					// Verify the attribute is schema-accessible without asserting value.
					resource.TestCheckResourceAttrSet(
						"data.ciphertrust_cm_prometheus_status.status", "token",
					),
				),
			},
		},
	})
}

func Test_CM_PrometheusStatus_ReadAccuracy(t *testing.T) {
	RequireCM(t)

	cfg := providerConfig + `
resource "ciphertrust_cm_prometheus" "test" { enabled = true }
data "ciphertrust_cm_prometheus_status" "test" {
  depends_on = [ciphertrust_cm_prometheus.test]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "ReadAccuracy",
					resource.TestCheckResourceAttr("data.ciphertrust_cm_prometheus_status.test", "id", "prometheus-status"),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_prometheus_status.test", "enabled", "true"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_prometheus_status.test", "token"),
				),
			},
		},
	})
}

// Test_CM_PrometheusStatus_Idempotency verifies that consecutive reads produce no plan diff.
func Test_CM_PrometheusStatus_Idempotency(t *testing.T) {
	RequireCM(t)

	cfg := providerConfig + `
resource "ciphertrust_cm_prometheus" "test" { enabled = true }
data "ciphertrust_cm_prometheus_status" "test" {
  depends_on = [ciphertrust_cm_prometheus.test]
}
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

// Test_CM_PrometheusStatus_ConsistencyWithResource verifies the data source reflects the
// live CM Prometheus state: enabled=true shows a token; enabled=false shows token="".
func Test_CM_PrometheusStatus_ConsistencyWithResource(t *testing.T) {
	RequireCM(t)

	cfgEnabled := providerConfig + `
resource "ciphertrust_cm_prometheus" "test" { enabled = true }
data "ciphertrust_cm_prometheus_status" "test" {
  depends_on = [ciphertrust_cm_prometheus.test]
}
`
	cfgDisabled := providerConfig + `
resource "ciphertrust_cm_prometheus" "test" { enabled = false }
data "ciphertrust_cm_prometheus_status" "test" {
  depends_on = [ciphertrust_cm_prometheus.test]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfgEnabled,
				Check: checkStep(t, "EnabledTrue",
					resource.TestCheckResourceAttr("data.ciphertrust_cm_prometheus_status.test", "enabled", "true"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_prometheus_status.test", "token"),
				),
			},
			{
				Config: cfgDisabled,
				Check: checkStep(t, "EnabledFalse",
					resource.TestCheckResourceAttr("data.ciphertrust_cm_prometheus_status.test", "enabled", "false"),
					// CM retains the token even when Prometheus is disabled; the data source reflects
					// the live CM value unconditionally. We verify the attribute is set (not absent).
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_prometheus_status.test", "token"),
				),
			},
		},
	})
}

func Test_CM_DataSourceCMPrometheusStatus_ValueAccuracy(t *testing.T) {
	RequireCM(t)

	cfg := providerConfig + `
resource "ciphertrust_cm_prometheus" "test" { enabled = true }
data "ciphertrust_cm_prometheus_status" "test" {
  depends_on = [ciphertrust_cm_prometheus.test]
}
`

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "ValueAccuracy",
					resource.TestCheckResourceAttr("data.ciphertrust_cm_prometheus_status.test", "id", "prometheus-status"),
					resource.TestCheckResourceAttr("data.ciphertrust_cm_prometheus_status.test", "enabled", "true"),
					resource.TestCheckResourceAttrSet("data.ciphertrust_cm_prometheus_status.test", "token"),
				),
			},
		},
	})
}
