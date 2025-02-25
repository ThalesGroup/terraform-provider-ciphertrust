package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCiphertrustCMPrometheusDataSource(t *testing.T) {
	// Config for the resource and data source
	cmEnablePrometheusConfig := `
		resource "ciphertrust_cm_prometheus" "cm_prometheus" {
		  enabled = true
		}

		data "ciphertrust_cm_prometheus_status" "status" {
			depends_on = [ciphertrust_cm_prometheus.cm_prometheus]
		}`

	cmDisablePrometheusConfig := `
		resource "ciphertrust_cm_prometheus" "cm_prometheus" {
		  enabled = false
		}

		data "ciphertrust_cm_prometheus_status" "status" {
			depends_on = [ciphertrust_cm_prometheus.cm_prometheus]
		}`

	datasourceName := "data.ciphertrust_cm_prometheus_status.status"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cmEnablePrometheusConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, "enabled", "true"),
				),
			},
		},
	})
	// test case for disable scenario
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + cmDisablePrometheusConfig,
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(datasourceName, "enabled", "false"),
				),
			},
		},
	})
}
