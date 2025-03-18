package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCiphertrustCMPrometheusDataSource(t *testing.T) {
	address := os.Getenv("CIPHERTRUST_ADDRESS")
	username := os.Getenv("CIPHERTRUST_USERNAME")
	password := os.Getenv("CIPHERTRUST_PASSWORD")
	bootstrap := "no"

	if address == "" || username == "" || password == "" {
		t.Fatal("CIPHERTRUST_ADDRESS, CIPHERTRUST_USERNAME, and CIPHERTRUST_PASSWORD must be set for testing")
	}

	providerConfig := fmt.Sprintf(providerConfig, address, username, password, bootstrap)

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
