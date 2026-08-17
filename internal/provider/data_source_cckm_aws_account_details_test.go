package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSDataSourceAccountDetails(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip()
	}
	accountDetailsDataConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
		  name = "tf-test-%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
		  connection_id = ciphertrust_aws_connection.aws_connection.id
		}`
	invalidConnectionConfig := `
		data "ciphertrust_aws_account_details" "bad_connection" {
			connection_id = "00000000-0000-0000-0000-000000000000"
		}`
	datasourceName := "data.ciphertrust_aws_account_details.account_details"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { cleanupCckmAwsKMS() },
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(accountDetailsDataConfig, uuid.New().String()[:8]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(datasourceName, "account_id"),
					resource.TestCheckResourceAttrSet(datasourceName, "regions.0"),
				),
			},
			{
				// An invalid connection ID must cause an error rather than returning empty results.
				Config:      invalidConnectionConfig,
				ExpectError: regexp.MustCompile("."),
			},
		},
	})
}

func TestCckmAWSDataSourceAccountDetailsCreateValidation(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// empty connection_id must be rejected at plan time
				Config: `
					data "ciphertrust_aws_account_details" "test" {
						connection_id = ""
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
			{
				// whitespace-only connection_id must be rejected at plan time
				Config: `
					data "ciphertrust_aws_account_details" "test" {
						connection_id = "   "
					}`,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile("non-whitespace"),
			},
		},
	})
}
