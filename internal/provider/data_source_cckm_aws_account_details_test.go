package provider

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAwsDataSourceAccountDetails(t *testing.T) {
	accountDetailsDataConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
		  name = "tf-test-%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
		  aws_connection = ciphertrust_aws_connection.aws_connection.id
		}`
	datasourceName := "data.ciphertrust_aws_account_details.account_details"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(accountDetailsDataConfig, uuid.New().String()[:8]),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrSet(datasourceName, "account_id"),
				),
			},
		},
	})
}
