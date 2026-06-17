package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestCckmAWSDataSourceAccountDetails(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip()
	}
	// On CDSPaaS pipelines ambient AWS credentials are ECR-only (no EC2 permissions).
	// Skip unless CCKM_AWS_ACCOUNT_TEST=true is explicitly set to opt in.
	if os.Getenv(envCDSPaaS) == "true" && os.Getenv("CCKM_AWS_ACCOUNT_TEST") != "true" {
		t.Skip("skipping: CDSPaaS pipeline AWS credentials lack ec2:DescribeRegions; set CCKM_AWS_ACCOUNT_TEST=true to force")
	}
	accountDetailsDataConfig := `
		resource "ciphertrust_aws_connection" "aws_connection" {
		  name = "tf-test-%s"
		}
		data "ciphertrust_aws_account_details" "account_details" {
		  aws_connection = ciphertrust_aws_connection.aws_connection.id
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
		},
	})
}
