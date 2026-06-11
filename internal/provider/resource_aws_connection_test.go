package provider

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

const awsConnectionResourceName = "ciphertrust_aws_connection.aws_connection"

func awsConnectionConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "aws_connection" {
  name              = %q
  cloud_name        = "aws"
  access_key_id     = %q
  secret_access_key = %q
  description       = "test AWS connection for drift detection"
}
`, name, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}

func TestAccAWSConnection_OOBDelete(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for this test")
	}
	var capturedID string
	connName := "TFTestAWSConnOOB"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionConfig(connName),
				Check: checkStep(t, "oob delete: create",
					resource.TestCheckResourceAttrSet(awsConnectionResourceName, "id"),
					resource.TestCheckResourceAttr(awsConnectionResourceName, "name", connName),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[awsConnectionResourceName]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion; Read() should remove from state and next plan proposes re-create.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_AWS_CONNECTION+"/"+capturedID,
					)
				},
				Config:             awsConnectionConfig(connName),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAccAWSConnection_DeleteOOBThenDestroy(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for this test")
	}
	var capturedID string
	connName := "TFTestAWSConnOOBDestroy"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionConfig(connName),
				Check: checkStep(t, "oob destroy: create",
					resource.TestCheckResourceAttrSet(awsConnectionResourceName, "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources[awsConnectionResourceName]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band deletion followed by terraform destroy: Delete() 404 guard must suppress error.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.DeleteByURL(
						context.Background(),
						uuid.NewString(),
						common.URL_AWS_CONNECTION+"/"+capturedID,
					)
				},
				Config:  awsConnectionConfig(connName),
				Destroy: true,
			},
		},
	})
}
