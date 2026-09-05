package provider

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// awsConnListConfig generates HCL for n distinct ciphertrust_aws_connection resources
// plus an optional ciphertrust_aws_connection_list data source block.
func awsConnListConfig(namePrefix string, count int, filters string) string {
	cfg := providerConfig
	for i := 0; i < count; i++ {
		cfg += fmt.Sprintf(`
resource "ciphertrust_aws_connection" "conn%d" {
  name          = %q
  access_key_id = %q
}
`, i, fmt.Sprintf("%s-%d", namePrefix, i), awsAccessKeyID())
	}

	// Build depends_on from all connection resource references.
	deps := ""
	for i := 0; i < count; i++ {
		if i > 0 {
			deps += ", "
		}
		deps += fmt.Sprintf("ciphertrust_aws_connection.conn%d", i)
	}

	if filters == "" {
		cfg += fmt.Sprintf(`
data "ciphertrust_aws_connection_list" "all" {
  depends_on = [%s]
}
`, deps)
	} else {
		cfg += fmt.Sprintf(`
data "ciphertrust_aws_connection_list" "all" {
  depends_on = [%s]
  filters = {
    %s
  }
}
`, deps, filters)
	}
	return cfg
}

// TestCckmAwsConnectionList_pagination verifies that ciphertrust_aws_connection_list
// returns all connections when more than one page (> 10) exist on CM.
func TestCckmAwsConnectionList_pagination(t *testing.T) {
	RequireCM(t)
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for this test")
	}

	namePrefix := "tftest-awslist-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnListConfig(namePrefix, 12, ""),
				Check: resource.TestCheckResourceAttr(
					"data.ciphertrust_aws_connection_list.all", "aws.#", "12",
				),
			},
		},
	})
}

// TestCckmAwsConnectionList_singlePage verifies that passing skip/limit in filters
// invokes the single-page branch and returns exactly the requested count.
func TestCckmAwsConnectionList_singlePage(t *testing.T) {
	RequireCM(t)
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for this test")
	}

	namePrefix := "tftest-awslist-sp-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnListConfig(namePrefix, 3, `skip = "0"
    limit = "1"`),
				Check: resource.TestCheckResourceAttr(
					"data.ciphertrust_aws_connection_list.all", "aws.#", "1",
				),
			},
		},
	})
}
