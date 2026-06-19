package provider

import (
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

// skipIfNoAWSCreds skips the test when the required AWS credentials are not set.
// The CM API requires access_key_id and secret_access_key to create an AWS connection.
func skipIfNoAWSCreds(t *testing.T) {
	t.Helper()
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("Skipping: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set")
	}
}

// awsConnTestConfig returns HCL for a ciphertrust_aws_connection resource using
// credentials from environment variables. Extra is appended inside the resource block.
func awsConnTestConfig(name, extra string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
  %s
}
`, name, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"), extra)
}

// TestAccAWSConnection_UpdateDescription verifies that updating the description of an
// AWS connection succeeds (no 422/400) and that the resource ID is not overwritten with
// a timestamp after the update.
func TestAccAWSConnection_UpdateDescription(t *testing.T) {
	RequireCM(t)
	skipIfNoAWSCreds(t)

	name := "tf-" + uuid.New().String()[:8]
	createCfg := awsConnTestConfig(name, `description = "initial description"`)
	updateCfg := awsConnTestConfig(name, `description = "updated description"`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "initial description"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
				),
			},
			{
				Config: updateCfg,
				Check: checkStep(t, "update description",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "updated description"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
				),
			},
		},
	})
}

// TestAccAWSConnection_NameRequiresReplace verifies that attempting to change the name
// of an AWS connection after creation produces a clear provider error at plan time.
func TestAccAWSConnection_NameRequiresReplace(t *testing.T) {
	RequireCM(t)
	skipIfNoAWSCreds(t)

	name := "tf-" + uuid.New().String()[:8]
	createCfg := awsConnTestConfig(name, "")
	renameCfg := awsConnTestConfig(name+"-renamed", "")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "name", name),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
				),
			},
			{
				Config:      renameCfg,
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`Connection name cannot be changed`),
			},
		},
	})
}

// TestAccAWSConnection_UpdateLabelsAndMeta verifies that updating labels and meta
// on an AWS connection succeeds without returning 400 or 422.
func TestAccAWSConnection_UpdateLabelsAndMeta(t *testing.T) {
	RequireCM(t)
	skipIfNoAWSCreds(t)

	name := "tf-" + uuid.New().String()[:8]
	createCfg := awsConnTestConfig(name, `
  labels = { "env" = "test" }
  meta   = { "owner" = "qa" }`)
	updateCfg := awsConnTestConfig(name, `
  labels = { "env" = "prod" }
  meta   = { "owner" = "sre" }`)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: createCfg,
				Check: checkStep(t, "create with labels/meta",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "labels.env", "test"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "meta.owner", "qa"),
				),
			},
			{
				Config: updateCfg,
				Check: checkStep(t, "update labels/meta",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "labels.env", "prod"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "meta.owner", "sre"),
				),
			},
		},
	})
}

// TestAccAWSConnection_CreateWithIsRoleAnywhere verifies that creating an AWS connection
// with is_role_anywhere=true sends the flag in the POST body. Requires additional env vars
// for IAM Anywhere credentials; the test is skipped when they are absent.
func TestAccAWSConnection_CreateWithIsRoleAnywhere(t *testing.T) {
	RequireCM(t)

	for _, v := range []string{
		"AWS_ROLE_ANYWHERE_ROLE_ARN",
		"AWS_ROLE_ANYWHERE_PROFILE_ARN",
		"AWS_ROLE_ANYWHERE_TRUST_ANCHOR_ARN",
		"AWS_ROLE_ANYWHERE_CERT",
	} {
		if os.Getenv(v) == "" {
			t.Skipf("requires %s env var", v)
		}
	}

	name := "tf-" + uuid.New().String()[:8]
	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name             = %q
  is_role_anywhere = true
  iam_role_anywhere {
    anywhere_role_arn  = %q
    profile_arn        = %q
    trust_anchor_arn   = %q
    certificate        = %q
  }
}
`,
		name,
		os.Getenv("AWS_ROLE_ANYWHERE_ROLE_ARN"),
		os.Getenv("AWS_ROLE_ANYWHERE_PROFILE_ARN"),
		os.Getenv("AWS_ROLE_ANYWHERE_TRUST_ANCHOR_ARN"),
		os.Getenv("AWS_ROLE_ANYWHERE_CERT"),
	)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "create with is_role_anywhere",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "is_role_anywhere", "true"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
				),
			},
		},
	})
}
