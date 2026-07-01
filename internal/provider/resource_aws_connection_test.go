package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// awsAccessKeyID returns the AWS access key ID for acceptance tests.
// Reads from the environment variable; falls back to the well-known placeholder
// value from AWS documentation when the env var is not set.
func awsAccessKeyID() string {
	if v := os.Getenv("AWS_ACCESS_KEY_ID"); v != "" {
		return v
	}
	return "AKIAIOSFODNN7EXAMPLE"
}

// awsSecretAccessKey returns the AWS secret access key for acceptance tests.
// Reads from the environment variable; falls back to the well-known placeholder
// value from AWS documentation when the env var is not set.
func awsSecretAccessKey() string {
	if v := os.Getenv("AWS_SECRET_ACCESS_KEY"); v != "" {
		return v
	}
	return "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

// awsConnConfig returns a minimal ciphertrust_aws_connection config.
func awsConnConfig(name, description string) string {
	cfg := fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
`, name, awsAccessKeyID(), awsSecretAccessKey())
	if description != "" {
		cfg += fmt.Sprintf("  description = %q\n", description)
	}
	cfg += "}\n"
	return providerConfig + cfg
}

func awsConnConfigWithScalars(name, region, cloudName string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
  aws_region        = %q
  cloud_name        = %q
}
`, name, awsAccessKeyID(), awsSecretAccessKey(), region, cloudName)
}

func awsConnConfigWithMapList(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
  labels            = { env = "test" }
  meta              = { owner = "qa" }
  products          = ["cckm"]
}
`, name, awsAccessKeyID(), awsSecretAccessKey())
}

// deleteAWSConnection deletes an AWS connection by ID from CM, ignoring errors.
func deleteAWSConnection(id string) {
	client, ok := createCMClient()
	if !ok {
		return
	}
	_, _ = client.DeleteByID(
		context.Background(),
		"DELETE",
		id,
		fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_AWS_CONNECTION, id),
		nil,
	)
}

// TestAccAWSConnection_drift verifies that Read() surfaces an out-of-band
// description change as drift.
func TestAccAWSConnection_drift(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-drift-" + suffix
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnConfig(name, "initial"),
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "initial"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_aws_connection.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band description change; next plan should detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload := []byte(`{"description":"out-of-band-changed"}`)
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_AWS_CONNECTION,
						patchPayload,
						"id",
					)
				},
				Config:             awsConnConfig(name, "initial"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccAWSConnection_driftScalars verifies drift detection for Optional scalar
// fields: aws_region and cloud_name.
func TestAccAWSConnection_driftScalars(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-scalar-" + suffix
	var capturedID string

	cfg := awsConnConfigWithScalars(name, "us-east-1", "aws")

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "scalar drift: create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "aws_region", "us-east-1"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "cloud_name", "aws"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_aws_connection.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change to aws_region; next plan should detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload := []byte(`{"aws_region":"us-west-2"}`)
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_AWS_CONNECTION,
						patchPayload,
						"id",
					)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccAWSConnection_driftMapAndList verifies drift detection for labels, meta,
// and products.
func TestAccAWSConnection_driftMapAndList(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-maplist-" + suffix
	var capturedID string

	cfg := awsConnConfigWithMapList(name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "map/list drift: create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "labels.env", "test"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "meta.owner", "qa"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_aws_connection.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change to labels; next plan should detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload := []byte(`{"labels":{"env":"changed"}}`)
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_AWS_CONNECTION,
						patchPayload,
						"id",
					)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccAWSConnection_driftIAMRoleAnywhere verifies drift detection for
// iam_role_anywhere readable sub-fields. Skipped if IAM Anywhere env vars
// are not set.
func TestAccAWSConnection_driftIAMRoleAnywhere(t *testing.T) {
	RequireCM(t)

	anywhereRoleARN := os.Getenv("CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN")
	trustAnchorARN := os.Getenv("CIPHERTRUST_AWS_TRUST_ANCHOR_ARN")
	profileARN := os.Getenv("CIPHERTRUST_AWS_PROFILE_ARN")
	certificate := os.Getenv("CIPHERTRUST_AWS_CERTIFICATE")
	if anywhereRoleARN == "" || trustAnchorARN == "" || profileARN == "" || certificate == "" {
		t.Skip("skipping TestAccAWSConnection_driftIAMRoleAnywhere: CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN, CIPHERTRUST_AWS_TRUST_ANCHOR_ARN, CIPHERTRUST_AWS_PROFILE_ARN, and CIPHERTRUST_AWS_CERTIFICATE must be set")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-iam-" + suffix
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name             = %q
  is_role_anywhere = true
  iam_role_anywhere {
    anywhere_role_arn = %q
    trust_anchor_arn  = %q
    profile_arn       = %q
    certificate       = %q
  }
}
`, name, anywhereRoleARN, trustAnchorARN, profileARN, certificate)

	altRoleARN := anywhereRoleARN + "-changed"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "iam anywhere drift: create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "name", name),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_aws_connection.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Out-of-band change to anywhere_role_arn; next plan should detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patchPayload := []byte(fmt.Sprintf(`{"iam_role_anywhere":{"anywhere_role_arn":%q}}`, altRoleARN))
					_, _ = client.UpdateData(
						context.Background(),
						capturedID,
						common.URL_AWS_CONNECTION,
						patchPayload,
						"id",
					)
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccAWSConnection_outOfBandDelete verifies that Read() removes the resource
// from state on 404, and that Delete() 404-guards the test teardown.
func TestAccAWSConnection_outOfBandDelete(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-oob-del-" + suffix
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnConfig(name, ""),
				Check: checkStep(t, "out-of-band delete: create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_aws_connection.test"].Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the connection out-of-band; Read() must detect the 404 and mark for re-creation.
				PreConfig:          func() { deleteAWSConnection(capturedID) },
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccAWSConnection_immutableName verifies that changing `name` raises a
// plan-time error from NameImmutableModifier, not a destroy+recreate diff.
func TestAccAWSConnection_immutableName(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	original := "tf-acc-aws-orig-" + suffix
	changed := "tf-acc-aws-chgd-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnConfig(original, ""),
				Check: checkStep(t, "immutable name: create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "name", original),
				),
			},
			{
				Config:      awsConnConfig(changed, ""),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// awsConnConfigNoCredentials returns a ciphertrust_aws_connection config that
// deliberately omits access_key_id and secret_access_key from HCL, relying on
// the backwards-compatibility env-var fallback in Create().
func awsConnConfigNoCredentials(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name = %q
}
`, name)
}

// TestAccAWSConnection_envVarFallbackWritesToState verifies that when
// access_key_id and secret_access_key are omitted from HCL config and supplied
// via AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY environment variables, the
// Create() function writes the resolved values into Terraform state so that
// subsequent plans are idempotent (no perpetual diff).
func TestAccAWSConnection_envVarFallbackWritesToState(t *testing.T) {
	RequireCM(t)
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("skipping TestAccAWSConnection_envVarFallbackWritesToState: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-envvar-" + suffix
	cfg := awsConnConfigNoCredentials(name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				// Create with no credentials in HCL; env-var fallback should supply them.
				Config: cfg,
				Check: checkStep(t, "env-var fallback: create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					// Both credential fields must be non-null in state after Create().
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "access_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "secret_access_key"),
				),
			},
			{
				// Second plan with identical config must produce no diff (idempotency).
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// TestAccAWSConnection_updateComputedFields verifies that Computed fields are
// refreshed from CM in state after an in-Terraform update, and that Update()
// does not corrupt the resource ID.
func TestAccAWSConnection_updateComputedFields(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-upd-" + suffix
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnConfig(name, "v1"),
				Check: checkStep(t, "update computed: create",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "v1"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "updated_at"),
					func(s *terraform.State) error {
						capturedID = s.RootModule().Resources["ciphertrust_aws_connection.test"].Primary.ID
						return nil
					},
				),
			},
			{
				Config: awsConnConfig(name, "v2"),
				Check: checkStep(t, "update computed: after update",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "v2"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "updated_at"),
					func(s *terraform.State) error {
						id := s.RootModule().Resources["ciphertrust_aws_connection.test"].Primary.ID
						if id != capturedID {
							return fmt.Errorf("resource ID changed after update: was %q, now %q", capturedID, id)
						}
						return nil
					},
				),
			},
		},
	})
}
