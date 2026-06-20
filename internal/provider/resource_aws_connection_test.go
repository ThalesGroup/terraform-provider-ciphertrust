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

// awsConnectionConfig returns the HCL for a minimal ciphertrust_aws_connection.
// Credentials come from environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
// so no secrets are hardcoded in source.
func awsConnectionConfig(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
}
`, name, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"))
}

// requireAWSCreds skips the calling test if AWS credentials are not set.
func requireAWSCreds(t *testing.T) {
	t.Helper()
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("skipping: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}
}

// TestAccAWSConnection_drift verifies that Read() surfaces an out-of-band change
// to the description field as a non-empty plan (drift detection).
func TestAccAWSConnection_drift(t *testing.T) {
	RequireCM(t)
	requireAWSCreds(t)
	name := "TFTestAWSConn-drift-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
  description       = "original"
}
`, name, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")),
				Check: checkStep(t, "drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "original"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_aws_connection.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Patch description out-of-band; Read() must surface the drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					patch := []byte(`{"description":"out-of-band modified"}`)
					_, _ = client.UpdateDataV2(context.Background(), capturedID, common.URL_AWS_CONNECTION, patch)
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccAWSConnection_updatePreservesID verifies that Update() preserves the resource UUID
// in state (regression for the UpdateData/updatedAt bug).
func TestAccAWSConnection_updatePreservesID(t *testing.T) {
	RequireCM(t)
	requireAWSCreds(t)
	name := "TFTestAWSConn-update-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
  description       = "before"
}
`, name, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")),
				Check: checkStep(t, "update preserves ID: create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_aws_connection.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Update description; the UUID stored in id must be unchanged.
				Config: providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
  description       = "after"
}
`, name, os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY")),
				Check: checkStep(t, "update preserves ID: after update",
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_aws_connection.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						if rs.Primary.ID != capturedID {
							return fmt.Errorf("ID changed after update: was %q, now %q", capturedID, rs.Primary.ID)
						}
						return nil
					},
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "after"),
				),
			},
		},
	})
}

// TestAccAWSConnection_deleteOOB verifies that Read() handles a 404 cleanly when the
// connection has been deleted out-of-band (RemoveResource path).
func TestAccAWSConnection_deleteOOB(t *testing.T) {
	RequireCM(t)
	requireAWSCreds(t)
	name := "TFTestAWSConn-oob-" + uuid.New().String()[:8]
	var capturedID string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionConfig(name),
				Check: checkStep(t, "oob delete: create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["ciphertrust_aws_connection.test"]
						if !ok {
							return fmt.Errorf("resource not found in state")
						}
						capturedID = rs.Primary.ID
						return nil
					},
				),
			},
			{
				// Delete the connection out-of-band; the next plan must show a diff (recreate)
				// without error, confirming the 404 path in Read() calls RemoveResource cleanly.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					url := fmt.Sprintf("%s/%s/%s", client.CipherTrustURL, common.URL_AWS_CONNECTION, capturedID)
					_, _ = client.DeleteByID(context.Background(), "DELETE", capturedID, url, nil)
				},
				Config:             awsConnectionConfig(name),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// TestAccAWSConnection_writeOnlyFieldsNotDrifted verifies that secret_access_key (write-only)
// is not surfaced as drift after a plan refresh.
func TestAccAWSConnection_writeOnlyFieldsNotDrifted(t *testing.T) {
	RequireCM(t)
	requireAWSCreds(t)
	name := "TFTestAWSConn-writeonly-" + uuid.New().String()[:8]

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnectionConfig(name),
				Check: checkStep(t, "write-only no drift: create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
				),
			},
			{
				// Refresh state; secret_access_key must remain stable (preserved from prior state),
				// producing no diff despite the CM API never returning it.
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}
