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

// testGetAWSAccessKeyID returns the AWS access key ID for create tests.
// Reads from TEST_AWS_ACCESS_KEY_ID; falls back to a clearly-fake placeholder
// that does not match GitHub's AKIA secret-scanning pattern.
func testGetAWSAccessKeyID() string {
	if v := os.Getenv("TEST_AWS_ACCESS_KEY_ID"); v != "" {
		return v
	}
	return "TESTACCESSKEYIDEXAMPLE"
}

// testGetAWSSecretAccessKey returns the AWS secret access key for create tests.
// Reads from TEST_AWS_SECRET_ACCESS_KEY; falls back to a clearly-fake placeholder.
func testGetAWSSecretAccessKey() string {
	if v := os.Getenv("TEST_AWS_SECRET_ACCESS_KEY"); v != "" {
		return v
	}
	return "TestFakeSecretAccessKeyForTestingOnlyXXXX"
}

const (

	testIAMAnywhereCert = `-----BEGIN CERTIFICATE-----
MIIFTzCCAzegAwIBAgIQZTREZhuT71nFpVShuW0pVTANBgkqhkiG9w0BAQsFADBa
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCVFgxDzANBgNVBAcTBkF1c3RpbjEPMA0G
A1UEChMGVGhhbGVzMRwwGgYDVQQDExNDaXBoZXJUcnVzdCBSb290IENBMB4XDTIz
MDMyMjA5MDY1NVoXDTMyMTIxNjEzMjEyOFowYTELMAkGA1UEBhMCVVMxCzAJBgNV
BAgTAk1EMRAwDgYDVQQHEwdCZWxjYW1wMRUwEwYDVQQKEwxUaGFsZXMgR3JvdXAx
DDAKBgNVBAsTA1JuRDEOMAwGA1UEAxMFYWRtaW4wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQD2COszQEX1HZbR6qMxmA/N7bvidDo1kpgCVqjN2hTjk5hh
SdurIudGxzW7JTJNf4adjYCibLNz+9QnmT/zWiOCgRIO1KIzK8Mh8V3BW/ZCin4Y
LqYswoNMQYEuVIRjU6Q7C+eSbAk82wIH+dkFJbTOerylKJ7QKYaikpjviwTLJM+K
thCfSaulsDU7qMOJMZqdgr5xDTcmVxFFXafqRMQgJjydT4IPr1ZtTapPIbJorjy/
alAvOkMjUBf7yDkGxZI48mKN4QX2V6wOcrPZBEVXWn3lHDt0zek8/k3oQt6wq20w
+zLyuopA6hbpkNInovu60nQvYwqVDcbwFkQ+k60tAgMBAAGjggEIMIIBBDAOBgNV
HQ8BAf8EBAMCA4gwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAf
BgNVHSMEGDAWgBRJtGj7rVwPDfLFgbU2wy3N4eIAGjBOBgNVHREERzBFghEqLnRo
YWxlc2dyb3VwLmNvbYIRKi50aGFsZXNncm91cC5uZXSBF2NvbnRhY3RAdGhhbGVz
Z3JvdXAuY29thwQBAQEBMF4GA1UdHwRXMFUwU6BRoE+GTWh0dHA6Ly9jaXBoZXJ0
cnVzdG1hbmFnZXIubG9jYWwvY3Jscy8zNjczNzgxNC1mYWMyLTQ4MGMtOGFlZi04
ZmY2MTA1YjljYWEuY3JsMA0GCSqGSIb3DQEBCwUAA4ICAQB8iJui2RGvhI7p4LVW
Qhz3k/FrzBXZBxJXnP6F+uczjgt4ML/FiAz4VuPRYnzHsfLh8ZkMvIdgGG4pDUt9
f8rgsvVETYwhzyFA6mjqVUzaDnfAR9Q9iGmZKh948DCebSi193G7qbqjiOFMPal9
OIlyoRGpSJ7vTFkbvnzNI0pZK9Wo+eR7XXuB2I8owYV4+3y8i0Otn+HqeCFpNPeh
Bw4d26KusdFRIJysdBs/6SuwaLamZ+Al5RYgbgEvcawCwKa8VqGCIiQDQA/1CBg8
SpuZLH5WtYrpos2cjbPqauZ9G0R0mLdEnmlpm8FCyPvWUAl9KgvgsQrnwVlDciiW
aX+0ZJtBWxlVGVUofNZX13+Z1DeYbJyHcjzfFyuu9kNUDbCjxnqirrSc+Jx10S4i
b+8wyz8/sX6TaZfknno2V9v5ETBUJxIFAKKEY9sBBqpkJL1hwcnBUhT5xjBqRQTX
nRvU+9WKnOto04MI1Zzb3kaRwBJi6KhY4Y1JMuApwRjKGGfsM3UkrN/WcconSa3i
oQZVRGw0Liu8W5OtyyQFhX8+qOilXOOEIIe7I4OF+Icfm4ftmryhqwFIOuhaqs0L
U5of3V2S+h2+Pknoo5by390lpzkvq9c7DEu0wzEyEZ5Pg1e4moOg49lfSVMoKi00
hsdrliuQ+mRB2RlHwskdaTW9oQ==
-----END CERTIFICATE-----`

	testIAMAnywherePrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA5Q0/50DPEc+ToVPT/aA+tQnWcThXma1X0cKXciwwCxAmNS6X
TzehzDjmnsdYoJV5S0aK2VNn0LBlGrsbPbQiYK9yQZ1pIh5i3vsXKr3JCotgLIw4
iyu4VFnwqqczMeyYr2Dv6G2UN44GUChqgP21cLrOE/YOF0THTxddeMvDAYpfVnJF
23sny83sCuYifg5Ektmi4JHrol1vj6sIbsEpB298EnWhemcTe1uZ5eor31iibKBI
OZJFd+Y6ZxZziofMC2NkCqGQdZqB/XJ+BxFpIwY72e3QgFRuR8dyDlHko3O8kIXf
hvwAm+jiDzGXvDtiUrkwj67STJAhld6vH/N08wIDAQABAoIBAQCKfw9zuek7AMNo
WfKlud4Qw2kJvqKhRoICUGIYZAWMuvAPWiOdf6ryfDleKnU5bAgSbw4HyHnOYspP
dnFLRv8+bPduG0r1mV/5KePhMS49lPbLGOIbrIzhXBy8Yyr+dewAp2GIrbFgQh0p
HLcBVeb+ycVPpojwouLMvPkE0FgSNj8FPeH3QDvk4hgr2UWmlqJ3OYRJYduF8TeP
IC/pY4v+zBHt+uaQYd90+yGVNeRuIsVmeIdsMLrE8M8uoK6cy0jAxjoCgkIOhGn6
d6Y+JizUZSQJoaLd+JB+ZETxCoCzfaOBHjcTgO+GUc2yWYJGwpSstjX2zRRZMv+w
acqsQCUBAoGBAPCiiWTjmPwL4ISjazAxwOy98Zrt4mtHpebiLVxH+sPtAudcuYat
M1N5mnayBMKlhI9U+G0IkNyTTY4MqfYIsw77enA84jfjp8nFTQEvoCOLx/9/0Rrc
qIhw7oj7QtWOzj6Yk6IXfLfdBQ0oiVJyBZbPthVrjytQ4SmqFbnHQ6OBAoGBAPOt
X18GsGZ3Uh5lu65r04WfbbjyQ8O5Gk0hpc9I9al7j1a5Oxpi47wI5Uq2Gw8oMnYy
iYashJQoyXXQIwDi0bzIsuhJa6tVbpdvMlHPqwhyh51mM4y6qspEaHfA2xgp7kXv
GPfGzQN71+zhZBDbWMszJRhvJxFSyN/udn/SSgJzAoGAPcjN1Cyn7Bc0l3nKHL65
lU+TyD7KAteLnkN2eBo3JbUmKLdjH1Q7OHShl1ZP6JZM+exMONqZLzlXEWDpBrXn
G7KwFj9bqhP20dSp1+Mdj+LlABIWY3pCf33XkS5KU8Dt7Z6JUXYMXL0P/ffpglSq
YLWGP+u0/98tYOA94cxq7oECgYAkRFd/cyVp+rRUJdwLF61Bo/rWnegMB06s0Cc3
dKprcSJiS+tKABHY+JH3zqa0WM053ketrZuF2ZQyXqn3Bcslh9Fo1RSbSXnOPBSH
LJtOBI2+lWlyto2Y0RmjSSbSr9rwuadDqWj17cazUNBt2debVp9cxZ5Q67tN6NXm
LEwrlQKBgQCMoQ+zk0iSRt2Xnbv4Fvx4d1/dTDhyeMIDG1Vp7OtDEgMVaBsAMjrW
jmooZyN/CR2iiFtUE5Yv9Y2kd586YaHEVQ9vBLUs0Fee5NtZPWgiBp5jTvpaBYlc
6nHwS7c+qB3UULBARunwbzkMVG3EbCcutXU1NZqVs3CchajlOAX1tg==
-----END RSA PRIVATE KEY-----`

	testIAMAnywhereProfileARN     = "arn:aws:rolesanywhere:us-east-1:556782317223:profile/3c30dfae-294e-42bd-b18a-75e9fd2759c0"
	testIAMAnywhereTrustAnchorARN = "arn:aws:rolesanywhere:us-east-1:556782317223:trust-anchor/c4564179-fa53-47a1-5e77-24d6829d2810"
	testIAMAnywhereRoleARN        = "arn:aws:rolesanywhere:us-east-1:556782317223:role-arn/3c30dfae-294e-42bd-b18a-54e9fd2759c0"
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

// requireAWSIAMCredentials skips the test when AWS IAM credentials are absent.
// Tests that create non-role-anywhere connections require both AWS_ACCESS_KEY_ID
// and AWS_SECRET_ACCESS_KEY; without the secret key the CM API returns 422.
func requireAWSIAMCredentials(t *testing.T) {
	t.Helper()
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("skipping: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for AWS Connection acceptance tests")
	}
}

// awsConnConfig returns a minimal ciphertrust_aws_connection config.
// secret_access_key is intentionally omitted; it is supplied via AWS_SECRET_ACCESS_KEY env-var fallback.
func awsConnConfig(name, description string) string {
	cfg := fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
`, name, awsAccessKeyID())
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
  aws_region        = %q
  cloud_name        = %q
}
`, name, awsAccessKeyID(), region, cloudName)
}

func awsConnConfigWithMapList(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  labels            = { env = "test" }
  meta              = { owner = "qa" }
  products          = ["cckm"]
}
`, name, awsAccessKeyID())
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

// TestCM_AWSConnection_drift verifies that Read() surfaces an out-of-band
// description change as drift.
func TestCM_AWSConnection_drift(t *testing.T) {
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

// TestCM_AWSConnection_driftScalars verifies drift detection for Optional scalar
// fields: aws_region and cloud_name.
func TestCM_AWSConnection_driftScalars(t *testing.T) {
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

// TestCM_AWSConnection_driftMapAndList verifies drift detection for labels, meta,
// and products.
func TestCM_AWSConnection_driftMapAndList(t *testing.T) {
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

// TestCM_AWSConnection_driftIAMRoleAnywhere verifies drift detection for
// iam_role_anywhere readable sub-fields.
func TestCM_AWSConnection_driftIAMRoleAnywhere(t *testing.T) {
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
`, name, testIAMAnywhereRoleARN, testIAMAnywhereTrustAnchorARN, testIAMAnywhereProfileARN, testIAMAnywhereCert)

	altRoleARN := testIAMAnywhereRoleARN + "-changed"

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

// TestCM_AWSConnection_outOfBandDelete verifies that Read() removes the resource
// from state on 404, and that Delete() 404-guards the test teardown.
func TestCM_AWSConnection_outOfBandDelete(t *testing.T) {
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

// TestCM_AWSConnection_immutableName verifies that changing `name` raises a
// plan-time error from NameImmutableModifier, not a destroy+recreate diff.
func TestCM_AWSConnection_immutableName(t *testing.T) {
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

// TestCM_AWSConnection_envVarFallbackWritesToState verifies that omitting credentials from HCL
// and supplying them via AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY writes them to state,
// keeping subsequent plans idempotent.
func TestCM_AWSConnection_envVarFallbackWritesToState(t *testing.T) {
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		t.Setenv("AWS_ACCESS_KEY_ID", testGetAWSAccessKeyID())
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Setenv("AWS_SECRET_ACCESS_KEY", testGetAWSSecretAccessKey())
	}

	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-envvar-" + suffix
	cfg := awsConnConfigNoCredentials(name)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "env-var fallback: create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "access_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "secret_access_key"),
				),
			},
			{
				Config:   cfg,
				PlanOnly: true,
			},
		},
	})
}

// awsConnConfigInvalidProduct returns HCL for an AWS connection with an invalid products value.
func awsConnConfigInvalidProduct(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name     = %q
  products = ["azure"]
}
`, name)
}

// awsConnConfigWithProducts returns HCL for an AWS connection with the given products literal.
// secret_access_key is intentionally omitted; it is supplied via AWS_SECRET_ACCESS_KEY env-var fallback.
func awsConnConfigWithProducts(name, productsLiteral string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  products          = %s
}
`, name, awsAccessKeyID(), productsLiteral)
}

// TestCM_AWSConnection_InvalidProductRejected verifies that terraform plan produces
// a diagnostic error when products contains an invalid value, preventing the user
// from reaching terraform apply.
func TestCM_AWSConnection_InvalidProductRejected(t *testing.T) {
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				PlanOnly:    true,
				Config:      awsConnConfigInvalidProduct("tftest-invalid-product"),
				ExpectError: regexp.MustCompile(`(?i)value must be one of`),
			},
		},
	})
}

// TestCM_AWSConnection_ValidProducts verifies the full happy path through the new
// validator: valid product values are accepted at plan time, applied successfully,
// updated to a multi-value list, and Read() round-trips products without drift.
func TestCM_AWSConnection_ValidProducts(t *testing.T) {
	resourceName := "ciphertrust_aws_connection.test"
	suffix := uuid.New().String()[:8]
	connName := "tftest-valid-products-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnConfigWithProducts(connName, `["cckm"]`),
				Check: checkStep(t, "create with cckm",
					resource.TestCheckResourceAttr(resourceName, "products.0", "cckm"),
					resource.TestCheckResourceAttr(resourceName, "products.#", "1"),
				),
			},
			{
				Config: awsConnConfigWithProducts(connName, `["cckm", "backup/restore"]`),
				Check: checkStep(t, "update to two products",
					resource.TestCheckResourceAttr(resourceName, "products.#", "2"),
					resource.TestCheckResourceAttr(resourceName, "products.0", "cckm"),
					resource.TestCheckResourceAttr(resourceName, "products.1", "backup/restore"),
				),
			},
			{
				RefreshState:       true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// TestCM_AWSConnection_createSecretKey verifies the basic create → read → delete
// lifecycle for an AWS connection that uses an access key ID and secret access key.
func TestCM_AWSConnection_createSecretKey(t *testing.T) {
	suffix := uuid.New().String()[:8]
	name := "tf-aws-secretkey-" + suffix
	resourceName := "ciphertrust_aws_connection.test"

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name              = %q
  access_key_id     = %q
  secret_access_key = %q
}
`, name, testGetAWSAccessKeyID(), testGetAWSSecretAccessKey())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "create secret key connection",
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "access_key_id", testGetAWSAccessKeyID()),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
		},
	})
}

// TestCM_AWSConnection_createIAMAnywhere verifies the basic create → read → delete
// lifecycle for an AWS connection that uses IAM Roles Anywhere (is_role_anywhere = true).
func TestCM_AWSConnection_createIAMAnywhere(t *testing.T) {
	suffix := uuid.New().String()[:8]
	name := "tf-aws-iamanywhere-" + suffix
	resourceName := "ciphertrust_aws_connection.test"

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name             = %q
  is_role_anywhere = true
  iam_role_anywhere {
    anywhere_role_arn = %q
    trust_anchor_arn  = %q
    profile_arn       = %q
    certificate       = %q
    private_key       = %q
  }
}
`, name, testIAMAnywhereRoleARN, testIAMAnywhereTrustAnchorARN, testIAMAnywhereProfileARN, testIAMAnywhereCert, testIAMAnywherePrivateKey)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: checkStep(t, "create IAM Anywhere connection",
					resource.TestCheckResourceAttr(resourceName, "name", name),
					resource.TestCheckResourceAttr(resourceName, "is_role_anywhere", "true"),
					resource.TestCheckResourceAttr(resourceName, "iam_role_anywhere.0.anywhere_role_arn", testIAMAnywhereRoleARN),
					resource.TestCheckResourceAttr(resourceName, "iam_role_anywhere.0.trust_anchor_arn", testIAMAnywhereTrustAnchorARN),
					resource.TestCheckResourceAttr(resourceName, "iam_role_anywhere.0.profile_arn", testIAMAnywhereProfileARN),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
		},
	})
}

// awsRoleAnywhereConfig returns a ciphertrust_aws_connection config with
// is_role_anywhere = true and an iam_role_anywhere block. private_key is
// intentionally omitted from HCL.
// awsRoleAnywhereConfig returns a ciphertrust_aws_connection config with
// is_role_anywhere = true and an iam_role_anywhere block. private_key is
// intentionally omitted from HCL — it is supplied via the
// CIPHERTRUST_AWS_PRIVATE_KEY environment variable fallback in Create().
func awsRoleAnywhereConfig(name, description, certificate, anywhereRoleARN, profileARN, trustAnchorARN string) string {
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
`, name, anywhereRoleARN, trustAnchorARN, profileARN, certificate)
	if description != "" {
		cfg += fmt.Sprintf("  description = %q\n", description)
	}
	cfg += "}\n"
	return cfg
}

// awsRoleAnywhereConfigBool returns a ciphertrust_aws_connection config with a
// configurable is_role_anywhere bool value. Used to test that changing
// is_role_anywhere fires the ImmutableBool plan modifier.
func awsRoleAnywhereConfigBool(name string, isRoleAnywhere bool, certificate, anywhereRoleARN, profileARN, trustAnchorARN string) string {
	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name             = %q
  is_role_anywhere = %v
  iam_role_anywhere {
    anywhere_role_arn = %q
    trust_anchor_arn  = %q
    profile_arn       = %q
    certificate       = %q
  }
}
`, name, isRoleAnywhere, anywhereRoleARN, trustAnchorARN, profileARN, certificate)
	return cfg
}

// TestCipherTrust_AWSConnectionRoleAnywhere verifies that Update() does not
// re-send the iam_role_anywhere block when only an unrelated field (description)
// changes, preventing the "Certificate from same CSR" 400 from CM.
func TestCipherTrust_AWSConnectionRoleAnywhere(t *testing.T) {
	RequireCM(t)

	anywhereRoleARN := os.Getenv("CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN")
	trustAnchorARN := os.Getenv("CIPHERTRUST_AWS_TRUST_ANCHOR_ARN")
	profileARN := os.Getenv("CIPHERTRUST_AWS_PROFILE_ARN")
	certificate := os.Getenv("CIPHERTRUST_AWS_CERTIFICATE")
	if anywhereRoleARN == "" || trustAnchorARN == "" || profileARN == "" || certificate == "" {
		t.Skip("skipping TestCipherTrust_AWSConnectionRoleAnywhere: CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN, CIPHERTRUST_AWS_TRUST_ANCHOR_ARN, CIPHERTRUST_AWS_PROFILE_ARN, and CIPHERTRUST_AWS_CERTIFICATE must be set")
	}

	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-ra-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsRoleAnywhereConfig(name, "initial description", testIAMAnywhereCert, testIAMAnywhereRoleARN, testIAMAnywhereProfileARN, testIAMAnywhereTrustAnchorARN),
				Check: checkStep(t, "create role-anywhere connection",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "initial description"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "is_role_anywhere", "true"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
				),
			},
			{
				Config: awsRoleAnywhereConfig(name, "updated description", testIAMAnywhereCert, testIAMAnywhereRoleARN, testIAMAnywhereProfileARN, testIAMAnywhereTrustAnchorARN),
				Check: checkStep(t, "update description only",
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "updated description"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "is_role_anywhere", "true"),
				),
			},
			{
				Config: awsRoleAnywhereConfig(name, "updated description", testIAMAnywhereCert, testIAMAnywhereRoleARN,
					"arn:aws:rolesanywhere:us-east-1:123456789012:profile/new",
					testIAMAnywhereTrustAnchorARN),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			// Step 4 — plan-only: attempt to flip is_role_anywhere from true to false.
			// ImmutableBool must fire a plan-time error and prevent the change.
			{
				Config:      awsRoleAnywhereConfigBool(name, false, certificate, anywhereRoleARN, profileARN, trustAnchorARN),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// TestCM_AWSConnection_updateComputedFields verifies that Computed fields are
// refreshed from CM in state after an in-Terraform update, and that Update()
// does not corrupt the resource ID.
func TestCM_AWSConnection_updateComputedFields(t *testing.T) {
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
