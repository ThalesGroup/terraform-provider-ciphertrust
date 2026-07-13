package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/connections"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Test_CM_ApplyNullDeletes verifies that ApplyNullDeletes injects nil for keys
// present in prior state but removed from plan, so they marshal as JSON null
// and trigger CM's merge-patch delete semantics.
func Test_CM_ApplyNullDeletes(t *testing.T) {
	mkElems := func(kv map[string]string) map[string]attr.Value {
		out := make(map[string]attr.Value, len(kv))
		for k, v := range kv {
			out[k] = types.StringValue(v)
		}
		return out
	}

	tests := []struct {
		name        string
		payload     map[string]interface{}
		stateElems  map[string]attr.Value
		wantNilKeys []string
		wantNonNil  []string
	}{
		{
			name:        "removed key gets explicit nil",
			payload:     map[string]interface{}{"key2": "v2"},
			stateElems:  mkElems(map[string]string{"key1": "v1", "key2": "v2"}),
			wantNilKeys: []string{"key1"},
			wantNonNil:  []string{"key2"},
		},
		{
			name:        "all keys removed — empty plan flushes entire map via nulls",
			payload:     map[string]interface{}{},
			stateElems:  mkElems(map[string]string{"key1": "v1", "key2": "v2"}),
			wantNilKeys: []string{"key1", "key2"},
		},
		{
			name:       "no change — no nulls injected",
			payload:    map[string]interface{}{"key1": "v1", "key2": "v2"},
			stateElems: mkElems(map[string]string{"key1": "v1", "key2": "v2"}),
			wantNonNil: []string{"key1", "key2"},
		},
		{
			name:       "new key added — no null injection",
			payload:    map[string]interface{}{"key1": "v1", "key2": "v2", "key3": "v3"},
			stateElems: mkElems(map[string]string{"key1": "v1", "key2": "v2"}),
			wantNonNil: []string{"key1", "key2", "key3"},
		},
		{
			name:       "empty state — nothing to delete",
			payload:    map[string]interface{}{"key1": "v1"},
			stateElems: map[string]attr.Value{},
			wantNonNil: []string{"key1"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			connections.ApplyNullDeletes(tc.payload, tc.stateElems)
			for _, k := range tc.wantNilKeys {
				v, ok := tc.payload[k]
				if !ok {
					t.Errorf("key %q: expected present with nil value, but absent", k)
					continue
				}
				if v != nil {
					t.Errorf("key %q: expected nil, got %v", k, v)
				}
			}
			for _, k := range tc.wantNonNil {
				v, ok := tc.payload[k]
				if !ok {
					t.Errorf("key %q: expected present with non-nil value, but absent", k)
					continue
				}
				if v == nil {
					t.Errorf("key %q: expected non-nil value, got nil", k)
				}
			}
		})
	}
}

// Test_CM_ApplyNullDeletes_JSONMarshaling verifies that nil values injected by
// ApplyNullDeletes marshal to JSON null — the delete signal for CM's PATCH endpoint.
func Test_CM_ApplyNullDeletes_JSONMarshaling(t *testing.T) {
	payload := map[string]interface{}{"key2": "v2"}
	stateElems := map[string]attr.Value{
		"key1": types.StringValue("v1"),
		"key2": types.StringValue("v2"),
	}
	connections.ApplyNullDeletes(payload, stateElems)

	body := map[string]interface{}{"meta": payload}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(raw)
	if !strings.Contains(jsonStr, `"key1":null`) {
		t.Errorf("expected JSON to contain %q for removed key, got: %s", `"key1":null`, jsonStr)
	}
	if !strings.Contains(jsonStr, `"key2":"v2"`) {
		t.Errorf("expected JSON to contain %q for retained key, got: %s", `"key2":"v2"`, jsonStr)
	}
}

// testGetAWSAccessKeyID returns a fake AWS access key ID for unit tests.
func testGetAWSAccessKeyID() string {
	if v := os.Getenv("TEST_AWS_ACCESS_KEY_ID"); v != "" {
		return v
	}
	return "TESTACCESSKEYIDEXAMPLE"
}

// testGetAWSSecretAccessKey returns a fake AWS secret access key for unit tests.
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
// Falls back to a well-known placeholder when the env var is not set.
func awsAccessKeyID() string {
	if v := os.Getenv("AWS_ACCESS_KEY_ID"); v != "" {
		return v
	}
	return "AKIAIOSFODNN7EXAMPLE"
}

// requireAWSIAMCredentials skips the test when AWS IAM credentials are absent.
func requireAWSIAMCredentials(t *testing.T) {
	t.Helper()
	if os.Getenv("AWS_ACCESS_KEY_ID") == "" || os.Getenv("AWS_SECRET_ACCESS_KEY") == "" {
		t.Skip("skipping: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")
	}
}

// awsConnConfig returns a minimal ciphertrust_aws_connection HCL config.
// secret_access_key is supplied via AWS_SECRET_ACCESS_KEY env-var fallback.
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
  name          = %q
  access_key_id = %q
  aws_region    = %q
  cloud_name    = %q
}
`, name, awsAccessKeyID(), region, cloudName)
}

func awsConnConfigWithMapList(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name          = %q
  access_key_id = %q
  labels        = { env = "test" }
  meta          = { owner = "qa" }
  products      = ["cckm"]
}
`, name, awsAccessKeyID())
}

// awsConnConfigWithTwoMetaKeys returns HCL with meta keys key1 and key2.
func awsConnConfigWithTwoMetaKeys(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name          = %q
  access_key_id = %q
  meta          = { key1 = "v1", key2 = "v2" }
}
`, name, awsAccessKeyID())
}

// awsConnConfigWithOneMetaKey returns HCL with only meta key2 (key1 removed).
func awsConnConfigWithOneMetaKey(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name          = %q
  access_key_id = %q
  meta          = { key2 = "v2" }
}
`, name, awsAccessKeyID())
}

// awsConnConfigNoCredentials omits credentials from HCL; relies on env-var fallback.
func awsConnConfigNoCredentials(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name = %q
}
`, name)
}

// awsConnConfigInvalidProduct returns HCL with an invalid products value.
func awsConnConfigInvalidProduct(name string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name     = %q
  products = ["azure"]
}
`, name)
}

// awsConnConfigWithProducts returns HCL with the given products literal.
func awsConnConfigWithProducts(name, productsLiteral string) string {
	return providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name          = %q
  access_key_id = %q
  products      = %s
}
`, name, awsAccessKeyID(), productsLiteral)
}

// awsRoleAnywhereConfig returns an is_role_anywhere=true HCL config.
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

// awsRoleAnywhereConfigBool returns an is_role_anywhere HCL config with explicit bool value.
func awsRoleAnywhereConfigBool(name string, isRoleAnywhere bool, certificate, anywhereRoleARN, profileARN, trustAnchorARN string) string {
	return providerConfig + fmt.Sprintf(`
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

// TestAWSConnectionCreateUpdateDestroy verifies the full create, update, and destroy
// lifecycle for an AWS connection using IAM credentials from environment variables.
func TestAWSConnectionCreateUpdateDestroy(t *testing.T) {
	RequireCM(t)
	requireAWSIAMCredentials(t)
	suffix := uuid.New().String()[:8]
	name := "tf-test-aws-conn-" + suffix

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnConfig(name, "initial description"),
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "uri"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "name", name),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "initial description"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "access_key_id"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "created_at"),
				),
			},
			{
				Config: awsConnConfig(name, "updated description"),
				Check: checkStep(t, "update",
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "id"),
					resource.TestCheckResourceAttr("ciphertrust_aws_connection.test", "description", "updated description"),
					resource.TestCheckResourceAttrSet("ciphertrust_aws_connection.test", "access_key_id"),
				),
			},
		},
	})
}

// Test_CM_AWSConnection_drift verifies that Read() surfaces an out-of-band
// description change as a non-empty plan.
func Test_CM_AWSConnection_drift(t *testing.T) {
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
				// Out-of-band description change; next plan must detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_AWS_CONNECTION,
						[]byte(`{"description":"out-of-band-changed"}`), "id")
				},
				Config:             awsConnConfig(name, "initial"),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AWSConnection_driftScalars verifies drift detection for aws_region
// and cloud_name Optional scalar fields.
func Test_CM_AWSConnection_driftScalars(t *testing.T) {
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
				// Out-of-band change to aws_region; next plan must detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_AWS_CONNECTION,
						[]byte(`{"aws_region":"us-west-2"}`), "id")
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AWSConnection_driftMapAndList verifies drift detection for labels,
// meta, and products.
func Test_CM_AWSConnection_driftMapAndList(t *testing.T) {
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
				// Out-of-band label change; next plan must detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_AWS_CONNECTION,
						[]byte(`{"labels":{"env":"changed"}}`), "id")
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AWSConnection_driftIAMRoleAnywhere verifies drift detection for
// iam_role_anywhere readable sub-fields.
func Test_CM_AWSConnection_driftIAMRoleAnywhere(t *testing.T) {
	RequireCM(t)
	anywhereRoleARN := os.Getenv("CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN")
	trustAnchorARN := os.Getenv("CIPHERTRUST_AWS_TRUST_ANCHOR_ARN")
	profileARN := os.Getenv("CIPHERTRUST_AWS_PROFILE_ARN")
	certificate := os.Getenv("CIPHERTRUST_AWS_CERTIFICATE")
	if anywhereRoleARN == "" || trustAnchorARN == "" || profileARN == "" || certificate == "" {
		t.Skip("skipping: CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN, CIPHERTRUST_AWS_TRUST_ANCHOR_ARN, CIPHERTRUST_AWS_PROFILE_ARN, and CIPHERTRUST_AWS_CERTIFICATE must be set")
	}
	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-iam-" + suffix
	var capturedID string

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name             = %q
  is_role_anywhere = true
  iam_role_anywhere = {
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
				// Out-of-band change to anywhere_role_arn; next plan must detect drift.
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					_, _ = client.UpdateData(context.Background(), capturedID, common.URL_AWS_CONNECTION,
						[]byte(fmt.Sprintf(`{"iam_role_anywhere":{"anywhere_role_arn":%q}}`, altRoleARN)), "id")
				},
				Config:             cfg,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AWSConnection_outOfBandDelete verifies that Read() removes the resource
// from state on 404.
func Test_CM_AWSConnection_outOfBandDelete(t *testing.T) {
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
				// Delete out-of-band; Read() must detect 404 and mark for re-creation.
				PreConfig:          func() { deleteAWSConnection(capturedID) },
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_CM_AWSConnection_immutableName verifies that changing name raises a
// plan-time error rather than a destroy+recreate.
func Test_CM_AWSConnection_immutableName(t *testing.T) {
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

// Test_CM_AWSConnection_envVarFallbackWritesToState verifies that omitting
// credentials from HCL and supplying via env vars keeps plans idempotent.
func Test_CM_AWSConnection_envVarFallbackWritesToState(t *testing.T) {
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

// Test_CM_AWSConnection_InvalidProductRejected verifies that plan raises a
// diagnostic error when products contains an invalid value.
func Test_CM_AWSConnection_InvalidProductRejected(t *testing.T) {
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

// Test_CM_AWSConnection_ValidProducts verifies create, update, and Read()
// round-trip for the products list attribute.
func Test_CM_AWSConnection_ValidProducts(t *testing.T) {
	RequireCM(t)
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

// Test_CM_AWSConnection_metaKeyRemovalIdempotent is a regression test verifying
// that removing a meta key from config actually deletes it from CM and that
// subsequent plans are empty (idempotent).
func Test_CM_AWSConnection_metaKeyRemovalIdempotent(t *testing.T) {
	RequireCM(t)
	suffix := uuid.New().String()[:8]
	name := "tf-acc-aws-meta-del-" + suffix
	resourceName := "ciphertrust_aws_connection.test"

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: awsConnConfigWithTwoMetaKeys(name),
				Check: checkStep(t, "meta key removal: create with two keys",
					resource.TestCheckResourceAttr(resourceName, "meta.key1", "v1"),
					resource.TestCheckResourceAttr(resourceName, "meta.key2", "v2"),
				),
			},
			{
				// Remove key1; after apply it must be absent from state.
				Config: awsConnConfigWithOneMetaKey(name),
				Check: checkStep(t, "meta key removal: after removing key1",
					resource.TestCheckNoResourceAttr(resourceName, "meta.key1"),
					resource.TestCheckResourceAttr(resourceName, "meta.key2", "v2"),
				),
			},
			{
				// Subsequent plan must be empty (removal was idempotent).
				Config:   awsConnConfigWithOneMetaKey(name),
				PlanOnly: true,
			},
		},
	})
}

// Test_CM_AWSConnection_createSecretKey verifies the create lifecycle for an
// AWS connection using an access key ID and secret access key.
func Test_CM_AWSConnection_createSecretKey(t *testing.T) {
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

// Test_CM_AWSConnection_createIAMAnywhere verifies the create lifecycle for an
// AWS connection using IAM Roles Anywhere (is_role_anywhere = true).
func Test_CM_AWSConnection_createIAMAnywhere(t *testing.T) {
	suffix := uuid.New().String()[:8]
	name := "tf-aws-iamanywhere-" + suffix
	resourceName := "ciphertrust_aws_connection.test"

	cfg := providerConfig + fmt.Sprintf(`
resource "ciphertrust_aws_connection" "test" {
  name             = %q
  is_role_anywhere = true
  iam_role_anywhere = {
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
					resource.TestCheckResourceAttr(resourceName, "iam_role_anywhere.anywhere_role_arn", testIAMAnywhereRoleARN),
					resource.TestCheckResourceAttr(resourceName, "iam_role_anywhere.trust_anchor_arn", testIAMAnywhereTrustAnchorARN),
					resource.TestCheckResourceAttr(resourceName, "iam_role_anywhere.profile_arn", testIAMAnywhereProfileARN),
					resource.TestCheckResourceAttrSet(resourceName, "id"),
					resource.TestCheckResourceAttrSet(resourceName, "created_at"),
					resource.TestCheckResourceAttrSet(resourceName, "updated_at"),
				),
			},
		},
	})
}

// Test_CM_AWSConnectionRoleAnywhere verifies that Update() does not re-send the
// iam_role_anywhere block when only an unrelated field (description) changes.
func Test_CM_AWSConnectionRoleAnywhere(t *testing.T) {
	RequireCM(t)

	anywhereRoleARN := os.Getenv("CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN")
	trustAnchorARN := os.Getenv("CIPHERTRUST_AWS_TRUST_ANCHOR_ARN")
	profileARN := os.Getenv("CIPHERTRUST_AWS_PROFILE_ARN")
	certificate := os.Getenv("CIPHERTRUST_AWS_CERTIFICATE")
	if anywhereRoleARN == "" || trustAnchorARN == "" || profileARN == "" || certificate == "" {
		t.Skip("skipping: CIPHERTRUST_AWS_ANYWHERE_ROLE_ARN, CIPHERTRUST_AWS_TRUST_ANCHOR_ARN, CIPHERTRUST_AWS_PROFILE_ARN, and CIPHERTRUST_AWS_CERTIFICATE must be set")
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
			{
				// Attempt to flip is_role_anywhere to false; must raise a plan-time error.
				Config:      awsRoleAnywhereConfigBool(name, false, certificate, anywhereRoleARN, profileARN, trustAnchorARN),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?i)immutable|cannot be changed`),
			},
		},
	})
}

// Test_CM_AWSConnection_updateComputedFields verifies that Computed fields are
// refreshed after an update and that Update() does not corrupt the resource ID.
func Test_CM_AWSConnection_updateComputedFields(t *testing.T) {
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
