package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	cm "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cm"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	tfresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func Test_CM_ResourceCMPrometheus(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = true
}
`,
				// Step 2: Check if the resource's 'enabled' attribute is set correctly after apply
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.cm_prometheus", "enabled", "true"),
				),
			},
		},
	})
	// create a new resource with prometheus disable
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "cm_prometheus" {
  enabled = false
}
`,
				// Step 2: Check if the resource's 'enabled' attribute is set correctly after apply
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.cm_prometheus", "enabled", "false"),
				),
			},
		},
	})
}

func Test_CM_PrometheusCreateAndToggle(t *testing.T) {
	RequireCM(t)
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
					resource.TestCheckResourceAttrSet("ciphertrust_cm_prometheus.test", "token"),
				),
			},
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = false
}
`,
				Check: checkStep(t, "toggle-off",
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "false"),
				),
			},
		},
	})
}

// Test_CM_CipherTrust_CMPrometheus_TokenSensitive verifies token is stored in state after
// create, is Sensitive (UseStateForUnknown prevents perpetual known-after-apply), is
// preserved in state when disabled, and is refreshed when re-enabled.
func Test_CM_CipherTrust_CMPrometheus_TokenSensitive(t *testing.T) {
	RequireCM(t)
	var capturedToken string

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			// Step 1: Create with enabled=true; verify token is stored.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_prometheus.test", "token"),
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
					func(s *terraform.State) error {
						capturedToken = s.RootModule().Resources["ciphertrust_cm_prometheus.test"].Primary.Attributes["token"]
						return nil
					},
				),
			},
			// Step 2: Plan stability — UseStateForUnknown() must prevent perpetual (known after apply).
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 3: Disable Prometheus; token must be preserved via Update() three-branch resolution.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = false
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "false"),
					// Use a closure so capturedToken is read lazily after Step 1 has run.
					func(s *terraform.State) error {
						return resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "token", capturedToken)(s)
					},
				),
			},
			// Step 4: Re-enable; token should be refreshed.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("ciphertrust_cm_prometheus.test", "token"),
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
				),
			},
			// Step 5: Plan stability after re-enable.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
			// Step 6: Cleanup — disable again to confirm full cycle completes without error.
			{
				Config: providerConfig + `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = false
}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "false"),
				),
			},
		},
	})
}

const prometheusEnabledConfig = `
resource "ciphertrust_cm_prometheus" "test" {
  enabled = true
}
`

// Test_CM_AccCMPrometheus_NoDrift verifies Read() introduces no spurious drift when CM state matches Terraform state.
func Test_CM_AccCMPrometheus_NoDrift(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + prometheusEnabledConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
				),
			},
			{
				Config:             providerConfig + prometheusEnabledConfig,
				PlanOnly:           true,
				ExpectNonEmptyPlan: false,
			},
		},
	})
}

// Test_CM_AccCMPrometheus_DriftDetection verifies Read() surfaces an out-of-band change to enabled as a plan diff.
func Test_CM_AccCMPrometheus_DriftDetection(t *testing.T) {
	RequireCM(t)

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: providerConfig + prometheusEnabledConfig,
				Check: checkStep(t, "create",
					resource.TestCheckResourceAttr("ciphertrust_cm_prometheus.test", "enabled", "true"),
				),
			},
			{
				PreConfig: func() {
					client, ok := createCMClient()
					if !ok {
						return
					}
					ctx := context.Background()
					payload, _ := json.Marshal(map[string]interface{}{})
					_, err := client.PostDataV2(ctx, "", common.URL_PROMETHEUS_DISABLE, payload)
					if err != nil {
						t.Logf("PreConfig disable failed: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

// Test_Unit_PrometheusRead_ResilientToEmptyResponse mock-tests that our updated Read()
// method returns a robust diagnostic error instead of silently mapping empty JSON to enabled = false.
func Test_Unit_PrometheusRead_ResilientToEmptyResponse(t *testing.T) {
	// 1. Set up a local mock server returning empty JSON `{}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{}`)); err != nil {
			t.Errorf("failed to write response body: %v", err)
		}
	}))
	defer server.Close()

	// 2. Initialize the standard Client configured to target the mock server
	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
	}

	// 3. Invoke the resource's Read method manually in a simulated framework call
	ctx := context.Background()
	res := cm.NewResourceCMPrometheus()

	client.Log = hclog.NewNullLogger()

	// Set up a mock Configure request
	confResp := &tfresource.ConfigureResponse{}
	res.(tfresource.ResourceWithConfigure).Configure(ctx, tfresource.ConfigureRequest{
		ProviderData: client,
	}, confResp)

	if confResp.Diagnostics.HasError() {
		t.Fatalf("Unexpected configuration error: %v", confResp.Diagnostics.Errors())
	}

	var schemaResp tfresource.SchemaResponse
	res.Schema(ctx, tfresource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	rawState := tftypes.NewValue(stateType, map[string]tftypes.Value{
		"enabled": tftypes.NewValue(tftypes.Bool, true),
		"token":   tftypes.NewValue(tftypes.String, "fake-token"),
	})

	// 4. Call Read with mock state
	readResp := &tfresource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}
	res.Read(ctx, tfresource.ReadRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}, readResp)

	// 5. Assert that an error diagnostic was successfully raised instead of silent failure
	if !readResp.Diagnostics.HasError() {
		t.Error("Expected error diagnostic regarding empty 'enabled' key, but got none")
	}
}
