package connections

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_ScpConnectionListDataSource_SchemaMatchesModel is a regression test for a real
// CI failure: adding password_version to CMScpConnectionTFSDK (for the write-only
// hardening pass) without also adding it to this data source's schema caused
// resp.State.Set to fail with "Value Conversion Error: Struct defines fields not
// found in object: password_version" — the framework requires every tfsdk-tagged
// struct field to have a matching schema attribute. Read() end-to-end against a fake
// CM server is the most direct way to catch this class of drift, since it exercises
// the same struct-to-object conversion Terraform performs.
func Test_ScpConnectionListDataSource_SchemaMatchesModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"resources":[{"id":"scp-id-1","name":"my-scp","host":"scp.example.com","auth_method":"password","path_to":"/data","public_key":"ssh-rsa AAAA","username":"svc-user"}],"total":1}`)
	}))
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	d := &dataSourceScpConnection{client: client}
	ctx := context.Background()

	var schemaResp datasource.SchemaResponse
	d.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	configType, ok := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	if !ok {
		t.Fatalf("expected schema type to be tftypes.Object")
	}
	configValue := tftypes.NewValue(configType, map[string]tftypes.Value{
		"filters": tftypes.NewValue(configType.AttributeTypes["filters"], nil),
		"scp":     tftypes.NewValue(configType.AttributeTypes["scp"], nil),
	})

	req := datasource.ReadRequest{
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: configValue},
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema},
	}

	d.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read() — likely a schema/struct field mismatch: %v", resp.Diagnostics)
	}
}
