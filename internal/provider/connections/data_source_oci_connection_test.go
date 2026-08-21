package connections

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	hclog "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_CM_OCIConnectionList_EmptyResponseSucceeds verifies that a CM response with an
// empty body (zero-match filter) returns an empty oci list attribute, not null (TFIN-570).
func Test_CM_OCIConnectionList_EmptyResponseSucceeds(t *testing.T) {
	ctx := context.Background()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "") // empty body = zero matches
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	d := &dataSourceOCIConnection{client: client}
	var schemaResp datasource.SchemaResponse
	d.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)

	dsType, ok := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	if !ok {
		t.Fatalf("expected schema type to be tftypes.Object")
	}
	dsVals := make(map[string]tftypes.Value, len(dsType.AttributeTypes))
	for name, attrType := range dsType.AttributeTypes {
		dsVals[name] = tftypes.NewValue(attrType, nil)
	}
	rawConfig := tftypes.NewValue(dsType, dsVals)

	req := datasource.ReadRequest{
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: rawConfig},
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawConfig},
	}
	d.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected error on empty response: %v", resp.Diagnostics)
	}
	var state OCIConnectionDataSourceModel
	if err := resp.State.Get(ctx, &state); err != nil {
		t.Fatalf("failed to decode state: %v", err)
	}
	if len(state.Oci) != 0 {
		t.Errorf("expected 0 oci connections, got %d", len(state.Oci))
	}
}

// Test_CM_OCIConnectionList_UnrecognizedFilterRejectedAtConfig verifies that
// ConfigValidators rejects unknown filter keys at config-validate time (TFIN-570).
func Test_CM_OCIConnectionList_UnrecognizedFilterRejectedAtConfig(t *testing.T) {
	ctx := context.Background()
	d := &dataSourceOCIConnection{}

	validators := d.ConfigValidators(ctx)
	if len(validators) == 0 {
		t.Fatal("expected at least one ConfigValidator on ciphertrust_oci_connection_list")
	}

	var schemaResp datasource.SchemaResponse
	d.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
	dsType, ok := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	if !ok {
		t.Fatalf("expected schema type to be tftypes.Object")
	}

	vals := make(map[string]tftypes.Value, len(dsType.AttributeTypes))
	for name, attrType := range dsType.AttributeTypes {
		if name == "filters" {
			vals[name] = tftypes.NewValue(tftypes.Map{ElementType: tftypes.String},
				map[string]tftypes.Value{"bogusKey": tftypes.NewValue(tftypes.String, "x")})
		} else {
			vals[name] = tftypes.NewValue(attrType, nil)
		}
	}
	rawConfig := tftypes.NewValue(dsType, vals)

	for _, v := range validators {
		req := datasource.ValidateConfigRequest{
			Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: rawConfig},
		}
		resp := &datasource.ValidateConfigResponse{}
		v.ValidateDataSource(ctx, req, resp)
		if !resp.Diagnostics.HasError() {
			t.Error("expected error for unrecognized filter key, got none")
		}
	}
}
