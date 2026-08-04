package cm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

func Test_CM_KeyRead_PreservesStateOn404(t *testing.T) {
	// Fake CM server returning HTTP 404
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"key not found"}`)
	}))
	defer srv.Close()

	client := &common.Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMKey{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	objTypes := stateType.(tftypes.Object).AttributeTypes
	stateValues := make(map[string]tftypes.Value)
	for k, v := range objTypes {
		stateValues[k] = tftypes.NewValue(v, nil)
	}
	stateValues["id"] = tftypes.NewValue(tftypes.String, "k1")
	stateValues["name"] = tftypes.NewValue(tftypes.String, "my-key")
	rawState := tftypes.NewValue(stateType, stateValues)

	req := resource.ReadRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}

	r.Read(ctx, req, resp)

	// 404 on Read must now produce a hard error (not a warning) so the operator
	// is clearly informed. State must still be preserved (not removed).
	if !resp.Diagnostics.HasError() {
		t.Fatal("Read() on 404: expected an error diagnostic but got none")
	}

	// State must NOT have been cleared — the resource is retained in Terraform state
	// even on error so the operator can decide whether to remove it explicitly.
	if resp.State.Raw.IsNull() {
		t.Fatal("Read() on 404: state was cleared — it should be preserved on error")
	}

	// The error summary must reference the resource and include guidance.
	foundError := false
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Summary(), "Not Found") && strings.Contains(e.Detail(), "terraform state rm") {
			foundError = true
			break
		}
	}
	if !foundError {
		t.Errorf("did not find expected error with 'terraform state rm' guidance. Errors: %v", resp.Diagnostics.Errors())
	}
}
