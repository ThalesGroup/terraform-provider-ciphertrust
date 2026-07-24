// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

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

	// Ensure there are no hard errors (only warnings)
	if resp.Diagnostics.HasError() {
		t.Fatalf("Read() returned unexpected errors: %v", resp.Diagnostics.Errors())
	}

	// Verify that state is preserved
	var final CMKeyTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("failed to parse final state: %v", diags)
	}
	if final.ID.ValueString() != "k1" {
		t.Errorf("expected state ID to be preserved as 'k1', got %q", final.ID.ValueString())
	}

	// Verify that a warning was appended
	warnings := resp.Diagnostics.Warnings()
	if len(warnings) == 0 {
		t.Fatal("expected diagnostic warnings to be populated, but got none")
	}

	foundWarning := false
	for _, w := range warnings {
		if strings.Contains(w.Summary(), "Key Not Found") && strings.Contains(w.Detail(), "terraform state rm") {
			foundWarning = true
			break
		}
	}

	if !foundWarning {
		t.Errorf("did not find expected warning with 'terraform state rm' instruction. Warnings got: %v", warnings)
	}
}
