package provider

// Tests that verify the corrected 404 behaviour for platform resources.
//
// Rule:
//   - Read HTTP 404  → AddError (state preserved — no RemoveResource)
//   - Delete HTTP 404 → AddWarning (Terraform removes from state on normal return)
//
// We use a real httptest.Server returning HTTP 404 so the test exercises the
// full code path from doRequest → resource method → diagnostics.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	connections "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/connections"
	cm "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cm"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	tfresource "github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// notFoundServer returns an httptest.Server that always responds with HTTP 404.
func notFoundServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
	}))
}

// configureResourceForTest wires the mock client into a resource and returns the schema.
func configureResourceForTest(t *testing.T, ctx context.Context, res tfresource.Resource, client *common.Client) tfresource.SchemaResponse {
	t.Helper()
	confResp := &tfresource.ConfigureResponse{}
	res.(tfresource.ResourceWithConfigure).Configure(ctx, tfresource.ConfigureRequest{
		ProviderData: client,
	}, confResp)
	if confResp.Diagnostics.HasError() {
		t.Fatalf("unexpected configure error: %v", confResp.Diagnostics)
	}
	var schemaResp tfresource.SchemaResponse
	res.Schema(ctx, tfresource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected schema error: %v", schemaResp.Diagnostics)
	}
	return schemaResp
}

// regTokenState returns a minimal tftypes.Value for CMRegTokenTFSDK.
// Only id is set; all other fields are null.
func regTokenState(id string) tftypes.Value {
	mapNullStr := tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, nil)
	return tftypes.NewValue(tftypes.Object{
		AttributeTypes: map[string]tftypes.Type{
			"id":                           tftypes.String,
			"token":                        tftypes.String,
			"ca_id":                        tftypes.String,
			"cert_duration":                tftypes.Number,
			"client_management_profile_id": tftypes.String,
			"label":                        tftypes.Map{ElementType: tftypes.String},
			"labels":                       tftypes.Map{ElementType: tftypes.String},
			"lifetime":                     tftypes.String,
			"max_clients":                  tftypes.Number,
			"name_prefix":                  tftypes.String,
		},
	}, map[string]tftypes.Value{
		"id":                           tftypes.NewValue(tftypes.String, id),
		"token":                        tftypes.NewValue(tftypes.String, nil),
		"ca_id":                        tftypes.NewValue(tftypes.String, nil),
		"cert_duration":                tftypes.NewValue(tftypes.Number, nil),
		"client_management_profile_id": tftypes.NewValue(tftypes.String, nil),
		"label":                        mapNullStr,
		"labels":                       mapNullStr,
		"lifetime":                     tftypes.NewValue(tftypes.String, nil),
		"max_clients":                  tftypes.NewValue(tftypes.Number, nil),
		"name_prefix":                  tftypes.NewValue(tftypes.String, nil),
	})
}

// Test_Read404_IsError_RegToken verifies that a 404 on Read raises a diagnostic
// error (not a warning) and keeps the resource in state (no RemoveResource call).
func Test_Read404_IsError_RegToken(t *testing.T) {
	srv := notFoundServer(t)
	defer srv.Close()

	client := &common.Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Log:            hclog.NewNullLogger(),
	}

	ctx := context.Background()
	res := cm.NewResourceCMRegToken()
	schemaResp := configureResourceForTest(t, ctx, res, client)

	raw := regTokenState("reg-token-id-123")

	readResp := &tfresource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: raw},
	}
	res.Read(ctx, tfresource.ReadRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: raw},
	}, readResp)

	// Must have a hard error — not just a warning.
	if !readResp.Diagnostics.HasError() {
		t.Fatal("Read 404: expected an error diagnostic but got none")
	}
	// State must NOT have been removed (preserved on error).
	if readResp.State.Raw.IsNull() {
		t.Fatal("Read 404: state was removed — it should be preserved on error")
	}
	// No 'not found' warnings should exist (the warning was converted to an error).
	for _, w := range readResp.Diagnostics.Warnings() {
		if strings.Contains(strings.ToLower(w.Summary()), "not found") {
			t.Errorf("Read 404: got a 'not found' warning instead of an error: %q", w.Summary())
		}
	}
}

// Test_Delete404_IsWarning_RegToken verifies that a 404 on Delete raises a
// diagnostic warning (not an error) so Terraform removes the resource from state.
func Test_Delete404_IsWarning_RegToken(t *testing.T) {
	srv := notFoundServer(t)
	defer srv.Close()

	client := &common.Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Log:            hclog.NewNullLogger(),
	}

	ctx := context.Background()
	res := cm.NewResourceCMRegToken()
	schemaResp := configureResourceForTest(t, ctx, res, client)

	raw := regTokenState("reg-token-id-123")

	deleteResp := &tfresource.DeleteResponse{}
	res.Delete(ctx, tfresource.DeleteRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: raw},
	}, deleteResp)

	// Must NOT have a hard error — only a warning.
	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete 404: got unexpected error: %v", deleteResp.Diagnostics.Errors())
	}
	if len(deleteResp.Diagnostics.Warnings()) == 0 {
		t.Fatal("Delete 404: expected a warning diagnostic but got none")
	}
	// The warning should reference the 'not found' / deletion situation.
	found := false
	for _, w := range deleteResp.Diagnostics.Warnings() {
		lower := strings.ToLower(w.Summary())
		if strings.Contains(lower, "not found") || strings.Contains(lower, "deleted") || strings.Contains(lower, "removed") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Delete 404: warning summary does not mention 'not found'/'deleted'/'removed'")
	}
}

// Test_Read404_IsError_AWSConnection verifies the connections package Read 404 behaviour.
func Test_Read404_IsError_AWSConnection(t *testing.T) {
	srv := notFoundServer(t)
	defer srv.Close()

	client := &common.Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Log:            hclog.NewNullLogger(),
	}

	ctx := context.Background()
	res := connections.NewResourceCCKMAWSConnection()
	schemaResp := configureResourceForTest(t, ctx, res, client)

	// Build a minimal state with just enough for the Read to proceed.
	// We'll use the schema's own TerraformType to discover attribute types
	// and populate null values for each, then override id.
	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	objType, ok := stateType.(tftypes.Object)
	if !ok {
		t.Fatalf("expected tftypes.Object schema type, got %T", stateType)
	}

	stateVals := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for k, typ := range objType.AttributeTypes {
		stateVals[k] = tftypes.NewValue(typ, nil)
	}
	stateVals["id"] = tftypes.NewValue(tftypes.String, "aws-conn-id-999")
	rawState := tftypes.NewValue(stateType, stateVals)

	readResp := &tfresource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}
	res.Read(ctx, tfresource.ReadRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}, readResp)

	if !readResp.Diagnostics.HasError() {
		t.Fatal("Read 404 (AWS Connection): expected an error diagnostic but got none")
	}
	if readResp.State.Raw.IsNull() {
		t.Fatal("Read 404 (AWS Connection): state was removed — it should be preserved on error")
	}
}

// Test_Delete404_IsWarning_AWSConnection verifies the connections Delete 404 behaviour.
func Test_Delete404_IsWarning_AWSConnection(t *testing.T) {
	srv := notFoundServer(t)
	defer srv.Close()

	client := &common.Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Log:            hclog.NewNullLogger(),
	}

	ctx := context.Background()
	res := connections.NewResourceCCKMAWSConnection()
	schemaResp := configureResourceForTest(t, ctx, res, client)

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	objType, ok := stateType.(tftypes.Object)
	if !ok {
		t.Fatalf("expected tftypes.Object schema type, got %T", stateType)
	}

	stateVals := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for k, typ := range objType.AttributeTypes {
		stateVals[k] = tftypes.NewValue(typ, nil)
	}
	stateVals["id"] = tftypes.NewValue(tftypes.String, "aws-conn-id-999")
	rawState := tftypes.NewValue(stateType, stateVals)

	deleteResp := &tfresource.DeleteResponse{}
	res.Delete(ctx, tfresource.DeleteRequest{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState},
	}, deleteResp)

	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete 404 (AWS Connection): got unexpected error: %v", deleteResp.Diagnostics.Errors())
	}
	if len(deleteResp.Diagnostics.Warnings()) == 0 {
		t.Fatal("Delete 404 (AWS Connection): expected a warning diagnostic but got none")
	}
}
