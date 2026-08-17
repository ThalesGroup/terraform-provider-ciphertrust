package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_CM_RegToken_buildLabelsPatch_ClearPath verifies that buildLabelsPatch
// emits nil (→ JSON null) when the user clears labels (plan null, state non-null).
// This is the key signal CM needs to remove all labels from the resource.
func Test_CM_RegToken_buildLabelsPatch_ClearPath(t *testing.T) {
	// State: labels were previously set
	stateLabels, _ := types.MapValueFrom(nil, types.StringType, map[string]string{"env": "test"})
	state := CMRegTokenTFSDK{Labels: stateLabels}

	// Plan: labels removed from config (null)
	plan := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}

	result := buildLabelsPatch(plan, state)

	if result == skipLabels {
		t.Fatal("expected nil (clear signal), got skipLabels (omit)")
	}
	if result != nil {
		t.Fatalf("expected nil (JSON null), got %v", result)
	}

	// Verify it marshals as "labels": null in the PATCH body
	patchMap := map[string]any{"labels": result}
	b, err := json.Marshal(patchMap)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	got := string(b)
	if got != `{"labels":null}` {
		t.Fatalf("expected {\"labels\":null}, got %s", got)
	}
}

// Test_CM_RegToken_buildLabelsPatch_SetPath verifies that buildLabelsPatch
// returns a populated map when labels are configured in the plan.
func Test_CM_RegToken_buildLabelsPatch_SetPath(t *testing.T) {
	planLabels, _ := types.MapValueFrom(nil, types.StringType, map[string]string{"k": "v"})
	plan := CMRegTokenTFSDK{Labels: planLabels}
	state := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}

	result := buildLabelsPatch(plan, state)

	if result == skipLabels {
		t.Fatal("expected map, got skipLabels")
	}
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatalf("expected map[string]any, got %T", result)
	}
	if m["k"] != "v" {
		t.Fatalf("expected k=v, got %v", m)
	}
}

// Test_CM_RegToken_buildLabelsPatch_NeverConfigured verifies that buildLabelsPatch
// returns skipLabels (omit key) when neither plan nor state has labels configured.
func Test_CM_RegToken_buildLabelsPatch_NeverConfigured(t *testing.T) {
	plan := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}
	state := CMRegTokenTFSDK{Labels: types.MapNull(types.StringType)}

	result := buildLabelsPatch(plan, state)

	if result != skipLabels {
		t.Fatalf("expected skipLabels (omit key), got %v", result)
	}
}

// Compile-time check: CMRegTokenTFSDK must have a Labels field of types.Map.
var _ attr.Value = CMRegTokenTFSDK{}.Labels

// Test_CM_RegToken_CAIDImmutableRemoved verifies that the ca_id schema attribute
// does NOT carry ImmutableString() in its PlanModifiers. This acts as a regression
// guard: if ImmutableString() is accidentally re-added, this test fails immediately,
// preventing a silent rollback to the incorrect destroy+recreate behavior.
func Test_CM_RegToken_CAIDImmutableRemoved(t *testing.T) {
	r := &resourceCMRegToken{}
	var resp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &resp)

	caIDAttr, ok := resp.Schema.Attributes["ca_id"]
	if !ok {
		t.Fatal("ca_id attribute not found in schema")
	}

	strAttr, ok := caIDAttr.(schema.StringAttribute)
	if !ok {
		t.Fatalf("ca_id is not a StringAttribute, got %T", caIDAttr)
	}

	for _, mod := range strAttr.PlanModifiers {
		desc := mod.Description(context.Background())
		if strings.Contains(strings.ToLower(desc), "immutable") {
			t.Fatalf("ca_id still has an immutability plan modifier: %q — remove it (TFIN-514)", desc)
		}
	}
}

// ---------------------------------------------------------------------------
// Shared helpers for the CRUD unit tests below (mirrors resource_cm_key_unit_test.go's
// httptest-server pattern, scoped to CMRegTokenTFSDK). strMap/strList from that file
// are type-agnostic and reused directly here.
// ---------------------------------------------------------------------------

// newTestCMRegTokenResource builds a resourceCMRegToken wired to a fake HTTP server and
// returns the resource, a background context, and the resource's schema (built once via
// r.Schema()).
func newTestCMRegTokenResource(t *testing.T, handler http.HandlerFunc) (*resourceCMRegToken, context.Context, resource.SchemaResponse) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := &common.Client{
		CipherTrustURL: srv.URL,
		HTTPClient:     srv.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMRegToken{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}
	return r, ctx, schemaResp
}

// ensureRegTokenLabels defaults the zero-value types.Map fields (Label, Labels) — used
// when a test literal doesn't set them explicitly — to a properly-typed null map. The
// struct zero value has no ElementType set, which Plan/Config/State.Set() rejects.
func ensureRegTokenLabels(val *CMRegTokenTFSDK) *CMRegTokenTFSDK {
	if reflect.ValueOf(val.Label).IsZero() {
		val.Label = types.MapNull(types.StringType)
	}
	if reflect.ValueOf(val.Labels).IsZero() {
		val.Labels = types.MapNull(types.StringType)
	}
	return val
}

func mustRegTokenPlan(t *testing.T, ctx context.Context, schemaResp resource.SchemaResponse, val *CMRegTokenTFSDK) tfsdk.Plan {
	t.Helper()
	val = ensureRegTokenLabels(val)
	p := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := p.Set(ctx, val)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building plan: %v", diags)
	}
	return p
}

func mustRegTokenConfig(t *testing.T, ctx context.Context, schemaResp resource.SchemaResponse, val *CMRegTokenTFSDK) tfsdk.Config {
	t.Helper()
	// tfsdk.Config has no Set method (unlike Plan/State) — build via Plan.Set and reuse
	// its Raw tftypes.Value, since all three wrap the same underlying data shape.
	val = ensureRegTokenLabels(val)
	p := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := p.Set(ctx, val)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building config: %v", diags)
	}
	return tfsdk.Config{Schema: schemaResp.Schema, Raw: p.Raw}
}

func mustRegTokenState(t *testing.T, ctx context.Context, schemaResp resource.SchemaResponse, val *CMRegTokenTFSDK) tfsdk.State {
	t.Helper()
	val = ensureRegTokenLabels(val)
	s := tfsdk.State{Schema: schemaResp.Schema}
	diags := s.Set(ctx, val)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building state: %v", diags)
	}
	return s
}

// regTokenCreateCapture runs Create() against a fake 201 response (with optional extra
// response fields) and returns the captured POST body plus the final hydrated state.
func regTokenCreateCapture(t *testing.T, plan, config *CMRegTokenTFSDK, responseExtra string) (string, CMRegTokenTFSDK) {
	t.Helper()
	if config == nil {
		config = plan
	}
	var capturedBody string
	r, ctx, schemaResp := newTestCMRegTokenResource(t, func(w http.ResponseWriter, req *http.Request) {
		b := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(b)
		capturedBody = string(b)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":"regtoken-123"%s}`, responseExtra)
	})
	req := resource.CreateRequest{
		Plan:   mustRegTokenPlan(t, ctx, schemaResp, plan),
		Config: mustRegTokenConfig(t, ctx, schemaResp, config),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Create(): %v", resp.Diagnostics)
	}
	var final CMRegTokenTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	return capturedBody, final
}

// regTokenReadCapture runs Read() against a canned response body and returns the final state.
func regTokenReadCapture(t *testing.T, state *CMRegTokenTFSDK, responseBody string) CMRegTokenTFSDK {
	t.Helper()
	r, ctx, schemaResp := newTestCMRegTokenResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, responseBody)
	})
	req := resource.ReadRequest{State: mustRegTokenState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustRegTokenState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var final CMRegTokenTFSDK
	resp.State.Get(ctx, &final)
	return final
}

// regTokenUpdateCapture runs Update() against a canned response body and returns the
// captured PATCH body unmarshaled into a map[string]any (not a typed struct) so that an
// explicit JSON null and an omitted key remain distinguishable — Update() itself builds
// a map[string]any patch body for exactly this reason. The captured request URL path is
// also returned, for tests asserting Update() addresses state.ID rather than plan.ID.
func regTokenUpdateCapture(t *testing.T, plan, state *CMRegTokenTFSDK, responseBody string) (map[string]any, string, CMRegTokenTFSDK) {
	t.Helper()
	var capturedBody, capturedPath string
	r, ctx, schemaResp := newTestCMRegTokenResource(t, func(w http.ResponseWriter, req *http.Request) {
		b := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(b)
		capturedBody = string(b)
		capturedPath = req.URL.Path
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseBody)
	})
	req := resource.UpdateRequest{
		Plan:  mustRegTokenPlan(t, ctx, schemaResp, plan),
		State: mustRegTokenState(t, ctx, schemaResp, state),
	}
	resp := &resource.UpdateResponse{State: mustRegTokenState(t, ctx, schemaResp, state)}
	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(capturedBody), &payload); err != nil {
		t.Fatalf("failed to unmarshal PATCH payload: %v", err)
	}
	var final CMRegTokenTFSDK
	resp.State.Get(ctx, &final)
	return payload, capturedPath, final
}

// ---------------------------------------------------------------------------
// Create()
// ---------------------------------------------------------------------------

func Test_CM_RegToken_Create_AllOptionalFieldsOmitted(t *testing.T) {
	plan := &CMRegTokenTFSDK{}
	body, _ := regTokenCreateCapture(t, plan, nil, "")
	for _, unwanted := range []string{
		`"ca_id"`, `"cert_duration"`, `"client_management_profile_id"`,
		`"label"`, `"labels"`, `"lifetime"`, `"max_clients"`, `"name_prefix"`,
	} {
		if strings.Contains(body, unwanted) {
			t.Errorf("expected POST body to omit unconfigured field %s, got: %s", unwanted, body)
		}
	}
}

func Test_CM_RegToken_Create_LabelAndLabelsIndependentPayloads(t *testing.T) {
	// Regression guard: Create() previously had both the "label" and "labels" blocks
	// iterating plan.Labels (bug); verify each field's payload reflects its own map.
	plan := &CMRegTokenTFSDK{
		Label:  strMap(map[string]string{"KmipClientProfile": "p1"}),
		Labels: strMap(map[string]string{"env": "test"}),
	}
	body, _ := regTokenCreateCapture(t, plan, nil, "")
	if !strings.Contains(body, `"label":{"KmipClientProfile":"p1"}`) {
		t.Errorf("expected POST body to contain label payload, got: %s", body)
	}
	if !strings.Contains(body, `"labels":{"env":"test"}`) {
		t.Errorf("expected POST body to contain labels payload, got: %s", body)
	}
}

func Test_CM_RegToken_Create_EmptyStringOptionalsOmitted(t *testing.T) {
	plan := &CMRegTokenTFSDK{
		CAID:                      types.StringValue(""),
		ClientManagementProfileID: types.StringValue(""),
		NamePrefix:                types.StringValue(""),
		Lifetime:                  types.StringValue(""),
	}
	body, _ := regTokenCreateCapture(t, plan, nil, "")
	for _, unwanted := range []string{`"ca_id"`, `"client_management_profile_id"`, `"name_prefix"`, `"lifetime"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("expected POST body to omit empty-string field %s, got: %s", unwanted, body)
		}
	}
}

func Test_CM_RegToken_Create_HydratesIDAndToken(t *testing.T) {
	plan := &CMRegTokenTFSDK{}
	_, final := regTokenCreateCapture(t, plan, nil, `,"token":"secret-token-xyz"`)
	if final.ID.ValueString() != "regtoken-123" {
		t.Errorf("expected ID to be hydrated from response, got %q", final.ID.ValueString())
	}
	if final.Token.ValueString() != "secret-token-xyz" {
		t.Errorf("expected Token to be hydrated from response, got %q", final.Token.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Read()
// ---------------------------------------------------------------------------

func Test_CM_RegToken_Read_TokenPreservedWhenAPIOmits(t *testing.T) {
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Token: types.StringValue("orig-token")}
	final := regTokenReadCapture(t, state, `{"id":"rt-1"}`)
	if final.Token.ValueString() != "orig-token" {
		t.Errorf("expected token to be preserved when API omits it, got %q", final.Token.ValueString())
	}

	final2 := regTokenReadCapture(t, state, `{"id":"rt-1","token":"new-token"}`)
	if final2.Token.ValueString() != "new-token" {
		t.Errorf("expected token to be overwritten when API returns a non-empty value, got %q", final2.Token.ValueString())
	}
}

func Test_CM_RegToken_Read_CAIDNullGuard(t *testing.T) {
	// Never configured (state null): stays null even if the API returns a value.
	neverConfigured := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	final := regTokenReadCapture(t, neverConfigured, `{"id":"rt-1","ca_id":"ca-999"}`)
	if !final.CAID.IsNull() {
		t.Errorf("expected ca_id to stay null when never configured, got %q", final.CAID.ValueString())
	}

	// Configured (state non-null): hydrates from the response.
	configured := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), CAID: types.StringValue("stale-ca")}
	final2 := regTokenReadCapture(t, configured, `{"id":"rt-1","ca_id":"ca-999"}`)
	if final2.CAID.ValueString() != "ca-999" {
		t.Errorf("expected ca_id to hydrate to %q, got %q", "ca-999", final2.CAID.ValueString())
	}

	// Configured, but response omits it: becomes null.
	final3 := regTokenReadCapture(t, configured, `{"id":"rt-1"}`)
	if !final3.CAID.IsNull() {
		t.Errorf("expected ca_id to become null when response omits it, got %q", final3.CAID.ValueString())
	}
}

func Test_CM_RegToken_Read_ClientMgmtProfileIDUnconditionalHydrate(t *testing.T) {
	// Unlike ca_id, client_management_profile_id hydrates even when state was null —
	// needed so OOB PATCH drift is observable on the next refresh.
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	final := regTokenReadCapture(t, state, `{"id":"rt-1","client_management_profile_id":"prof-1"}`)
	if final.ClientManagementProfileID.ValueString() != "prof-1" {
		t.Errorf("expected client_management_profile_id to hydrate unconditionally, got %q", final.ClientManagementProfileID.ValueString())
	}
}

func Test_CM_RegToken_Read_ClientMgmtProfileIDExplicitJSONNull(t *testing.T) {
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), ClientManagementProfileID: types.StringValue("prof-old")}
	final := regTokenReadCapture(t, state, `{"id":"rt-1","client_management_profile_id":null}`)
	if !final.ClientManagementProfileID.IsNull() {
		t.Errorf("expected client_management_profile_id to become null on explicit JSON null, got %q", final.ClientManagementProfileID.ValueString())
	}
}

func Test_CM_RegToken_Read_LifetimeNeverOverwrittenWhenAbsent(t *testing.T) {
	// CM never returns lifetime in GET responses (write-only field) — Read() must not
	// null it out just because the response omits it.
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Lifetime: types.StringValue("30d")}
	final := regTokenReadCapture(t, state, `{"id":"rt-1"}`)
	if final.Lifetime.ValueString() != "30d" {
		t.Errorf("expected lifetime to be untouched when API never returns it, got %q", final.Lifetime.ValueString())
	}
}

func Test_CM_RegToken_Read_NamePrefixNullGuard(t *testing.T) {
	neverConfigured := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	final := regTokenReadCapture(t, neverConfigured, `{"id":"rt-1","name_prefix":"pre-"}`)
	if !final.NamePrefix.IsNull() {
		t.Errorf("expected name_prefix to stay null when never configured, got %q", final.NamePrefix.ValueString())
	}

	configured := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), NamePrefix: types.StringValue("stale-")}
	final2 := regTokenReadCapture(t, configured, `{"id":"rt-1","name_prefix":"pre-"}`)
	if final2.NamePrefix.ValueString() != "pre-" {
		t.Errorf("expected name_prefix to hydrate to %q, got %q", "pre-", final2.NamePrefix.ValueString())
	}

	final3 := regTokenReadCapture(t, configured, `{"id":"rt-1"}`)
	if !final3.NamePrefix.IsNull() {
		t.Errorf("expected name_prefix to become null when response omits it, got %q", final3.NamePrefix.ValueString())
	}
}

func Test_CM_RegToken_Read_CertDurationAndMaxClientsZeroVsNullGuard(t *testing.T) {
	neverConfigured := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	final := regTokenReadCapture(t, neverConfigured, `{"id":"rt-1","cert_duration":0,"max_clients":0}`)
	if !final.CertDuration.IsNull() || !final.MaxClients.IsNull() {
		t.Errorf("expected cert_duration/max_clients to stay null when never configured even if API returns 0, got cert_duration=%v max_clients=%v",
			final.CertDuration, final.MaxClients)
	}

	configured := &CMRegTokenTFSDK{
		ID:           types.StringValue("rt-1"),
		CertDuration: types.Int64Value(5),
		MaxClients:   types.Int64Value(10),
	}
	final2 := regTokenReadCapture(t, configured, `{"id":"rt-1"}`)
	if !final2.CertDuration.IsNull() || !final2.MaxClients.IsNull() {
		t.Errorf("expected cert_duration/max_clients to become null when response omits them, got cert_duration=%v max_clients=%v",
			final2.CertDuration, final2.MaxClients)
	}

	final3 := regTokenReadCapture(t, configured, `{"id":"rt-1","cert_duration":7,"max_clients":20}`)
	if final3.CertDuration.ValueInt64() != 7 || final3.MaxClients.ValueInt64() != 20 {
		t.Errorf("expected cert_duration/max_clients to hydrate to 7/20, got %d/%d",
			final3.CertDuration.ValueInt64(), final3.MaxClients.ValueInt64())
	}
}

func Test_CM_RegToken_Read_LabelThreeWayBranch(t *testing.T) {
	// label is only touched when state.Label is non-null.
	neverConfigured := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	final := regTokenReadCapture(t, neverConfigured, `{"id":"rt-1","label":{"KmipClientProfile":"p1"}}`)
	if !final.Label.IsNull() {
		t.Error("expected label to stay null when never configured, regardless of API response")
	}

	configured := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Label: strMap(map[string]string{"KmipClientProfile": "stale"})}

	// Response omits label entirely: becomes null.
	final2 := regTokenReadCapture(t, configured, `{"id":"rt-1"}`)
	if !final2.Label.IsNull() {
		t.Error("expected label to become null when response omits it")
	}

	// Response returns {}: becomes an empty (non-null) map.
	final3 := regTokenReadCapture(t, configured, `{"id":"rt-1","label":{}}`)
	if final3.Label.IsNull() || len(final3.Label.Elements()) != 0 {
		t.Errorf("expected label to become a non-null empty map on {} response, got %v", final3.Label)
	}

	// Response returns a populated map: hydrates.
	final4 := regTokenReadCapture(t, configured, `{"id":"rt-1","label":{"KmipClientProfile":"newval"}}`)
	elems := final4.Label.Elements()
	v, ok := elems["KmipClientProfile"]
	if !ok || v.(types.String).ValueString() != "newval" {
		t.Errorf("expected label to hydrate KmipClientProfile=newval, got %v", elems)
	}
}

func Test_CM_RegToken_Read_LabelsNeverConfiguredStaysNullOnEmptyResponse(t *testing.T) {
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	final := regTokenReadCapture(t, state, `{"id":"rt-1","labels":{}}`)
	if !final.Labels.IsNull() {
		t.Error("expected labels to stay null when never configured and API returns {}")
	}
}

func Test_CM_RegToken_Read_LabelsClearedOOBBecomesEmptyMap(t *testing.T) {
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Labels: strMap(map[string]string{"env": "test"})}
	final := regTokenReadCapture(t, state, `{"id":"rt-1","labels":{}}`)
	if final.Labels.IsNull() || len(final.Labels.Elements()) != 0 {
		t.Errorf("expected labels to become a non-null empty map after an OOB clear, got %v", final.Labels)
	}
}

func Test_CM_RegToken_Read_404IsErrorAndPreservesState(t *testing.T) {
	r, ctx, schemaResp := newTestCMRegTokenResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"reg token not found"}`)
	})

	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	objTypes := stateType.(tftypes.Object).AttributeTypes
	stateValues := make(map[string]tftypes.Value)
	for k, v := range objTypes {
		stateValues[k] = tftypes.NewValue(v, nil)
	}
	stateValues["id"] = tftypes.NewValue(tftypes.String, "rt-1")
	rawState := tftypes.NewValue(stateType, stateValues)

	req := resource.ReadRequest{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}

	r.Read(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("Read() on 404: expected an error diagnostic but got none")
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("Read() on 404: state was cleared — it should be preserved on error")
	}

	found := false
	wantSummary := fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "Registration Token")
	for _, e := range resp.Diagnostics.Errors() {
		if e.Summary() == wantSummary {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected an error diagnostic with summary %q, got: %v", wantSummary, resp.Diagnostics.Errors())
	}
}

// ---------------------------------------------------------------------------
// Update()
// ---------------------------------------------------------------------------

func Test_CM_RegToken_Update_ClientMgmtProfileIDAlwaysSentEvenEmpty(t *testing.T) {
	plan := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	payload, _, _ := regTokenUpdateCapture(t, plan, state, `{"id":"rt-1"}`)
	v, ok := payload["client_management_profile_id"]
	if !ok {
		t.Fatalf("expected client_management_profile_id key to always be present in PATCH body, got: %v", payload)
	}
	if v != "" {
		t.Errorf("expected client_management_profile_id to be sent as empty string, got %v", v)
	}
}

func Test_CM_RegToken_Update_LifetimeAlwaysSentEmptyWhenCleared(t *testing.T) {
	plan := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Lifetime: types.StringValue("30d")}
	payload, _, _ := regTokenUpdateCapture(t, plan, state, `{"id":"rt-1"}`)
	v, ok := payload["lifetime"]
	if !ok {
		t.Fatalf("expected lifetime key to always be present in PATCH body, got: %v", payload)
	}
	if v != "" {
		t.Errorf("expected lifetime to be sent as empty string when cleared, got %v", v)
	}
}

func Test_CM_RegToken_Update_LabelsOmittedWhenNeverConfigured(t *testing.T) {
	plan := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	payload, _, _ := regTokenUpdateCapture(t, plan, state, `{"id":"rt-1"}`)
	if _, ok := payload["labels"]; ok {
		t.Errorf("expected labels key to be omitted from PATCH body when never configured, got: %v", payload)
	}
}

func Test_CM_RegToken_Update_LabelsExplicitNullWhenCleared(t *testing.T) {
	plan := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Labels: strMap(map[string]string{"env": "test"})}
	payload, _, _ := regTokenUpdateCapture(t, plan, state, `{"id":"rt-1"}`)
	v, ok := payload["labels"]
	if !ok {
		t.Fatalf("expected labels key to be present (as explicit null) in PATCH body, got: %v", payload)
	}
	if v != nil {
		t.Errorf("expected labels to be explicit JSON null when cleared, got %v", v)
	}
}

func Test_CM_RegToken_Update_UsesStateIDNotPlanID(t *testing.T) {
	plan := &CMRegTokenTFSDK{ID: types.StringValue("plan-id-WRONG")}
	state := &CMRegTokenTFSDK{ID: types.StringValue("state-id-correct")}
	_, path, _ := regTokenUpdateCapture(t, plan, state, `{"id":"state-id-correct"}`)
	if !strings.Contains(path, "state-id-correct") {
		t.Errorf("expected PATCH request path to contain state.ID %q, got path %q", "state-id-correct", path)
	}
	if strings.Contains(path, "plan-id-WRONG") {
		t.Errorf("expected PATCH request path to NOT contain plan.ID, got path %q", path)
	}
}

func Test_CM_RegToken_Update_TokenPreservedFromState(t *testing.T) {
	plan := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Token: types.StringValue("plan-token-should-be-ignored")}
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1"), Token: types.StringValue("state-secret-token")}
	_, _, final := regTokenUpdateCapture(t, plan, state, `{"id":"rt-1"}`)
	if final.Token.ValueString() != "state-secret-token" {
		t.Errorf("expected token to be preserved from state, got %q", final.Token.ValueString())
	}
}

// ---------------------------------------------------------------------------
// Delete()
// ---------------------------------------------------------------------------

func Test_CM_RegToken_Delete_404IsWarningNotError(t *testing.T) {
	r, ctx, schemaResp := newTestCMRegTokenResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"reg token not found"}`)
	})
	state := &CMRegTokenTFSDK{ID: types.StringValue("rt-1")}
	req := resource.DeleteRequest{State: mustRegTokenState(t, ctx, schemaResp, state)}
	resp := &resource.DeleteResponse{State: mustRegTokenState(t, ctx, schemaResp, state)}
	r.Delete(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("expected no error diagnostics on 404 delete, got: %v", resp.Diagnostics)
	}
	found := false
	for _, w := range resp.Diagnostics.Warnings() {
		if w.Summary() == common.NotFoundDeleteWarningSummary {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a warning diagnostic with summary %q, got: %v", common.NotFoundDeleteWarningSummary, resp.Diagnostics.Warnings())
	}
}
