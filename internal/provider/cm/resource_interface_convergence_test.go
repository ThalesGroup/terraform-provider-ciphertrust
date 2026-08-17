package cm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

const convergenceIfaceName = "nae"

// newInterfaceTestClient builds a common.Client pointed at the given test server.
func newInterfaceTestClient(server *httptest.Server) *common.Client {
	return &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}
}

// interfaceSchemaForTest returns the resource schema, failing the test on diagnostics.
func interfaceSchemaForTest(t *testing.T, ctx context.Context, r *resourceCMInterface) resource.SchemaResponse {
	t.Helper()
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}
	return schemaResp
}

// tlsCipherSetValue builds a tftypes Set value for the tls_ciphers attribute from
// (cipher_suite, enabled) pairs, in the given order.
func tlsCipherSetValue(ctx context.Context, schemaResp resource.SchemaResponse, suites []string, enabled []bool) tftypes.Value {
	objType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	setType := objType.AttributeTypes["tls_ciphers"].(tftypes.Set)
	elemType := setType.ElementType.(tftypes.Object)

	elems := make([]tftypes.Value, 0, len(suites))
	for i, suite := range suites {
		elems = append(elems, tftypes.NewValue(elemType, map[string]tftypes.Value{
			"cipher_suite": tftypes.NewValue(tftypes.String, suite),
			"enabled":      tftypes.NewValue(tftypes.Bool, enabled[i]),
		}))
	}
	return tftypes.NewValue(setType, elems)
}

// Test_CMInterfaceSchema_TLSCiphersIsSetNotList locks in the fix for the tls_ciphers
// non-convergence bug. CM returns the cipher-suite entries in an arbitrary, unstable order
// on every GET. While the attribute was schema-typed as an order-sensitive
// ListNestedAttribute, every refresh rewrote state in CM's latest order and then re-planned
// a diff against the config's order — the resource never converged, even when the
// configured members exactly matched CM's own current set. Reverting this to a List would
// silently reintroduce that bug, so assert the type directly.
func Test_CMInterfaceSchema_TLSCiphersIsSetNotList(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCMInterface{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	attr := resp.Schema.Attributes["tls_ciphers"]
	if _, isList := attr.(schema.ListNestedAttribute); isList {
		t.Fatal("tls_ciphers is a ListNestedAttribute: ordering is significant, so CM's unstable " +
			"element order makes the resource re-plan forever. It must be a SetNestedAttribute.")
	}
	setAttr, ok := attr.(schema.SetNestedAttribute)
	if !ok {
		t.Fatalf("expected tls_ciphers to be schema.SetNestedAttribute, got %T", attr)
	}
	for _, nested := range []string{"cipher_suite", "enabled"} {
		if _, ok := setAttr.NestedObject.Attributes[nested]; !ok {
			t.Errorf("expected tls_ciphers nested object to retain attribute %q", nested)
		}
	}
}

// Test_CMInterfaceRead_TLSCiphersReorderedByCMConverges is the behavioural half of the
// tls_ciphers fix: it proves that when CM returns exactly the configured cipher-suite
// members but in a different order, Read() produces a state value that is *equal* to the
// prior state, so Terraform reports no diff. SetValue.Equal compares length plus membership
// (not index-by-index), which is precisely why the Set type fixes this and a List cannot.
func Test_CMInterfaceRead_TLSCiphersReorderedByCMConverges(t *testing.T) {
	// Same three members as the state below, deliberately shuffled — this mirrors the real
	// CM behaviour reported in the ticket.
	body := fmt.Sprintf(`{
		"id":"iface-1","name":%q,"port":9000,"interface_type":"nae",
		"createdAt":"c","updatedAt":"u",
		"tls_ciphers":[
			{"cipher_suite":"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256","enabled":false,"hex_code":"0xc02b"},
			{"cipher_suite":"TLS_AES_256_GCM_SHA384","enabled":true,"hex_code":"0x1302"},
			{"cipher_suite":"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","enabled":true,"hex_code":"0xc030"}
		]
	}`, convergenceIfaceName)

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_INTERFACE+"/"+convergenceIfaceName, handler)
	mux.HandleFunc("/"+common.URL_INTERFACE+"/", handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	r := &resourceCMInterface{client: newInterfaceTestClient(server)}
	ctx := context.Background()
	schemaResp := interfaceSchemaForTest(t, ctx, r)

	// Prior state: the user's configured order (alphabetical-ish), which is NOT CM's order.
	suites := []string{
		"TLS_AES_256_GCM_SHA384",
		"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	}
	enabled := []bool{true, false, true}

	rawState := newInterfaceRawValue(ctx, schemaResp, map[string]tftypes.Value{
		"id":             tftypes.NewValue(tftypes.String, "iface-1"),
		"name":           tftypes.NewValue(tftypes.String, convergenceIfaceName),
		"port":           tftypes.NewValue(tftypes.Number, int64(9000)),
		"interface_type": tftypes.NewValue(tftypes.String, "nae"),
		"created_at":     tftypes.NewValue(tftypes.String, "c"),
		"updated_at":     tftypes.NewValue(tftypes.String, "u"),
		"tls_ciphers":    tlsCipherSetValue(ctx, schemaResp, suites, enabled),
	})

	req := resource.ReadRequest{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read(): %v", resp.Diagnostics)
	}

	setAttrType, ok := schemaResp.Schema.Attributes["tls_ciphers"].GetType().(types.SetType)
	if !ok {
		t.Fatalf("expected tls_ciphers attr type to be types.SetType, got %T",
			schemaResp.Schema.Attributes["tls_ciphers"].GetType())
	}
	want, diags := types.SetValueFrom(ctx, setAttrType.ElementType(), []TLSCiphersTFSDK{
		{CipherSuite: types.StringValue(suites[0]), Enabled: types.BoolValue(enabled[0])},
		{CipherSuite: types.StringValue(suites[1]), Enabled: types.BoolValue(enabled[1])},
		{CipherSuite: types.StringValue(suites[2]), Enabled: types.BoolValue(enabled[2])},
	})
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building expected set: %v", diags)
	}

	var got types.Set
	if diags := resp.State.GetAttribute(ctx, path.Root("tls_ciphers"), &got); diags.HasError() {
		t.Fatalf("unexpected diagnostics reading tls_ciphers from state: %v", diags)
	}

	if !got.Equal(want) {
		t.Errorf("tls_ciphers did not converge after Read():\n got: %s\nwant: %s\n"+
			"CM returned the same members in a different order; state must compare equal so no diff is planned.",
			got.String(), want.String())
	}
}

// Test_CMInterfaceRead_AutoGenCAIdEmptyStringPreserved proves that Read() keeps an explicit
// auto_gen_ca_id = "" in state instead of collapsing it to null. Setting the field to an
// empty string is the documented way to disable server-certificate auto-generation, and CM
// echoes the key back with an empty value (live-confirmed: PATCH {"auto_gen_ca_id":""}
// returns 200 with "auto_gen_ca_id":"" and the subsequent GET agrees). The pre-fix guard
// `r.Exists() && r.String() != ""` discarded that, so state flipped to null on every
// refresh and config's "" re-planned forever.
func Test_CMInterfaceRead_AutoGenCAIdEmptyStringPreserved(t *testing.T) {
	body := fmt.Sprintf(`{"id":"iface-1","name":%q,"port":9000,"interface_type":"nae",
		"createdAt":"c","updatedAt":"u","auto_gen_ca_id":""}`, convergenceIfaceName)

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_INTERFACE+"/"+convergenceIfaceName, handler)
	mux.HandleFunc("/"+common.URL_INTERFACE+"/", handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	r := &resourceCMInterface{client: newInterfaceTestClient(server)}
	ctx := context.Background()
	schemaResp := interfaceSchemaForTest(t, ctx, r)

	rawState := newInterfaceRawValue(ctx, schemaResp, map[string]tftypes.Value{
		"id":             tftypes.NewValue(tftypes.String, "iface-1"),
		"name":           tftypes.NewValue(tftypes.String, convergenceIfaceName),
		"port":           tftypes.NewValue(tftypes.Number, int64(9000)),
		"interface_type": tftypes.NewValue(tftypes.String, "nae"),
		"created_at":     tftypes.NewValue(tftypes.String, "c"),
		"updated_at":     tftypes.NewValue(tftypes.String, "u"),
		"auto_gen_ca_id": tftypes.NewValue(tftypes.String, ""),
	})

	req := resource.ReadRequest{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read(): %v", resp.Diagnostics)
	}

	var final CMInterfaceTFSDK
	if diags := resp.State.Get(ctx, &final); diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}

	if final.AutogenCAId.IsNull() {
		t.Error("auto_gen_ca_id collapsed to null: an explicit \"\" (auto-generation disabled) " +
			"must be preserved in state, otherwise the config value re-plans on every refresh")
	}
	if got := final.AutogenCAId.ValueString(); got != "" {
		t.Errorf("expected auto_gen_ca_id to remain %q, got %q", "", got)
	}
}

// Test_CMInterfaceRead_AutoGenCAIdDriftFromCAToEmptyDetected guards the other side of the
// same fix: preserving "" must not turn into blindly holding whatever state already had. If
// auto-generation is disabled out of band (CM now reports ""), a stale Local CA URI in state
// has to be overwritten so the drift is surfaced.
func Test_CMInterfaceRead_AutoGenCAIdDriftFromCAToEmptyDetected(t *testing.T) {
	const staleCA = "kylo:kylo:naboo:localca:262441b1-b1a5-4044-a903-14bb91969c4d"

	body := fmt.Sprintf(`{"id":"iface-1","name":%q,"port":9000,"interface_type":"nae",
		"createdAt":"c","updatedAt":"u","auto_gen_ca_id":""}`, convergenceIfaceName)

	handler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_INTERFACE+"/"+convergenceIfaceName, handler)
	mux.HandleFunc("/"+common.URL_INTERFACE+"/", handler)
	server := httptest.NewServer(mux)
	defer server.Close()

	r := &resourceCMInterface{client: newInterfaceTestClient(server)}
	ctx := context.Background()
	schemaResp := interfaceSchemaForTest(t, ctx, r)

	rawState := newInterfaceRawValue(ctx, schemaResp, map[string]tftypes.Value{
		"id":             tftypes.NewValue(tftypes.String, "iface-1"),
		"name":           tftypes.NewValue(tftypes.String, convergenceIfaceName),
		"port":           tftypes.NewValue(tftypes.Number, int64(9000)),
		"interface_type": tftypes.NewValue(tftypes.String, "nae"),
		"created_at":     tftypes.NewValue(tftypes.String, "c"),
		"updated_at":     tftypes.NewValue(tftypes.String, "u"),
		"auto_gen_ca_id": tftypes.NewValue(tftypes.String, staleCA),
	})

	req := resource.ReadRequest{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}
	resp := &resource.ReadResponse{State: tfsdk.State{Schema: schemaResp.Schema, Raw: rawState}}

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read(): %v", resp.Diagnostics)
	}

	var final CMInterfaceTFSDK
	if diags := resp.State.Get(ctx, &final); diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}

	// Assert the value is a *known* "" rather than null. types.String.ValueString() returns
	// "" for a null value too, so checking only the string would pass vacuously against the
	// pre-fix behaviour (which set StringNull() here).
	if final.AutogenCAId.IsNull() {
		t.Error("expected auto_gen_ca_id to become a known \"\" reflecting CM's disabled state, got null")
	}
	if got := final.AutogenCAId.ValueString(); got != "" {
		t.Errorf("expected stale CA URI to be overwritten with %q so the drift surfaces, got %q", "", got)
	}
}

// Test_CMInterfaceCreate_AutoGenCAIdEmptyStringPreserved is the Create()-path counterpart of
// Test_CMInterfaceRead_AutoGenCAIdEmptyStringPreserved: creating an interface with
// auto_gen_ca_id = "" must land "" in state, not null. Returning null where the plan said ""
// would fail Terraform's "Provider produced inconsistent result after apply" check.
func Test_CMInterfaceCreate_AutoGenCAIdEmptyStringPreserved(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_INTERFACE, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"iface-1","port":9000,"interface_type":"nae",
			"createdAt":"c","updatedAt":"u","auto_gen_ca_id":""}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	r := &resourceCMInterface{client: newInterfaceTestClient(server)}
	ctx := context.Background()
	schemaResp := interfaceSchemaForTest(t, ctx, r)

	overrides := map[string]tftypes.Value{
		"port":           tftypes.NewValue(tftypes.Number, int64(9000)),
		"interface_type": tftypes.NewValue(tftypes.String, "nae"),
		"auto_gen_ca_id": tftypes.NewValue(tftypes.String, ""),
	}
	rawValue := newInterfaceRawValue(ctx, schemaResp, overrides)

	req := resource.CreateRequest{
		Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: rawValue},
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: rawValue},
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}

	r.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Create(): %v", resp.Diagnostics)
	}

	var final CMInterfaceTFSDK
	if diags := resp.State.Get(ctx, &final); diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}

	if final.AutogenCAId.IsNull() {
		t.Error("auto_gen_ca_id collapsed to null after Create(): the plan said \"\", so state must " +
			"say \"\" too or Terraform rejects the apply as an inconsistent result")
	}
	if got := final.AutogenCAId.ValueString(); got != "" {
		t.Errorf("expected auto_gen_ca_id to be %q in state, got %q", "", got)
	}
}
