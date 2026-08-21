package cm

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_CMKeySchema_MaterialPasswordSaltWriteOnly verifies that material, password, and
// the nested hkdf_create_parameters.salt / wrap_hkdf.salt are all marked WriteOnly (never
// stored in state/plan artifacts). None of these carry a companion *_version attribute:
// Update() never resends any of them, so the only supported way to change them is to
// destroy and recreate the resource — matching their pre-existing (Immutable) behavior.
func Test_CMKeySchema_MaterialPasswordSaltWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCMKey{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	materialAttr, ok := resp.Schema.Attributes["material"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected material attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["material"])
	}
	if !materialAttr.WriteOnly {
		t.Error("expected material to be marked WriteOnly: true")
	}
	if !materialAttr.Sensitive {
		t.Error("expected material to remain marked Sensitive: true")
	}
	if len(materialAttr.PlanModifiers) != 0 {
		t.Error("expected material to carry no plan modifiers: a RequiresReplace/Immutable modifier on a " +
			"write-only attribute would compare the real config value against an always-null state value " +
			"and misfire on every plan")
	}

	passwordAttr, ok := resp.Schema.Attributes["password"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected password attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["password"])
	}
	if !passwordAttr.WriteOnly {
		t.Error("expected password to be marked WriteOnly: true")
	}
	if !passwordAttr.Sensitive {
		t.Error("expected password to remain marked Sensitive: true")
	}
	if len(passwordAttr.PlanModifiers) != 0 {
		t.Error("expected password to carry no plan modifiers")
	}

	hkdfCreateAttr, ok := resp.Schema.Attributes["hkdf_create_parameters"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("expected hkdf_create_parameters to be schema.SingleNestedAttribute, got %T", resp.Schema.Attributes["hkdf_create_parameters"])
	}
	hkdfCreateSaltAttr, ok := hkdfCreateAttr.Attributes["salt"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected hkdf_create_parameters.salt to be schema.StringAttribute, got %T", hkdfCreateAttr.Attributes["salt"])
	}
	if !hkdfCreateSaltAttr.WriteOnly {
		t.Error("expected hkdf_create_parameters.salt to be marked WriteOnly: true")
	}
	if !hkdfCreateSaltAttr.Sensitive {
		t.Error("expected hkdf_create_parameters.salt to be marked Sensitive: true")
	}

	wrapHKDFAttr, ok := resp.Schema.Attributes["wrap_hkdf"].(schema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("expected wrap_hkdf to be schema.SingleNestedAttribute, got %T", resp.Schema.Attributes["wrap_hkdf"])
	}
	wrapHKDFSaltAttr, ok := wrapHKDFAttr.Attributes["salt"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected wrap_hkdf.salt to be schema.StringAttribute, got %T", wrapHKDFAttr.Attributes["salt"])
	}
	if !wrapHKDFSaltAttr.WriteOnly {
		t.Error("expected wrap_hkdf.salt to be marked WriteOnly: true")
	}
	if !wrapHKDFSaltAttr.Sensitive {
		t.Error("expected wrap_hkdf.salt to be marked Sensitive: true")
	}
}

// newCMKeyRawValue builds a tftypes.Value covering every attribute declared in
// resourceCMKey's Schema(), defaulting every attribute to null and applying the given
// overrides.
func newCMKeyRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
	objType, ok := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	if !ok {
		panic("expected schema type to be tftypes.Object")
	}
	values := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for name, attrType := range objType.AttributeTypes {
		if v, ok := overrides[name]; ok {
			values[name] = v
			continue
		}
		values[name] = tftypes.NewValue(attrType, nil)
	}
	return tftypes.NewValue(objType, values)
}

// Test_CMKeyCreate_MaterialPasswordSaltReadFromConfigNotPlan proves that Create() reads
// material, password, hkdf_create_parameters.salt, and wrap_hkdf.salt from req.Config
// rather than req.Plan. This matters because the framework nulls WriteOnly attributes out
// of the plan before Create() ever runs; reading from plan (the pre-fix behavior) would
// silently send empty values to CM instead of what the user configured.
func Test_CMKeyCreate_MaterialPasswordSaltReadFromConfigNotPlan(t *testing.T) {
	const wantMaterial = "000102030405060708090a0b0c0d0e0f"
	const wantPassword = "cGFzc3dvcmQ="
	const wantCreateSalt = "aabbccdd"
	const wantWrapSalt = "eeff0011"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/"+common.URL_KEY_MANAGEMENT, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"key-1"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMKey{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	objType, ok := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	if !ok {
		t.Fatalf("expected schema type to be tftypes.Object")
	}
	hkdfCreateType, ok := objType.AttributeTypes["hkdf_create_parameters"].(tftypes.Object)
	if !ok {
		t.Fatalf("expected hkdf_create_parameters to be tftypes.Object")
	}
	wrapHKDFType, ok := objType.AttributeTypes["wrap_hkdf"].(tftypes.Object)
	if !ok {
		t.Fatalf("expected wrap_hkdf to be tftypes.Object")
	}

	buildHKDFCreate := func(salt interface{}) tftypes.Value {
		return tftypes.NewValue(hkdfCreateType, map[string]tftypes.Value{
			"hash_algorithm": tftypes.NewValue(tftypes.String, "hmac-sha256"),
			"ikm_key_name":   tftypes.NewValue(tftypes.String, "ikm-key"),
			"info":           tftypes.NewValue(tftypes.String, "info-value"),
			"salt":           tftypes.NewValue(tftypes.String, salt),
		})
	}
	buildWrapHKDF := func(salt interface{}) tftypes.Value {
		return tftypes.NewValue(wrapHKDFType, map[string]tftypes.Value{
			"hash_algorithm": tftypes.NewValue(tftypes.String, "hmac-sha256"),
			"okm_len":        tftypes.NewValue(tftypes.Number, nil),
			"info":           tftypes.NewValue(tftypes.String, "info-value"),
			"salt":           tftypes.NewValue(tftypes.String, salt),
		})
	}

	commonOverrides := map[string]tftypes.Value{
		"name":      tftypes.NewValue(tftypes.String, "tf-key"),
		"algorithm": tftypes.NewValue(tftypes.String, "aes"),
	}

	// Plan: material/password/salts are null, exactly as the framework leaves them for
	// WriteOnly attributes before Create() runs.
	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["material"] = tftypes.NewValue(tftypes.String, nil)
	planOverrides["password"] = tftypes.NewValue(tftypes.String, nil)
	planOverrides["hkdf_create_parameters"] = buildHKDFCreate(nil)
	planOverrides["wrap_hkdf"] = buildWrapHKDF(nil)
	planValue := newCMKeyRawValue(ctx, schemaResp, planOverrides)

	// Config: the real HCL-configured values.
	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["material"] = tftypes.NewValue(tftypes.String, wantMaterial)
	configOverrides["password"] = tftypes.NewValue(tftypes.String, wantPassword)
	configOverrides["hkdf_create_parameters"] = buildHKDFCreate(wantCreateSalt)
	configOverrides["wrap_hkdf"] = buildWrapHKDF(wantWrapSalt)
	configValue := newCMKeyRawValue(ctx, schemaResp, configOverrides)

	req := resource.CreateRequest{
		Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: configValue},
	}
	resp := &resource.CreateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema},
	}

	r.Create(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Create(): %v", resp.Diagnostics)
	}

	for _, want := range []string{
		fmt.Sprintf(`"material":%q`, wantMaterial),
		fmt.Sprintf(`"password":%q`, wantPassword),
		fmt.Sprintf(`"salt":%q`, wantCreateSalt),
		fmt.Sprintf(`"salt":%q`, wantWrapSalt),
	} {
		if !strings.Contains(capturedBody, want) {
			t.Errorf("expected request payload to contain %s (read from config), got body: %s", want, capturedBody)
		}
	}

	var final CMKeyTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.Material.IsNull() {
		t.Errorf("expected material to be null in state (write-only), got %q", final.Material.ValueString())
	}
	if !final.Password.IsNull() {
		t.Errorf("expected password to be null in state (write-only), got %q", final.Password.ValueString())
	}
	if final.HKDFCreateParameters != nil && !final.HKDFCreateParameters.Salt.IsNull() {
		t.Errorf("expected hkdf_create_parameters.salt to be null in state (write-only), got %q", final.HKDFCreateParameters.Salt.ValueString())
	}
	if final.HKDFWrap != nil && !final.HKDFWrap.Salt.IsNull() {
		t.Errorf("expected wrap_hkdf.salt to be null in state (write-only), got %q", final.HKDFWrap.Salt.ValueString())
	}
}
