package connections

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	datasourceschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_AWSConnectionSchema_SecretAccessKeyWriteOnly verifies that
// ciphertrust_aws_connection.secret_access_key is marked WriteOnly (never stored in
// state/plan artifacts, per the AWS connection SecScan finding) and that
// secret_access_key_version exists as the companion state-tracked rotation trigger.
// access_key_id must remain unaffected: it is not a true secret (CM echoes it back on
// GET), so it keeps its existing Computed-based drift detection instead of going
// write-only.
func Test_AWSConnectionSchema_SecretAccessKeyWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCCKMAWSConnection{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	secretAttr, ok := resp.Schema.Attributes["secret_access_key"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected secret_access_key attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["secret_access_key"])
	}
	if !secretAttr.WriteOnly {
		t.Error("expected secret_access_key schema attribute to be marked WriteOnly: true")
	}
	if !secretAttr.Sensitive {
		t.Error("expected secret_access_key schema attribute to remain marked Sensitive: true")
	}
	if secretAttr.Computed {
		t.Error("expected secret_access_key schema attribute to no longer be Computed (WriteOnly attributes cannot be Computed)")
	}

	if _, ok := resp.Schema.Attributes["secret_access_key_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected secret_access_key_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["secret_access_key_version"])
	}

	accessKeyAttr, ok := resp.Schema.Attributes["access_key_id"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected access_key_id attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["access_key_id"])
	}
	if accessKeyAttr.WriteOnly {
		t.Error("access_key_id must not be WriteOnly: it is not a true secret (CM echoes it back on GET) and relies on Computed-based drift detection")
	}
	if !accessKeyAttr.Computed {
		t.Error("access_key_id must remain Computed for its existing drift-detection behavior")
	}
}

// newAWSConnectionRawValue builds a tftypes.Value covering every attribute declared in
// resourceCCKMAWSConnection's Schema(), defaulting every attribute to null and applying
// the given overrides. Attribute types (including the nested iam_role_anywhere object,
// and the labels/meta/products collection types) are derived from the schema itself, so
// this helper does not need to hand-duplicate the nested type shapes.
func newAWSConnectionRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
	objType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
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

// Test_AWSConnectionCreate_SecretAccessKeyReadFromConfigNotPlan proves that Create()
// reads secret_access_key from req.Config rather than req.Plan. This matters because the
// framework nulls WriteOnly attributes out of the plan before Create() ever runs; reading
// from plan (the pre-fix behavior) would silently send an empty secret to CM instead of
// the value the user configured.
func Test_AWSConnectionCreate_SecretAccessKeyReadFromConfigNotPlan(t *testing.T) {
	const wantSecret = "shhh-its-a-secret"

	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"conn-id-1","uri":"u","account":"a","devAccount":"d","application":"app","createdAt":"c","updatedAt":"u","category":"cat","service":"svc","resource_url":"ru"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCCKMAWSConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name":             tftypes.NewValue(tftypes.String, "my-conn"),
		"is_role_anywhere": tftypes.NewValue(tftypes.Bool, false),
	}

	// Plan: secret_access_key is null, exactly as the framework leaves it for a
	// WriteOnly attribute before Create() runs.
	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["secret_access_key"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newAWSConnectionRawValue(ctx, schemaResp, planOverrides)

	// Config: secret_access_key carries the actual HCL-configured value.
	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["secret_access_key"] = tftypes.NewValue(tftypes.String, wantSecret)
	configValue := newAWSConnectionRawValue(ctx, schemaResp, configOverrides)

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

	if want := fmt.Sprintf(`"secret_access_key":%q`, wantSecret); !strings.Contains(capturedBody, want) {
		t.Errorf("expected request payload to contain %s (read from config), got body: %s", want, capturedBody)
	}

	var final AWSConnectionModelTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.SecretAccessKey.IsNull() {
		t.Errorf("expected secret_access_key to be null in state (write-only), got %q", final.SecretAccessKey.ValueString())
	}
}

// Test_AWSConnectionCreate_NullConfigSecretNeverSentAsLiteralNullString is a regression
// test for a real bug caught live against CipherTrust Manager: types.String.String()
// returns the literal text "<null>" (not "") when the value is null. Code that guards
// on TrimString(config.Field.String()) != "" therefore treats a null config value as
// non-empty and sends the literal string "<null>" to CM — exactly what broke IAM
// Roles Anywhere connections, where CM requires secret_access_key to be absent/null and
// rejected the literal string with "Secret Access Key should be null". The fix uses
// config.Field.ValueString() directly, which correctly returns "" for null.
func Test_AWSConnectionCreate_NullConfigSecretNeverSentAsLiteralNullString(t *testing.T) {
	var capturedBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"conn-id-1"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCCKMAWSConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	// is_role_anywhere=true, secret_access_key left completely unconfigured (null) in
	// both plan and config — mirrors an IAM Roles Anywhere connection.
	overrides := map[string]tftypes.Value{
		"name":              tftypes.NewValue(tftypes.String, "my-conn"),
		"is_role_anywhere":  tftypes.NewValue(tftypes.Bool, true),
		"secret_access_key": tftypes.NewValue(tftypes.String, nil),
	}
	planValue := newAWSConnectionRawValue(ctx, schemaResp, overrides)
	configValue := newAWSConnectionRawValue(ctx, schemaResp, overrides)

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

	if strings.Contains(capturedBody, "<null>") {
		t.Errorf("regression: request payload contains the literal string \"<null>\" instead of omitting the field: %s", capturedBody)
	}
}

// Test_AWSConnectionUpdate_SecretAccessKeyVersionGatesResend proves that Update() only
// re-sends secret_access_key to CM when secret_access_key_version changes between state
// and plan. Since secret_access_key is write-only (never stored in state), it cannot be
// diffed on its own — secret_access_key_version is the explicit signal that the caller
// wants the current value re-sent. Without this gate, secret_access_key would either
// never be resendable, or (the pre-fix bug) get silently restored from empty prior state.
func Test_AWSConnectionUpdate_SecretAccessKeyVersionGatesResend(t *testing.T) {
	const connID = "conn-id-1"

	tests := []struct {
		name         string
		stateVersion int64
		planVersion  int64
		configSecret string
		expectInBody bool
	}{
		{
			name:         "version unchanged: secret omitted from payload",
			stateVersion: 1,
			planVersion:  1,
			configSecret: "unused-secret",
			expectInBody: false,
		},
		{
			name:         "version bumped: secret included from config",
			stateVersion: 1,
			planVersion:  2,
			configSecret: "rotated-secret",
			expectInBody: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedPatchBody string
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodPatch:
					body, _ := io.ReadAll(r.Body)
					capturedPatchBody = string(body)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"id":%q}`, connID)
				case http.MethodGet:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"id":%q}`, connID)
				default:
					t.Fatalf("unexpected method %s", r.Method)
				}
			})
			server := httptest.NewServer(mux)
			defer server.Close()

			client := &common.Client{
				CipherTrustURL: server.URL,
				HTTPClient:     server.Client(),
				Log:            hclog.NewNullLogger(),
			}

			r := &resourceCCKMAWSConnection{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":                tftypes.NewValue(tftypes.String, connID),
				"name":              tftypes.NewValue(tftypes.String, "my-conn"),
				"is_role_anywhere":  tftypes.NewValue(tftypes.Bool, false),
				"secret_access_key": tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["secret_access_key_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newAWSConnectionRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["secret_access_key_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newAWSConnectionRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["secret_access_key"] = tftypes.NewValue(tftypes.String, tc.configSecret)
			configOverrides["secret_access_key_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newAWSConnectionRawValue(ctx, schemaResp, configOverrides)

			req := resource.UpdateRequest{
				Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
				Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: configValue},
				State:  tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
			}
			resp := &resource.UpdateResponse{
				State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
			}

			r.Update(ctx, req, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics from Update(): %v", resp.Diagnostics)
			}

			want := fmt.Sprintf(`"secret_access_key":%q`, tc.configSecret)
			got := strings.Contains(capturedPatchBody, want)
			if got != tc.expectInBody {
				t.Errorf("expected secret_access_key present in PATCH body = %v, got %v (body: %s)", tc.expectInBody, got, capturedPatchBody)
			}

			var final AWSConnectionModelTFSDK
			diags := resp.State.Get(ctx, &final)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
			}
			if !final.SecretAccessKey.IsNull() {
				t.Errorf("expected secret_access_key to be null in state (write-only), got %q", final.SecretAccessKey.ValueString())
			}
		})
	}
}

// Test_CM_AWSConnection_DescriptionDoubleQuotes verifies that a description containing
// literal double quotes is sent to CM exactly as a raw string without backslash corruption (TFIN-482).
func Test_CM_AWSConnection_DescriptionDoubleQuotes(t *testing.T) {
	const wantDesc = `a "quoted" description`
	var capturedBody string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"conn-id-1"}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCCKMAWSConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	overrides := map[string]tftypes.Value{
		"name":             tftypes.NewValue(tftypes.String, "my-conn"),
		"description":      tftypes.NewValue(tftypes.String, wantDesc),
		"is_role_anywhere": tftypes.NewValue(tftypes.Bool, false),
	}
	planValue := newAWSConnectionRawValue(ctx, schemaResp, overrides)
	configValue := newAWSConnectionRawValue(ctx, schemaResp, overrides)

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

	// Double quotes should be escaped normally by JSON marshaling, not double-escaped.
	expectedJSONPart := `"description":"a \"quoted\" description"`
	if !strings.Contains(capturedBody, expectedJSONPart) {
		t.Errorf("expected request payload to contain %s, got: %s", expectedJSONPart, capturedBody)
	}
}

// Test_CM_AWSConnection_ProductsEmptySliceClearing verifies that when products is cleared
// (empty list configured in HCL), the PATCH payload carries "products":[] to CM (TFIN-479).
func Test_CM_AWSConnection_ProductsEmptySliceClearing(t *testing.T) {
	const connID = "conn-id-1"
	var capturedPatchBody string

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			body, _ := io.ReadAll(r.Body)
			capturedPatchBody = string(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"id":%q}`, connID)
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `{"id":%q}`, connID)
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCCKMAWSConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	baseOverrides := map[string]tftypes.Value{
		"id":               tftypes.NewValue(tftypes.String, connID),
		"name":             tftypes.NewValue(tftypes.String, "my-conn"),
		"is_role_anywhere": tftypes.NewValue(tftypes.Bool, false),
	}

	// Prior state had 1 product ["cckm"]
	stateOverrides := map[string]tftypes.Value{}
	for k, v := range baseOverrides {
		stateOverrides[k] = v
	}
	stateOverrides["products"] = tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
		tftypes.NewValue(tftypes.String, "cckm"),
	})
	stateValue := newAWSConnectionRawValue(ctx, schemaResp, stateOverrides)

	// Plan has cleared products: []
	planOverrides := map[string]tftypes.Value{}
	for k, v := range baseOverrides {
		planOverrides[k] = v
	}
	planOverrides["products"] = tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{})
	planValue := newAWSConnectionRawValue(ctx, schemaResp, planOverrides)

	req := resource.UpdateRequest{
		Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: planValue},
		State:  tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
	}
	resp := &resource.UpdateResponse{
		State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
	}

	r.Update(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Update(): %v", resp.Diagnostics)
	}

	expectedJSONPart := `"products":[]`
	if !strings.Contains(capturedPatchBody, expectedJSONPart) {
		t.Errorf("expected request payload to contain %s, got: %s", expectedJSONPart, capturedPatchBody)
	}
}

// Test_CM_AWSConnectionList_InvalidFilterKey verifies that specifying an unsupported key in the
// data source's filters attribute results in an error diagnostic (TFIN-484).
func Test_CM_AWSConnectionList_InvalidFilterKey(t *testing.T) {
	d := NewDataSourceAWSConnection()
	ctx := context.Background()

	var schemaResp datasource.SchemaResponse
	d.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	configType := schemaResp.Schema.Type().TerraformType(ctx).(tftypes.Object)
	configValue := tftypes.NewValue(configType, map[string]tftypes.Value{
		"filters": tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, map[string]tftypes.Value{
			"totally_bogus_key": tftypes.NewValue(tftypes.String, "xyz"),
		}),
		"aws": tftypes.NewValue(configType.AttributeTypes["aws"], nil),
	})

	req := datasource.ReadRequest{
		Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: configValue},
	}
	resp := &datasource.ReadResponse{
		State: tfsdk.State{Schema: schemaResp.Schema},
	}

	d.Read(ctx, req, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic when using an invalid filter key, but got none")
	}

	foundExpectedError := false
	for _, diag := range resp.Diagnostics.Errors() {
		if strings.Contains(diag.Summary(), "Invalid Filter Key") {
			foundExpectedError = true
			break
		}
	}

	if !foundExpectedError {
		t.Errorf("expected diagnostics error to contain 'Invalid Filter Key', got: %v", resp.Diagnostics)
	}
}

// Test_CM_AWSConnectionList_SensitiveFields verifies that credentials-related attributes
// are marked as Sensitive: true in the AWS connection data source schema (TFIN-485).
func Test_CM_AWSConnectionList_SensitiveFields(t *testing.T) {
	d := NewDataSourceAWSConnection()
	ctx := context.Background()

	var schemaResp datasource.SchemaResponse
	d.Schema(ctx, datasource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	awsListAttr, ok := schemaResp.Schema.Attributes["aws"]
	if !ok {
		t.Fatal("expected 'aws' attribute in schema")
	}

	listNestedAttr, ok := awsListAttr.(datasourceschema.ListNestedAttribute)
	if !ok {
		t.Fatalf("expected 'aws' to be a ListNestedAttribute, got %T", awsListAttr)
	}

	secretAccessKeyAttr, ok := listNestedAttr.NestedObject.Attributes["secret_access_key"]
	if !ok {
		t.Fatal("expected 'secret_access_key' under 'aws' nested object")
	}

	strAttr, ok := secretAccessKeyAttr.(datasourceschema.StringAttribute)
	if !ok {
		t.Fatalf("expected 'secret_access_key' to be StringAttribute, got %T", secretAccessKeyAttr)
	}

	if !strAttr.Sensitive {
		t.Error("expected 'secret_access_key' to be marked Sensitive: true")
	}

	iamRoleAnywhereAttr, ok := listNestedAttr.NestedObject.Attributes["iam_role_anywhere"]
	if !ok {
		t.Fatal("expected 'iam_role_anywhere' under 'aws' nested object")
	}

	nestedAttr, ok := iamRoleAnywhereAttr.(datasourceschema.SingleNestedAttribute)
	if !ok {
		t.Fatalf("expected 'iam_role_anywhere' to be SingleNestedAttribute, got %T", iamRoleAnywhereAttr)
	}

	privateKeyAttr, ok := nestedAttr.Attributes["private_key"]
	if !ok {
		t.Fatal("expected 'private_key' under 'iam_role_anywhere'")
	}

	pkStrAttr, ok := privateKeyAttr.(datasourceschema.StringAttribute)
	if !ok {
		t.Fatalf("expected 'private_key' to be StringAttribute, got %T", privateKeyAttr)
	}

	if !pkStrAttr.Sensitive {
		t.Error("expected 'private_key' to be marked Sensitive: true")
	}
}

// Test_CM_AWSConnection_ArchitectureValidationScenarios validates all four required architectural scenarios:
// 1. Updating each of the three string attributes still works as expected.
// 2. Attempting to clear each attribute no longer produces plan drift (using plan modifier).
// 3. Out-of-band modifications to those attributes are unconditionally detected after refresh/plan.
// 4. products = [] continues to clear the products list successfully and remains stable.
func Test_CM_AWSConnection_ArchitectureValidationScenarios(t *testing.T) {
	ctx := context.Background()

	// =========================================================================
	// Scenario 1: Updating each of the three string attributes works as expected.
	// =========================================================================
	t.Run("Scenario 1: Updating un-clearable attributes passes new values to CM", func(t *testing.T) {
		const connID = "conn-id-1"
		var capturedPatchBody string

		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPatch {
				body, _ := io.ReadAll(r.Body)
				capturedPatchBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"id":%q}`, connID)
			}
		})
		server := httptest.NewServer(mux)
		defer server.Close()

		client := &common.Client{
			CipherTrustURL: server.URL,
			HTTPClient:     server.Client(),
			Log:            hclog.NewNullLogger(),
		}

		r := &resourceCCKMAWSConnection{client: client}
		var schemaResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

		baseOverrides := map[string]tftypes.Value{
			"id":               tftypes.NewValue(tftypes.String, connID),
			"name":             tftypes.NewValue(tftypes.String, "my-conn"),
			"is_role_anywhere": tftypes.NewValue(tftypes.Bool, false),
		}

		// Prior state: old values
		stateOverrides := map[string]tftypes.Value{}
		for k, v := range baseOverrides {
			stateOverrides[k] = v
		}
		stateOverrides["description"] = tftypes.NewValue(tftypes.String, "old-desc")
		stateOverrides["assume_role_arn"] = tftypes.NewValue(tftypes.String, "old-arn")
		stateOverrides["assume_role_external_id"] = tftypes.NewValue(tftypes.String, "old-ext")
		stateValue := newAWSConnectionRawValue(ctx, schemaResp, stateOverrides)

		// Plan: new values
		planOverrides := map[string]tftypes.Value{}
		for k, v := range baseOverrides {
			planOverrides[k] = v
		}
		planOverrides["description"] = tftypes.NewValue(tftypes.String, "new-desc")
		planOverrides["assume_role_arn"] = tftypes.NewValue(tftypes.String, "new-arn")
		planOverrides["assume_role_external_id"] = tftypes.NewValue(tftypes.String, "new-ext")
		planValue := newAWSConnectionRawValue(ctx, schemaResp, planOverrides)

		req := resource.UpdateRequest{
			Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
			Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: planValue},
			State:  tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
		}
		resp := &resource.UpdateResponse{
			State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
		}

		r.Update(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
		}

		// Verify update payload carries all updated values
		if !strings.Contains(capturedPatchBody, `"description":"new-desc"`) {
			t.Errorf("expected updated description, got: %s", capturedPatchBody)
		}
		if !strings.Contains(capturedPatchBody, `"assume_role_arn":"new-arn"`) {
			t.Errorf("expected updated assume_role_arn, got: %s", capturedPatchBody)
		}
		if !strings.Contains(capturedPatchBody, `"assume_role_external_id":"new-ext"`) {
			t.Errorf("expected updated assume_role_external_id, got: %s", capturedPatchBody)
		}
	})

	// =========================================================================
	// Scenario 2: Attempting to clear each attribute no longer produces perpetual plan drift.
	// =========================================================================
	t.Run("Scenario 2: Clearing un-clearable fields is intercepted by plan modifier", func(t *testing.T) {
		r := &resourceCCKMAWSConnection{}
		var schemaResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

		// Verify that description, assume_role_arn, and assume_role_external_id all have plan modifiers
		attrs := []string{"description", "assume_role_arn", "assume_role_external_id"}
		for _, name := range attrs {
			attr, ok := schemaResp.Schema.Attributes[name]
			if !ok {
				t.Fatalf("attribute %s not found in schema", name)
			}
			strAttr, ok := attr.(schema.StringAttribute)
			if !ok {
				t.Fatalf("attribute %s is not a StringAttribute", name)
			}
			if len(strAttr.PlanModifiers) == 0 {
				t.Errorf("expected attribute %s to have at least one plan modifier", name)
			}
		}

		// Run plan-modifier validation
		mod := modifiers.UseStateWhenClearingString()
		stateRaw := tfsdk.State{Raw: tftypes.NewValue(tftypes.Object{AttributeTypes: map[string]tftypes.Type{}}, map[string]tftypes.Value{})}

		req := planmodifier.StringRequest{
			State:      stateRaw,
			StateValue: types.StringValue("prior-val"),
			PlanValue:  types.StringNull(), // User attempted to clear the value
		}
		resp := &planmodifier.StringResponse{PlanValue: types.StringNull()}
		mod.PlanModifyString(ctx, req, resp)

		if resp.PlanValue.ValueString() != "prior-val" {
			t.Errorf("expected plan-modifier to substitute prior state value 'prior-val' when user attempts to clear, got: %v", resp.PlanValue)
		}
	})

	// =========================================================================
	// Scenario 3: Out-of-band modifications to those attributes are detected after refresh/plan.
	// =========================================================================
	t.Run("Scenario 3: Out-of-band modifications are unconditionally detected in Read()", func(t *testing.T) {
		const connID = "conn-id-1"

		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			// Return out-of-band updated values from CM
			fmt.Fprintf(w, `{
				"id": %q,
				"name": "my-conn",
				"description": "oob-desc",
				"assume_role_arn": "oob-arn",
				"assume_role_external_id": "oob-ext"
			}`, connID)
		})
		server := httptest.NewServer(mux)
		defer server.Close()

		client := &common.Client{
			CipherTrustURL: server.URL,
			HTTPClient:     server.Client(),
			Log:            hclog.NewNullLogger(),
		}

		r := &resourceCCKMAWSConnection{client: client}
		var schemaResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

		baseOverrides := map[string]tftypes.Value{
			"id":               tftypes.NewValue(tftypes.String, connID),
			"name":             tftypes.NewValue(tftypes.String, "my-conn"),
			"is_role_anywhere": tftypes.NewValue(tftypes.Bool, false),
		}

		// Prior state: old values
		stateOverrides := map[string]tftypes.Value{}
		for k, v := range baseOverrides {
			stateOverrides[k] = v
		}
		stateOverrides["description"] = tftypes.NewValue(tftypes.String, "old-desc")
		stateOverrides["assume_role_arn"] = tftypes.NewValue(tftypes.String, "old-arn")
		stateOverrides["assume_role_external_id"] = tftypes.NewValue(tftypes.String, "old-ext")
		stateValue := newAWSConnectionRawValue(ctx, schemaResp, stateOverrides)

		req := resource.ReadRequest{
			State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
		}
		resp := &resource.ReadResponse{
			State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
		}

		r.Read(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics in Read(): %v", resp.Diagnostics)
		}

		var updatedState AWSConnectionModelTFSDK
		resp.State.Get(ctx, &updatedState)

		// Assert that Read unconditionally updated state to the new out-of-band CM values!
		if updatedState.Description.ValueString() != "oob-desc" {
			t.Errorf("expected state to reflect out-of-band description 'oob-desc', got: %s", updatedState.Description.ValueString())
		}
		if updatedState.AssumeRoleARN.ValueString() != "oob-arn" {
			t.Errorf("expected state to reflect out-of-band assume_role_arn 'oob-arn', got: %s", updatedState.AssumeRoleARN.ValueString())
		}
		if updatedState.AssumeRoleExternalID.ValueString() != "oob-ext" {
			t.Errorf("expected state to reflect out-of-band assume_role_external_id 'oob-ext', got: %s", updatedState.AssumeRoleExternalID.ValueString())
		}
	})

	// =========================================================================
	// Scenario 4: products = [] continues to clear products list successfully and remains stable.
	// =========================================================================
	t.Run("Scenario 4: products = [] sends literal empty list to CM", func(t *testing.T) {
		const connID = "conn-id-1"
		var capturedPatchBody string

		mux := http.NewServeMux()
		mux.HandleFunc("/api/v1/connectionmgmt/services/aws/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPatch {
				body, _ := io.ReadAll(r.Body)
				capturedPatchBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"id":%q}`, connID)
			}
		})
		server := httptest.NewServer(mux)
		defer server.Close()

		client := &common.Client{
			CipherTrustURL: server.URL,
			HTTPClient:     server.Client(),
			Log:            hclog.NewNullLogger(),
		}

		r := &resourceCCKMAWSConnection{client: client}
		var schemaResp resource.SchemaResponse
		r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

		baseOverrides := map[string]tftypes.Value{
			"id":               tftypes.NewValue(tftypes.String, connID),
			"name":             tftypes.NewValue(tftypes.String, "my-conn"),
			"is_role_anywhere": tftypes.NewValue(tftypes.Bool, false),
		}

		// Prior state had 1 product ["cckm"]
		stateOverrides := map[string]tftypes.Value{}
		for k, v := range baseOverrides {
			stateOverrides[k] = v
		}
		stateOverrides["products"] = tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{
			tftypes.NewValue(tftypes.String, "cckm"),
		})
		stateValue := newAWSConnectionRawValue(ctx, schemaResp, stateOverrides)

		// Plan has cleared products: []
		planOverrides := map[string]tftypes.Value{}
		for k, v := range baseOverrides {
			planOverrides[k] = v
		}
		planOverrides["products"] = tftypes.NewValue(tftypes.List{ElementType: tftypes.String}, []tftypes.Value{})
		planValue := newAWSConnectionRawValue(ctx, schemaResp, planOverrides)

		req := resource.UpdateRequest{
			Plan:   tfsdk.Plan{Schema: schemaResp.Schema, Raw: planValue},
			Config: tfsdk.Config{Schema: schemaResp.Schema, Raw: planValue},
			State:  tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
		}
		resp := &resource.UpdateResponse{
			State: tfsdk.State{Schema: schemaResp.Schema, Raw: stateValue},
		}

		r.Update(ctx, req, resp)
		if resp.Diagnostics.HasError() {
			t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
		}

		// Assert that the PATCH request payload carries a literal "products":[]
		if !strings.Contains(capturedPatchBody, `"products":[]`) {
			t.Errorf("expected request payload to contain 'products':[], got: %s", capturedPatchBody)
		}
	})
}

// Test_AWSConnectionSchema_PlanModifierRequiresComputed guarantees that any String attribute
// in the AWS connection schema using UseStateWhenClearingString plan modifier is marked Computed: true.
// Failing to mark Optional plan-modifier-substituted string attributes as Computed triggers a
// critical plan contract validation error 'Provider produced invalid plan for a non-computed attribute'
// under Terraform CLI.
func Test_AWSConnectionSchema_PlanModifierRequiresComputed(t *testing.T) {
	ctx := context.Background()
	r := &resourceCCKMAWSConnection{}
	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	for name, attr := range schemaResp.Schema.Attributes {
		strAttr, ok := attr.(schema.StringAttribute)
		if !ok {
			continue
		}
		if len(strAttr.PlanModifiers) > 0 {
			for _, mod := range strAttr.PlanModifiers {
				// Identify UseStateWhenClearingString modifier by description text
				if strings.Contains(mod.Description(ctx), "useStateWhenClearingStringModifier") || strings.Contains(mod.Description(ctx), "Preserves the prior state value") {
					if !strAttr.Computed {
						t.Errorf("attribute %q uses UseStateWhenClearingString plan modifier but is NOT marked Computed: true. This will trigger a critical Terraform validation failure on plan clear.", name)
					}
				}
			}
		}
	}
}



