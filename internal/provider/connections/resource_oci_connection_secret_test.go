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
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_OciConnectionSchema_KeyFileWriteOnly verifies that
// ciphertrust_oci_connection.key_file and key_file_pass_phrase are marked WriteOnly
// (never stored in state/plan artifacts, per the SecScan write-only hardening pass) and
// that key_file_version exists as the shared companion state-tracked rotation trigger.
// tenancy_ocid must remain unaffected: it is not a secret, just an account identifier.
func Test_OciConnectionSchema_KeyFileWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCCKMOCIConnection{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	keyFileAttr, ok := resp.Schema.Attributes["key_file"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected key_file attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["key_file"])
	}
	if !keyFileAttr.WriteOnly {
		t.Error("expected key_file schema attribute to be marked WriteOnly: true")
	}
	if !keyFileAttr.Sensitive {
		t.Error("expected key_file schema attribute to remain marked Sensitive: true")
	}

	passPhraseAttr, ok := resp.Schema.Attributes["key_file_pass_phrase"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected key_file_pass_phrase attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["key_file_pass_phrase"])
	}
	if !passPhraseAttr.WriteOnly {
		t.Error("expected key_file_pass_phrase schema attribute to be marked WriteOnly: true")
	}
	if !passPhraseAttr.Sensitive {
		t.Error("expected key_file_pass_phrase schema attribute to remain marked Sensitive: true")
	}

	if _, ok := resp.Schema.Attributes["key_file_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected key_file_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["key_file_version"])
	}

	tenancyAttr, ok := resp.Schema.Attributes["tenancy_ocid"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected tenancy_ocid attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["tenancy_ocid"])
	}
	if tenancyAttr.WriteOnly || tenancyAttr.Sensitive {
		t.Error("tenancy_ocid must not be WriteOnly/Sensitive: it is a plain account identifier, not a secret")
	}
}

// newOciConnectionRawValue builds a tftypes.Value covering every attribute declared in
// resourceCCKMOCIConnection's Schema(), defaulting every attribute to null and applying
// the given overrides. Attribute types are derived from the schema itself.
func newOciConnectionRawValue(ctx context.Context, schemaResp resource.SchemaResponse, overrides map[string]tftypes.Value) tftypes.Value {
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

// Test_OciConnectionCreate_KeyFileReadFromConfigNotPlan proves that Create() reads
// key_file/key_file_pass_phrase from req.Config rather than req.Plan, since the
// framework nulls WriteOnly attributes out of the plan before Create() ever runs.
func Test_OciConnectionCreate_KeyFileReadFromConfigNotPlan(t *testing.T) {
	const wantKeyFile = "-----BEGIN PRIVATE KEY-----abc123-----END PRIVATE KEY-----"
	const wantPassPhrase = "oci-pass"
	const connID = "oci-id-1"

	var capturedCreateBody string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/connectionmgmt/services/oci/connections", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %s on collection endpoint", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		capturedCreateBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":%q}`, connID)
	})
	mux.HandleFunc("/api/v1/connectionmgmt/services/oci/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"id":%q,"name":"my-oci-conn","region":"us-ashburn-1","tenancy_ocid":"ocid1.tenancy.oc1..a","user_ocid":"ocid1.user.oc1..a","fingerprint":"aa:bb"}`, connID)
	})
	mux.HandleFunc("/api/v1/connectionmgmt/services/oci/connections/"+connID+"/test", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"connection_ok":true}`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCCKMOCIConnection{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	commonOverrides := map[string]tftypes.Value{
		"name":                        tftypes.NewValue(tftypes.String, "my-oci-conn"),
		"region":                      tftypes.NewValue(tftypes.String, "us-ashburn-1"),
		"tenancy_ocid":                tftypes.NewValue(tftypes.String, "ocid1.tenancy.oc1..a"),
		"user_ocid":                   tftypes.NewValue(tftypes.String, "ocid1.user.oc1..a"),
		"pub_key_fingerprint":         tftypes.NewValue(tftypes.String, "aa:bb"),
		"skip_connection_params_test": tftypes.NewValue(tftypes.Bool, true),
	}

	planOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		planOverrides[k] = v
	}
	planOverrides["key_file"] = tftypes.NewValue(tftypes.String, nil)
	planOverrides["key_file_pass_phrase"] = tftypes.NewValue(tftypes.String, nil)
	planValue := newOciConnectionRawValue(ctx, schemaResp, planOverrides)

	configOverrides := map[string]tftypes.Value{}
	for k, v := range commonOverrides {
		configOverrides[k] = v
	}
	configOverrides["key_file"] = tftypes.NewValue(tftypes.String, wantKeyFile)
	configOverrides["key_file_pass_phrase"] = tftypes.NewValue(tftypes.String, wantPassPhrase)
	configValue := newOciConnectionRawValue(ctx, schemaResp, configOverrides)

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

	if !strings.Contains(capturedCreateBody, wantKeyFile) {
		t.Errorf("expected create payload to contain the config-supplied key_file, got body: %s", capturedCreateBody)
	}
	if !strings.Contains(capturedCreateBody, wantPassPhrase) {
		t.Errorf("expected create payload to contain the config-supplied key_file_pass_phrase, got body: %s", capturedCreateBody)
	}

	var final OCIConnectionTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	if !final.KeyFile.IsNull() {
		t.Errorf("expected key_file to be null in state (write-only), got %q", final.KeyFile.ValueString())
	}
	if !final.PassPhrase.IsNull() {
		t.Errorf("expected key_file_pass_phrase to be null in state (write-only), got %q", final.PassPhrase.ValueString())
	}
}

// Test_OciConnectionUpdate_KeyFileVersionGatesResend proves that Update() only re-sends
// key_file/key_file_pass_phrase to CM when key_file_version changes between state and
// plan. Since both are write-only (never stored in state), they can't be diffed on their
// own — key_file_version is the explicit signal that the caller wants the current values
// re-sent. This replaces the old approach of diffing the resolved plaintext key content
// against prior state, which required keeping the plaintext key in state.
func Test_OciConnectionUpdate_KeyFileVersionGatesResend(t *testing.T) {
	const connID = "oci-id-1"

	tests := []struct {
		name         string
		stateVersion int64
		planVersion  int64
		configKey    string
		expectInBody bool
	}{
		{
			name:         "version unchanged: credentials omitted from payload",
			stateVersion: 1,
			planVersion:  1,
			configKey:    "unused-key",
			expectInBody: false,
		},
		{
			name:         "version bumped: credentials included from config",
			stateVersion: 1,
			planVersion:  2,
			configKey:    "rotated-key-content",
			expectInBody: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var capturedPatchBody string
			mux := http.NewServeMux()
			mux.HandleFunc("/api/v1/connectionmgmt/services/oci/connections/"+connID, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method {
				case http.MethodGet:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprintf(w, `{"id":%q,"name":"my-oci-conn","region":"us-ashburn-1","tenancy_ocid":"ocid1.tenancy.oc1..a","user_ocid":"ocid1.user.oc1..a","fingerprint":"aa:bb"}`, connID)
				case http.MethodPatch:
					body, _ := io.ReadAll(r.Body)
					capturedPatchBody = string(body)
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

			r := &resourceCCKMOCIConnection{client: client}
			ctx := context.Background()

			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
			if schemaResp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
			}

			baseOverrides := map[string]tftypes.Value{
				"id":                   tftypes.NewValue(tftypes.String, connID),
				"name":                 tftypes.NewValue(tftypes.String, "my-oci-conn"),
				"region":               tftypes.NewValue(tftypes.String, "us-ashburn-1"),
				"tenancy_ocid":         tftypes.NewValue(tftypes.String, "ocid1.tenancy.oc1..a"),
				"user_ocid":            tftypes.NewValue(tftypes.String, "ocid1.user.oc1..a"),
				"pub_key_fingerprint":  tftypes.NewValue(tftypes.String, "aa:bb"),
				"key_file":             tftypes.NewValue(tftypes.String, nil),
				"key_file_pass_phrase": tftypes.NewValue(tftypes.String, nil),
			}

			stateOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				stateOverrides[k] = v
			}
			stateOverrides["key_file_version"] = tftypes.NewValue(tftypes.Number, tc.stateVersion)
			stateValue := newOciConnectionRawValue(ctx, schemaResp, stateOverrides)

			planOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				planOverrides[k] = v
			}
			planOverrides["key_file_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			planValue := newOciConnectionRawValue(ctx, schemaResp, planOverrides)

			configOverrides := map[string]tftypes.Value{}
			for k, v := range baseOverrides {
				configOverrides[k] = v
			}
			configOverrides["key_file"] = tftypes.NewValue(tftypes.String, tc.configKey)
			configOverrides["key_file_version"] = tftypes.NewValue(tftypes.Number, tc.planVersion)
			configValue := newOciConnectionRawValue(ctx, schemaResp, configOverrides)

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

			got := strings.Contains(capturedPatchBody, "rotated-key-content")
			if got != tc.expectInBody {
				t.Errorf("expected rotated key_file content present in PATCH body = %v, got %v (body: %s)", tc.expectInBody, got, capturedPatchBody)
			}

			var final OCIConnectionTFSDK
			diags := resp.State.Get(ctx, &final)
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
			}
			if !final.KeyFile.IsNull() {
				t.Errorf("expected key_file to be null in state (write-only), got %q", final.KeyFile.ValueString())
			}
			if !final.PassPhrase.IsNull() {
				t.Errorf("expected key_file_pass_phrase to be null in state (write-only), got %q", final.PassPhrase.ValueString())
			}
		})
	}
}
