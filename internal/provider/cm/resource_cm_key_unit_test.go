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
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

// ---------------------------------------------------------------------------
// Shared helpers for the CRUD unit tests below.
// ---------------------------------------------------------------------------

// newTestCMKeyResource builds a resourceCMKey wired to a fake HTTP server and returns
// the resource, a background context, and the resource's schema (built once via r.Schema()).
func newTestCMKeyResource(t *testing.T, handler http.HandlerFunc) (*resourceCMKey, context.Context, resource.SchemaResponse) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

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
	return r, ctx, schemaResp
}

// ensureLabels defaults the zero-value types.Map (used when a test literal doesn't set
// Labels explicitly) to a properly-typed null map. The struct zero value has no
// ElementType set, which Plan/Config/State.Set() rejects as a type-conversion error.
func ensureLabels(val *CMKeyTFSDK) *CMKeyTFSDK {
	if reflect.ValueOf(val.Labels).IsZero() {
		val.Labels = types.MapNull(types.StringType)
	}
	return val
}

func mustPlan(t *testing.T, ctx context.Context, schemaResp resource.SchemaResponse, val *CMKeyTFSDK) tfsdk.Plan {
	t.Helper()
	val = ensureLabels(val)
	p := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := p.Set(ctx, val)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building plan: %v", diags)
	}
	return p
}

func mustConfig(t *testing.T, ctx context.Context, schemaResp resource.SchemaResponse, val *CMKeyTFSDK) tfsdk.Config {
	t.Helper()
	// tfsdk.Config has no Set method (unlike Plan/State) — build via Plan.Set and
	// reuse its Raw tftypes.Value, since all three wrap the same underlying data shape.
	val = ensureLabels(val)
	p := tfsdk.Plan{Schema: schemaResp.Schema}
	diags := p.Set(ctx, val)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building config: %v", diags)
	}
	return tfsdk.Config{Schema: schemaResp.Schema, Raw: p.Raw}
}

func mustState(t *testing.T, ctx context.Context, schemaResp resource.SchemaResponse, val *CMKeyTFSDK) tfsdk.State {
	t.Helper()
	val = ensureLabels(val)
	s := tfsdk.State{Schema: schemaResp.Schema}
	diags := s.Set(ctx, val)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics building state: %v", diags)
	}
	return s
}

func strList(vals ...string) []types.String {
	out := make([]types.String, 0, len(vals))
	for _, v := range vals {
		out = append(out, types.StringValue(v))
	}
	return out
}

func strMap(kv map[string]string) types.Map {
	elems := make(map[string]attr.Value, len(kv))
	for k, v := range kv {
		elems[k] = types.StringValue(v)
	}
	return types.MapValueMust(types.StringType, elems)
}

// ---------------------------------------------------------------------------
// Create()
// ---------------------------------------------------------------------------

// createCapture runs Create() against a fake 201 response (with optional extra response
// fields) and returns the captured POST body plus the final hydrated state. Shared by the
// focused Create() payload tests below so each test only needs to state its own plan/config
// and what it wants to assert — not re-implement the server/request/response plumbing.
func createCapture(t *testing.T, plan, config *CMKeyTFSDK, responseExtra string) (string, CMKeyTFSDK) {
	t.Helper()
	if config == nil {
		config = plan
	}
	var capturedBody string
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		b := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(b)
		// A plan with revocation_reason/revocation_message set triggers a second,
		// separate POST to the /revoke endpoint (see revokeKey) right after creation.
		// Handle it distinctly so it doesn't clobber the create POST body below.
		if strings.HasSuffix(req.URL.Path, "/revoke") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		capturedBody = string(b)
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"id":"key-123"%s}`, responseExtra)
	})
	req := resource.CreateRequest{
		Plan:   mustPlan(t, ctx, schemaResp, plan),
		Config: mustConfig(t, ctx, schemaResp, config),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Create(): %v", resp.Diagnostics)
	}
	var final CMKeyTFSDK
	diags := resp.State.Get(ctx, &final)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back final state: %v", diags)
	}
	return capturedBody, final
}

func Test_CMKeyCreate_SimpleScalarFieldsInPayload(t *testing.T) {
	plan := &CMKeyTFSDK{
		Algorithm:             types.StringValue("aes"),
		AssignSelfAsOwner:     types.BoolValue(true),
		Description:           types.StringValue("a test key"),
		GenerateKeyId:         types.BoolValue(true),
		IDSize:                types.Int64Value(64),
		KeyId:                 types.StringValue("1234"),
		MUID:                  types.StringValue("muid-1"),
		ObjectType:            types.StringValue("Symmetric Key"),
		Name:                  types.StringValue("tf-simple"),
		ProcessStartDate:      types.StringValue("2024-01-01T00:00:00Z"),
		ProtectStopDate:       types.StringValue("2030-01-01T00:00:00Z"),
		RotationFrequencyDays: types.StringValue("30"),
		Size:                  types.Int64Value(256),
		State:                 types.StringValue("Active"),
		UsageMask:             types.Int64Value(12),
	}
	body, _ := createCapture(t, plan, nil, "")
	for _, want := range []string{
		`"algorithm":"aes"`,
		`"assignSelfAsOwner":true`,
		`"description":"a test key"`,
		`"generateKeyId":true`,
		`"idSize":64`,
		`"keyId":"1234"`,
		`"muid":"muid-1"`,
		`"objectType":"Symmetric Key"`,
		`"processStartDate":"2024-01-01T00:00:00Z"`,
		`"protectStopDate":"2030-01-01T00:00:00Z"`,
		`"rotationFrequencyDays":"30"`,
		`"size":256`,
		`"state":"Active"`,
		`"usageMask":12`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected POST body to contain %s, got: %s", want, body)
		}
	}
}

func Test_CMKeyCreate_UsageMaskZeroReachesPayload(t *testing.T) {
	// UsageMask is *int64 specifically so an explicit 0 still serializes — a plain
	// int64 with omitempty would drop it, silently no-op'ing the user's config.
	plan := &CMKeyTFSDK{
		Name:      types.StringValue("tf-usagemask-zero"),
		UsageMask: types.Int64Value(0),
	}
	body, _ := createCapture(t, plan, nil, "")
	if !strings.Contains(body, `"usageMask":0`) {
		t.Errorf("expected POST body to contain \"usageMask\":0, got: %s", body)
	}
}

func Test_CMKeyCreate_RemainingScalarFieldsInPayload(t *testing.T) {
	// Every plan.<Field>.ValueString() != "" pass-through branch in Create() that isn't
	// exercised by Test_CMKeyCreate_SimpleScalarFieldsInPayload. Table-driven with one
	// subtest per field so a failure names the exact field whose branch broke.
	plan := &CMKeyTFSDK{
		Name:                     types.StringValue("tf-remaining"),
		ActivationDate:           types.StringValue("2024-01-01T00:00:00Z"),
		ArchiveDate:              types.StringValue("2024-02-01T00:00:00Z"),
		CertType:                 types.StringValue("x509-pem"),
		CompromiseDate:           types.StringValue("2024-03-01T00:00:00Z"),
		CompromiseOccurrenceDate: types.StringValue("2024-03-02T00:00:00Z"),
		Curveid:                  types.StringValue("secp256k1"),
		DeactivationDate:         types.StringValue("2025-01-01T00:00:00Z"),
		DefaultIV:                types.StringValue("00112233445566778899aabbccddeeff"),
		DestroyDate:              types.StringValue("2026-01-01T00:00:00Z"),
		EmptyMaterial:            types.BoolValue(true),
		Encoding:                 types.StringValue("hex"),
		Format:                   types.StringValue("pkcs8"),
		MacSignBytes:             types.StringValue("aabbcc"),
		MacSignKeyIdentifier:     types.StringValue("mac-key-1"),
		MacSignKeyIdentifierType: types.StringValue("name"),
		Padded:                   types.BoolValue(true),
		SecretDataEncoding:       types.StringValue("HEX"),
		SecretDataLink:           types.StringValue("secret-1"),
		SigningAlgo:              types.StringValue("RSA"),
		TemplateID:               types.StringValue("template-1"),
		UUID:                     types.StringValue("11111111-1111-1111-1111-111111111111"),
		WrapKeyIDType:            types.StringValue("name"),
		WrapKeyName:              types.StringValue("wrap-key-1"),
		WrapPublicKey:            types.StringValue("-----BEGIN PUBLIC KEY-----abc-----END PUBLIC KEY-----"),
		WrapPublicKeyPadding:     types.StringValue("oaep"),
		WrappingEncryptionAlgo:   types.StringValue("AES/AESKEYWRAP"),
		WrappingHashAlgo:         types.StringValue("sha256"),
		WrappingMethod:           types.StringValue("encrypt"),
	}
	body, _ := createCapture(t, plan, nil, "")
	for _, tc := range []struct{ name, want string }{
		{"activation_date", `"activationDate":"2024-01-01T00:00:00Z"`},
		{"archive_date", `"archiveDate":"2024-02-01T00:00:00Z"`},
		{"cert_type", `"certType":"x509-pem"`},
		{"compromise_date", `"compromiseDate":"2024-03-01T00:00:00Z"`},
		{"compromise_occurrence_date", `"compromiseOccurrenceDate":"2024-03-02T00:00:00Z"`},
		{"curveid", `"curveid":"secp256k1"`},
		{"deactivation_date", `"deactivationDate":"2025-01-01T00:00:00Z"`},
		{"default_iv", `"defaultIV":"00112233445566778899aabbccddeeff"`},
		{"destroy_date", `"destroyDate":"2026-01-01T00:00:00Z"`},
		{"empty_material", `"emptyMaterial":true`},
		{"encoding", `"encoding":"hex"`},
		{"format", `"format":"pkcs8"`},
		{"mac_sign_bytes", `"macSignBytes":"aabbcc"`},
		{"mac_sign_key_identifier", `"macSignKeyIdentifier":"mac-key-1"`},
		{"mac_sign_key_identifier_type", `"macSignKeyIdentifierType":"name"`},
		{"padded", `"padded":true`},
		{"secret_data_encoding", `"secretDataEncoding":"HEX"`},
		{"secret_data_link", `"secretDataLink":"secret-1"`},
		{"signing_algo", `"signingAlgo":"RSA"`},
		{"template_id", `"templateId":"template-1"`},
		{"uuid", `"uuid":"11111111-1111-1111-1111-111111111111"`},
		{"wrap_key_id_type", `"wrapKeyIDType":"name"`},
		{"wrap_key_name", `"wrapKeyName":"wrap-key-1"`},
		{"wrap_public_key", `"wrapPublicKey":"-----BEGIN PUBLIC KEY-----abc-----END PUBLIC KEY-----"`},
		{"wrap_public_key_padding", `"wrapPublicKeyPadding":"oaep"`},
		{"wrapping_encryption_algo", `"wrappingEncryptionAlgo":"AES/AESKEYWRAP"`},
		{"wrapping_hash_algo", `"wrappingHashAlgo":"sha256"`},
		{"wrapping_method", `"wrappingMethod":"encrypt"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(body, tc.want) {
				t.Errorf("expected POST body to contain %s, got: %s", tc.want, body)
			}
		})
	}
}

func Test_CMKeyCreate_RevocationSentToRevokeEndpoint(t *testing.T) {
	// Revocation is a dedicated CM operation (see revokeKey), not a field on the general
	// key create payload — reason/message must never appear there. Confirm they instead
	// reach CM via a distinct POST to .../<id>/revoke using CM's reason/message field names.
	plan := &CMKeyTFSDK{
		Name:              types.StringValue("tf-revoke"),
		RevocationReason:  types.StringValue("KeyCompromise"),
		RevocationMessage: types.StringValue("revoked for testing"),
	}
	var revokePath, revokeBody string
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		b := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(b)
		if strings.HasSuffix(req.URL.Path, "/revoke") {
			revokePath = req.URL.Path
			revokeBody = string(b)
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"key-999"}`)
	})
	req := resource.CreateRequest{
		Plan:   mustPlan(t, ctx, schemaResp, plan),
		Config: mustConfig(t, ctx, schemaResp, plan),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Create(): %v", resp.Diagnostics)
	}
	if !strings.HasSuffix(revokePath, "/key-999/revoke") {
		t.Fatalf("expected revoke call to hit .../key-999/revoke, got path: %q", revokePath)
	}
	if !strings.Contains(revokeBody, `"reason":"KeyCompromise"`) || !strings.Contains(revokeBody, `"message":"revoked for testing"`) {
		t.Errorf(`expected revoke POST body to contain "reason":"KeyCompromise" and "message":"revoked for testing", got: %s`, revokeBody)
	}
}

func Test_CMKeyCreate_AliasesSentWithoutIndex(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-aliases"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("alias-one"), Index: types.StringNull(), Type: types.StringValue("string")},
			{Alias: types.StringValue("alias-two"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	body, _ := createCapture(t, plan, nil, "")
	if !strings.Contains(body, `"aliases":[{"alias":"alias-one","type":"string"},{"alias":"alias-two","type":"string"}]`) {
		t.Errorf("expected both aliases sent with no index (server assigns it), got: %s", body)
	}
}

func Test_CMKeyCreate_AliasWithExplicitIndexInPayload(t *testing.T) {
	// Re-create scenario: the plan already knows a prior server-assigned index (e.g. a
	// destroy/recreate cycle) and resends it verbatim.
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-alias-index"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("alias-one"), Index: types.StringValue("3"), Type: types.StringValue("string")},
		},
	}
	body, _ := createCapture(t, plan, nil, "")
	if !strings.Contains(body, `"index":3`) {
		t.Errorf("expected alias index 3 to be sent verbatim in payload, got: %s", body)
	}
}

func Test_CMKeyCreate_AliasHydrationSkipsUnconfiguredAndHandlesMissingFields(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-alias-filter"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("configured-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	// Response includes an alias the user never configured (must be skipped) and the
	// configured one with its "type" field omitted (must hydrate as null, not error).
	_, final := createCapture(t, plan, nil, `,"aliases":[`+
		`{"alias":"server-only-alias","index":"9"},`+
		`{"alias":"configured-alias","index":"1"}]`)
	if len(final.Aliases) != 1 || final.Aliases[0].Alias.ValueString() != "configured-alias" {
		t.Fatalf("expected only the configured alias to be hydrated, got %+v", final.Aliases)
	}
	if !final.Aliases[0].Type.IsNull() {
		t.Errorf("expected alias type to be null when absent from response, got %+v", final.Aliases[0].Type)
	}
}

func Test_CMKeyCreate_MetadataPermissionsAndCTEInPayload(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-meta"),
		Metadata: &KeyMetadataTFSDK{
			OwnerId: types.StringValue("owner-1"),
			Permissions: &KeyMetadataPermissionsTFSDK{
				DecryptWithKey:    strList("user1"),
				EncryptWithKey:    strList("user1"),
				ExportKey:         strList("user1"),
				MACVerifyWithKey:  strList("user1"),
				MACWithKey:        strList("user1"),
				ReadKey:           strList("user1"),
				SignVerifyWithKey: strList("user1"),
				SignWithKey:       strList("user1"),
				UseKey:            strList("user1"),
			},
			CTE: &KeyMetadataCTETFSDK{
				PersistentOnClient: types.BoolValue(true),
				EncryptionMode:     types.StringValue("CBC"),
				CTEVersioned:       types.BoolValue(true),
			},
		},
	}
	body, _ := createCapture(t, plan, nil, "")
	for _, tc := range []struct{ name, want string }{
		{"owner_id", `"ownerId":"owner-1"`},
		{"decrypt_with_key", `"DecryptWithKey":["user1"]`},
		{"encrypt_with_key", `"EncryptWithKey":["user1"]`},
		{"export_key", `"ExportKey":["user1"]`},
		{"mac_verify_with_key", `"MACVerifyWithKey":["user1"]`},
		{"mac_with_key", `"MACWithKey":["user1"]`},
		{"read_key", `"ReadKey":["user1"]`},
		{"sign_verify_with_key", `"SignVerifyWithKey":["user1"]`},
		{"sign_with_key", `"SignWithKey":["user1"]`},
		{"use_key", `"UseKey":["user1"]`},
		{"cte_persistent_on_client", `"persistent_on_client":true`},
		{"cte_encryption_mode", `"encryption_mode":"CBC"`},
		{"cte_versioned", `"cte_versioned":true`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(body, tc.want) {
				t.Errorf("expected POST body to contain %s, got: %s", tc.want, body)
			}
		})
	}
}

func Test_CMKeyCreate_PublicKeyParametersInPayload(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-pubkey"),
		PublicKeyParameters: &PublicKeyParametersTFSDK{
			ActivationDate:   types.StringValue("2024-01-01T00:00:00Z"),
			ArchiveDate:      types.StringValue("2024-02-01T00:00:00Z"),
			DeactivationDate: types.StringValue("2025-01-01T00:00:00Z"),
			Name:             types.StringValue("tf-pubkey-pub"),
			State:            types.StringValue("Active"),
			UnDeletable:      types.BoolValue(true),
			UnExportable:     types.BoolValue(true),
			UsageMask:        types.Int64Value(4),
			Aliases: []KeyAliasTFSDK{
				{Alias: types.StringValue("pub-alias"), Index: types.StringValue("7"), Type: types.StringValue("string")},
			},
		},
	}
	body, _ := createCapture(t, plan, nil, "")
	for _, tc := range []struct{ name, want string }{
		{"activation_date", `"activationDate":"2024-01-01T00:00:00Z"`},
		{"archive_date", `"archiveDate":"2024-02-01T00:00:00Z"`},
		{"deactivation_date", `"deactivationDate":"2025-01-01T00:00:00Z"`},
		{"name", `"name":"tf-pubkey-pub"`},
		{"undeletable", `"undeletable":true`},
		{"unexportable", `"unexportable":true`},
		{"usage_mask", `"usageMask":4`},
		{"alias_with_index", `"pub-alias","index":7`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(body, tc.want) {
				t.Errorf("expected POST body to contain %s, got: %s", tc.want, body)
			}
		})
	}
}

func Test_CMKeyCreate_WrapHKDFInPayload(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-wraphkdf"),
		HKDFWrap: &WrapHKDFTFSDK{
			HashAlgorithm: types.StringValue("hmac-sha256"),
			Info:          types.StringValue("wrap-info"),
			OKMLen:        types.Int64Value(32),
		},
	}
	body, _ := createCapture(t, plan, nil, "")
	for _, want := range []string{`"hashAlgorithm":"hmac-sha256"`, `"okmLen":32`} {
		if !strings.Contains(body, want) {
			t.Errorf("expected POST body to contain %s, got: %s", want, body)
		}
	}
}

func Test_CMKeyCreate_WrapPBEInPayload(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-wrappbe"),
		PBEWrap: &WrapPBETFSDK{
			DKLen:                  types.Int64Value(32),
			HashAlgorithm:          types.StringValue("hmac-sha256"),
			Iteration:              types.Int64Value(1000),
			Password:               types.StringValue("cGFzc3dvcmQ="),
			PasswordIdentifier:     types.StringValue("pw-id-1"),
			PasswordIdentifierType: types.StringValue("name"),
			Purpose:                types.StringValue("test"),
			Salt:                   types.StringValue("aabbccddeeff00112233445566778899"),
		},
	}
	body, _ := createCapture(t, plan, nil, "")
	for _, tc := range []struct{ name, want string }{
		{"dklen", `"dklen":32`},
		{"hash_algorithm", `"hashAlgorithm":"hmac-sha256"`},
		{"password", `"password":"cGFzc3dvcmQ="`},
		{"password_identifier", `"passwordIdentifier":"pw-id-1"`},
		{"password_identifier_type", `"passwordIdentifierType":"name"`},
		{"purpose", `"purpose":"test"`},
		{"salt", `"salt":"aabbccddeeff00112233445566778899"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(body, tc.want) {
				t.Errorf("expected POST body to contain %s, got: %s", tc.want, body)
			}
		})
	}
}

func Test_CMKeyCreate_WrapRSAAESInPayload(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-wraprsaaes"),
		RSAAESWrap: &WrapRSAAESTFSDK{
			AESKeySize: types.Int64Value(256),
			Padding:    types.StringValue("oaep256"),
		},
	}
	body, _ := createCapture(t, plan, nil, "")
	for _, want := range []string{`"aesKeySize":256`, `"padding":"oaep256"`} {
		if !strings.Contains(body, want) {
			t.Errorf("expected POST body to contain %s, got: %s", want, body)
		}
	}
}

func Test_CMKeyCreate_LabelsInPayload(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name:   types.StringValue("tf-labels"),
		Labels: strMap(map[string]string{"env": "test"}),
	}
	body, _ := createCapture(t, plan, nil, "")
	if !strings.Contains(body, `"env":"test"`) {
		t.Errorf("expected POST body to contain label env=test, got: %s", body)
	}
}

func Test_CMKeyCreate_HydratesIDFromResponse(t *testing.T) {
	plan := &CMKeyTFSDK{Name: types.StringValue("tf-id")}
	_, final := createCapture(t, plan, nil, "")
	if final.ID.ValueString() != "key-123" {
		t.Errorf("expected id=key-123, got %q", final.ID.ValueString())
	}
}

func Test_CMKeyCreate_BoolsHydratedFromResponse(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name:         types.StringValue("tf-bools"),
		UnDeletable:  types.BoolValue(false),
		UnExportable: types.BoolValue(false),
		XTS:          types.BoolValue(false),
	}
	_, final := createCapture(t, plan, nil, `,"undeletable":true,"unexportable":true,"xts":true`)
	if !final.UnDeletable.ValueBool() || !final.UnExportable.ValueBool() || !final.XTS.ValueBool() {
		t.Errorf("expected undeletable/unexportable/xts to be hydrated true from response, got %+v/%+v/%+v",
			final.UnDeletable, final.UnExportable, final.XTS)
	}
}

func Test_CMKeyCreate_AliasesHydratedInPlanOrderWithServerIndex(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-alias-hydrate"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("alias-one"), Index: types.StringNull(), Type: types.StringValue("string")},
			{Alias: types.StringValue("alias-two"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	_, final := createCapture(t, plan, nil, `,"aliases":[{"alias":"alias-one","index":"1","type":"string"},{"alias":"alias-two","index":"2","type":"string"}]`)
	if len(final.Aliases) != 2 || final.Aliases[0].Alias.ValueString() != "alias-one" || final.Aliases[0].Index.ValueString() != "1" {
		t.Errorf("expected 2 hydrated aliases in plan order with server indices, got %+v", final.Aliases)
	}
}

func Test_CMKeyCreate_WriteOnlyFieldsNullInFinalState(t *testing.T) {
	plan := &CMKeyTFSDK{
		Name: types.StringValue("tf-writeonly"),
		HKDFCreateParameters: &HKDFParametersTFSDK{
			HashAlgorithm: types.StringValue("hmac-sha256"),
			Salt:          types.StringNull(), // write-only: plan always null
		},
		HKDFWrap: &WrapHKDFTFSDK{
			HashAlgorithm: types.StringValue("hmac-sha256"),
			Salt:          types.StringNull(), // write-only: plan always null
		},
	}
	config := &CMKeyTFSDK{}
	*config = *plan
	config.Material = types.StringValue("00112233")
	config.Password = types.StringValue("cGFzcw==")
	config.HKDFCreateParameters = &HKDFParametersTFSDK{
		HashAlgorithm: plan.HKDFCreateParameters.HashAlgorithm,
		Salt:          types.StringValue("0123456789abcdef"),
	}
	config.HKDFWrap = &WrapHKDFTFSDK{
		HashAlgorithm: plan.HKDFWrap.HashAlgorithm,
		Salt:          types.StringValue("fedcba9876543210"),
	}

	_, final := createCapture(t, plan, config, "")
	if !final.Material.IsNull() || !final.Password.IsNull() {
		t.Errorf("expected material/password to be null (write-only) in final state")
	}
	if !final.HKDFCreateParameters.Salt.IsNull() || !final.HKDFWrap.Salt.IsNull() {
		t.Errorf("expected hkdf salts to be null (write-only) in final state")
	}
}

func Test_CMKeyCreate_NoAliasesSkipsHydration(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"key-noalias"}`)
	})
	plan := &CMKeyTFSDK{Name: types.StringValue("no-alias-key"), Algorithm: types.StringValue("aes")}
	req := resource.CreateRequest{
		Plan:   mustPlan(t, ctx, schemaResp, plan),
		Config: mustConfig(t, ctx, schemaResp, plan),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if final.Aliases != nil {
		t.Errorf("expected no aliases to be hydrated, got %+v", final.Aliases)
	}
}

func Test_CMKeyCreate_BoolsPreservedWhenAbsentFromResponse(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"id":"key-boolpreserve"}`) // no undeletable/unexportable/xts in response
	})
	plan := &CMKeyTFSDK{
		Name:         types.StringValue("bool-preserve-key"),
		UnDeletable:  types.BoolValue(true),
		UnExportable: types.BoolValue(true),
		XTS:          types.BoolValue(true),
	}
	req := resource.CreateRequest{
		Plan:   mustPlan(t, ctx, schemaResp, plan),
		Config: mustConfig(t, ctx, schemaResp, plan),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if !final.UnDeletable.ValueBool() || !final.UnExportable.ValueBool() || !final.XTS.ValueBool() {
		t.Errorf("expected plan bool values to be preserved when absent from response, got %+v/%+v/%+v",
			final.UnDeletable, final.UnExportable, final.XTS)
	}
}

func Test_CMKeyCreate_InvalidAliasIndex(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("server should not be called when alias index is invalid")
	})
	plan := &CMKeyTFSDK{
		Name: types.StringValue("bad-alias-key"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("a1"), Index: types.StringValue("not-a-number"), Type: types.StringValue("string")},
		},
	}
	req := resource.CreateRequest{
		Plan:   mustPlan(t, ctx, schemaResp, plan),
		Config: mustConfig(t, ctx, schemaResp, plan),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic for invalid alias index")
	}
	found := false
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Detail(), "Invalid alias index value") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Invalid alias index value' error, got: %v", resp.Diagnostics.Errors())
	}
}

func Test_CMKeyCreate_InvalidPublicKeyAliasIndex(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("server should not be called when public key alias index is invalid")
	})
	plan := &CMKeyTFSDK{
		Name: types.StringValue("bad-pubkey-alias-key"),
		PublicKeyParameters: &PublicKeyParametersTFSDK{
			Aliases: []KeyAliasTFSDK{
				{Alias: types.StringValue("a1"), Index: types.StringValue("nope"), Type: types.StringValue("string")},
			},
		},
	}
	req := resource.CreateRequest{
		Plan:   mustPlan(t, ctx, schemaResp, plan),
		Config: mustConfig(t, ctx, schemaResp, plan),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic for invalid public key alias index")
	}
	found := false
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Detail(), "Invalid public key alias index value") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'Invalid public key alias index value' error, got: %v", resp.Diagnostics.Errors())
	}
}

func Test_CMKeyCreate_TransportErrorSurfaces(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"boom"}`)
	})
	plan := &CMKeyTFSDK{Name: types.StringValue("err-key")}
	req := resource.CreateRequest{
		Plan:   mustPlan(t, ctx, schemaResp, plan),
		Config: mustConfig(t, ctx, schemaResp, plan),
	}
	resp := &resource.CreateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	r.Create(ctx, req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic on transport failure")
	}
	found := false
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Summary(), "Error creating key on CipherTrust Manager") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected creation error, got: %v", resp.Diagnostics.Errors())
	}
}

// ---------------------------------------------------------------------------
// Read()
// ---------------------------------------------------------------------------

func Test_CMKeyRead_FullHydration(t *testing.T) {
	responseJSON := `{
		"id": "key-1",
		"name": "tf-key",
		"algorithm": "AES",
		"usageMask": 12,
		"size": 256,
		"description": "hydrated description",
		"rotationFrequencyDays": "45",
		"undeletable": true,
		"unexportable": true,
		"emptyMaterial": false,
		"xts": true,
		"state": "Active",
		"uuid": "11111111-1111-1111-1111-111111111111",
		"muid": "muid-hydrated",
		"objectType": "Symmetric Key",
		"defaultIV": "00112233445566778899aabbccddeeff",
		"activationDate": "2024-01-01T00:00:00Z",
		"deactivationDate": "2025-01-01T00:00:00Z",
		"archiveDate": "2024-06-01T00:00:00Z",
		"labels": {"env": "prod", "ncryptify-reserved/internal": "hidden"},
		"aliases": [
			{"alias": "tf-key", "index": "0", "type": "string"},
			{"alias": "configured-alias", "index": "1", "type": "string"}
		],
		"meta": {
			"ownerId": "owner-1",
			"permissions": {
				"DecryptWithKey": ["user1"],
				"EncryptWithKey": ["user1"],
				"ExportKey": ["user1"],
				"MACVerifyWithKey": ["user1"],
				"MACWithKey": ["user1"],
				"ReadKey": ["user1"],
				"SignVerifyWithKey": ["user1"],
				"SignWithKey": ["user1"],
				"UseKey": ["user1"]
			},
			"cte": {
				"persistent_on_client": true,
				"encryption_mode": "CBC",
				"cte_versioned": true
			}
		}
	}`
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseJSON)
	})

	state := &CMKeyTFSDK{
		ID:                    types.StringValue("key-1"),
		Name:                  types.StringValue("tf-key"),
		Algorithm:             types.StringValue("aes"), // lowercase; response is "AES" -> preserve casing
		UsageMask:             types.Int64Value(12),
		Size:                  types.Int64Value(256),
		Description:           types.StringValue("stale description"),
		RotationFrequencyDays: types.StringValue("30"),
		UnDeletable:           types.BoolValue(false),
		UnExportable:          types.BoolValue(false),
		EmptyMaterial:         types.BoolValue(true),
		XTS:                   types.BoolValue(false),
		State:                 types.StringValue("Pre-Active"),
		UUID:                  types.StringValue("00000000-0000-0000-0000-000000000000"),
		MUID:                  types.StringValue("muid-stale"),
		ObjectType:            types.StringValue("Symmetric Key"),
		DefaultIV:             types.StringValue("ffffffffffffffffffffffffffffffff"),
		ActivationDate:        types.StringValue("2023-01-01T00:00:00Z"),
		DeactivationDate:      types.StringValue("2023-06-01T00:00:00Z"),
		ArchiveDate:           types.StringValue("2023-12-01T00:00:00Z"),
		Labels:                strMap(map[string]string{"env": "stale"}),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("configured-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
		Metadata: &KeyMetadataTFSDK{OwnerId: types.StringValue("stale-owner")},
	}

	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)

	if final.Algorithm.ValueString() != "aes" {
		t.Errorf("expected algorithm casing preserved as 'aes', got %q", final.Algorithm.ValueString())
	}
	if final.UsageMask.ValueInt64() != 12 {
		t.Errorf("expected usage_mask=12, got %d", final.UsageMask.ValueInt64())
	}
	if final.Description.ValueString() != "hydrated description" {
		t.Errorf("expected hydrated description, got %q", final.Description.ValueString())
	}
	if final.RotationFrequencyDays.ValueString() != "45" {
		t.Errorf("expected rotation_frequency_days=45, got %q", final.RotationFrequencyDays.ValueString())
	}
	if !final.UnDeletable.ValueBool() || !final.UnExportable.ValueBool() || final.EmptyMaterial.ValueBool() || !final.XTS.ValueBool() {
		t.Errorf("expected bool fields hydrated from response, got %+v", final)
	}
	if final.State.ValueString() != "Active" || final.UUID.ValueString() != "11111111-1111-1111-1111-111111111111" ||
		final.MUID.ValueString() != "muid-hydrated" || final.ObjectType.ValueString() != "Symmetric Key" {
		t.Errorf("expected server-auto fields hydrated, got %+v", final)
	}
	labelsMap := final.Labels.Elements()
	if _, ok := labelsMap["ncryptify-reserved/internal"]; ok {
		t.Errorf("expected ncryptify-reserved/ label to be filtered out, got %+v", labelsMap)
	}
	if v, ok := labelsMap["env"]; !ok || v.(types.String).ValueString() != "prod" {
		t.Errorf("expected env=prod label, got %+v", labelsMap)
	}
	if len(final.Aliases) != 1 || final.Aliases[0].Alias.ValueString() != "configured-alias" {
		t.Errorf("expected server-auto key-name alias filtered out, got %+v", final.Aliases)
	}
	if final.Metadata == nil || final.Metadata.OwnerId.ValueString() != "owner-1" {
		t.Fatalf("expected meta hydrated, got %+v", final.Metadata)
	}
	if final.Metadata.CTE == nil || !final.Metadata.CTE.PersistentOnClient.ValueBool() || final.Metadata.CTE.EncryptionMode.ValueString() != "CBC" {
		t.Errorf("expected meta.cte hydrated, got %+v", final.Metadata.CTE)
	}
	if final.Metadata.Permissions == nil || len(final.Metadata.Permissions.UseKey) != 1 {
		t.Errorf("expected meta.permissions hydrated, got %+v", final.Metadata.Permissions)
	}
}

func Test_CMKeyRead_MetaPermissionsSnakeCaseCasing(t *testing.T) {
	// CM persists meta.permissions under whichever casing was last PATCHed - including
	// snake_case written by a non-Terraform client - and echoes that casing back on GET.
	responseJSON := `{
		"id": "key-1",
		"name": "tf-key",
		"meta": {
			"permissions": {
				"read_key": ["CTE Clients"],
				"export_key": ["CTE Clients"]
			}
		}
	}`
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseJSON)
	})

	state := &CMKeyTFSDK{
		ID:   types.StringValue("key-1"),
		Name: types.StringValue("tf-key"),
		Metadata: &KeyMetadataTFSDK{
			Permissions: &KeyMetadataPermissionsTFSDK{
				ReadKey:   []types.String{types.StringValue("CTE Clients")},
				ExportKey: []types.String{types.StringValue("CTE Clients")},
			},
		},
	}

	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}

	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)

	if final.Metadata == nil || final.Metadata.Permissions == nil {
		t.Fatalf("expected meta.permissions hydrated, got %+v", final.Metadata)
	}
	perms := final.Metadata.Permissions
	if len(perms.ReadKey) != 1 || perms.ReadKey[0].ValueString() != "CTE Clients" {
		t.Errorf("expected read_key hydrated from snake_case response, got %+v", perms.ReadKey)
	}
	if len(perms.ExportKey) != 1 || perms.ExportKey[0].ValueString() != "CTE Clients" {
		t.Errorf("expected export_key hydrated from snake_case response, got %+v", perms.ExportKey)
	}
}

func Test_CMKeyRead_AlgorithmDriftSurfaced(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"id":"key-1","algorithm":"rsa"}`)
	})
	state := &CMKeyTFSDK{ID: types.StringValue("key-1"), Algorithm: types.StringValue("aes")}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if final.Algorithm.ValueString() != "rsa" {
		t.Errorf("expected genuine algorithm drift to surface as 'rsa', got %q", final.Algorithm.ValueString())
	}
}

func Test_CMKeyRead_AlgorithmNullStateSkipsHydration(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"id":"key-1","algorithm":"aes"}`)
	})
	state := &CMKeyTFSDK{ID: types.StringValue("key-1"), Algorithm: types.StringNull()}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if !final.Algorithm.IsNull() {
		t.Errorf("expected algorithm to remain null (template-driven), got %q", final.Algorithm.ValueString())
	}
}

func Test_CMKeyRead_RotationFrequencyDaysEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		stateValue string
		want       string
		wantNull   bool
	}{
		{"server_empty_state_zero_preserved", `{"id":"key-1","rotationFrequencyDays":""}`, "0", "0", false},
		{"absent_state_zero_preserved", `{"id":"key-1"}`, "0", "0", false},
		{"absent_state_nonzero_becomes_null", `{"id":"key-1"}`, "30", "", true},
		{"present_hydrates", `{"id":"key-1","rotationFrequencyDays":"60"}`, "30", "60", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
				fmt.Fprint(w, tc.response)
			})
			state := &CMKeyTFSDK{ID: types.StringValue("key-1"), RotationFrequencyDays: types.StringValue(tc.stateValue)}
			req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
			resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
			r.Read(ctx, req, resp)
			var final CMKeyTFSDK
			resp.State.Get(ctx, &final)
			if tc.wantNull {
				if !final.RotationFrequencyDays.IsNull() {
					t.Errorf("expected null, got %q", final.RotationFrequencyDays.ValueString())
				}
			} else if final.RotationFrequencyDays.ValueString() != tc.want {
				t.Errorf("expected %q, got %q", tc.want, final.RotationFrequencyDays.ValueString())
			}
		})
	}
}

func Test_CMKeyRead_BoolFieldsAbsentPreservesState(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"id":"key-1"}`) // no undeletable/unexportable/emptyMaterial/xts
	})
	state := &CMKeyTFSDK{
		ID:            types.StringValue("key-1"),
		UnDeletable:   types.BoolValue(true),
		UnExportable:  types.BoolValue(true),
		EmptyMaterial: types.BoolValue(true),
		XTS:           types.BoolValue(true),
	}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if !final.UnDeletable.ValueBool() || !final.UnExportable.ValueBool() || !final.XTS.ValueBool() {
		t.Errorf("expected undeletable/unexportable/xts preserved from state when absent, got %+v", final)
	}
	if !final.EmptyMaterial.IsNull() {
		t.Errorf("expected empty_material to become null when absent from response, got %+v", final.EmptyMaterial)
	}
}

func Test_CMKeyRead_NeverConfiguredFieldsStayUntouched(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{
			"id": "key-1",
			"usageMask": 99,
			"size": 999,
			"description": "server desc",
			"undeletable": true,
			"unexportable": true,
			"emptyMaterial": true,
			"xts": true,
			"state": "Active",
			"uuid": "u",
			"muid": "m",
			"objectType": "Symmetric Key",
			"defaultIV": "iv",
			"activationDate": "a",
			"deactivationDate": "d",
			"archiveDate": "ar",
			"labels": {"foo":"bar"}
		}`)
	})
	// state has all these fields null (never configured by user)
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if !final.UsageMask.IsNull() || !final.Size.IsNull() || !final.Description.IsNull() ||
		!final.UnDeletable.IsNull() || !final.UnExportable.IsNull() || !final.EmptyMaterial.IsNull() || !final.XTS.IsNull() ||
		!final.State.IsNull() || !final.UUID.IsNull() || !final.MUID.IsNull() || !final.ObjectType.IsNull() ||
		!final.DefaultIV.IsNull() || !final.ActivationDate.IsNull() || !final.DeactivationDate.IsNull() || !final.ArchiveDate.IsNull() ||
		!final.Labels.IsNull() {
		t.Errorf("expected all never-configured fields to remain null/untouched, got %+v", final)
	}
}

// readCapture runs Read() with the given state against a fake 200 response body and
// returns the final hydrated state. Shared by the focused Read() tests below.
func readCapture(t *testing.T, state *CMKeyTFSDK, responseBody string) CMKeyTFSDK {
	t.Helper()
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, responseBody)
	})
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	return final
}

func Test_CMKeyRead_ConfiguredFieldsAbsentFromResponseBecomeNull(t *testing.T) {
	// The inverse of Test_CMKeyRead_NeverConfiguredFieldsStayUntouched: when the user DID
	// configure these fields (state non-null) but the response omits them, each guarded
	// Optional+Computed field must reset to null, not silently keep the stale state value.
	// usage_mask is deliberately excluded here — CM omits "usageMask" from the response
	// specifically when its value is 0, so absence means 0, not null. See
	// Test_CMKeyRead_UsageMaskAbsentFromResponseBecomesZero.
	state := &CMKeyTFSDK{
		ID:          types.StringValue("key-1"),
		Algorithm:   types.StringValue("aes"),
		Size:        types.Int64Value(256),
		Description: types.StringValue("stale description"),
		State:       types.StringValue("Pre-Active"),
		UUID:        types.StringValue("stale-uuid"),
		MUID:        types.StringValue("stale-muid"),
		ObjectType:  types.StringValue("Symmetric Key"),
		DefaultIV:   types.StringValue("stale-iv"),
		ActivationDate:   types.StringValue("stale-activation"),
		DeactivationDate: types.StringValue("stale-deactivation"),
		ArchiveDate:      types.StringValue("stale-archive"),
	}
	final := readCapture(t, state, `{"id":"key-1"}`) // every other field omitted
	for _, tc := range []struct {
		name  string
		value interface{ IsNull() bool }
	}{
		{"algorithm", final.Algorithm},
		{"key_size", final.Size},
		{"description", final.Description},
		{"state", final.State},
		{"uuid", final.UUID},
		{"muid", final.MUID},
		{"object_type", final.ObjectType},
		{"default_iv", final.DefaultIV},
		{"activation_date", final.ActivationDate},
		{"deactivation_date", final.DeactivationDate},
		{"archive_date", final.ArchiveDate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.value.IsNull() {
				t.Errorf("expected %s to become null when absent from response, got %+v", tc.name, tc.value)
			}
		})
	}
}

func Test_CMKeyRead_UsageMaskAbsentFromResponseBecomesZero(t *testing.T) {
	// CM omits "usageMask" from the response specifically when its value is 0 (confirmed
	// live) — indistinguishable on the wire from "field never set". Since this only
	// matters when the field was already configured, absence must resolve to 0, not null,
	// or a config of usage_mask = 0 would never converge.
	state := &CMKeyTFSDK{
		ID:        types.StringValue("key-1"),
		UsageMask: types.Int64Value(12),
	}
	final := readCapture(t, state, `{"id":"key-1"}`) // usageMask omitted
	if final.UsageMask.IsNull() || final.UsageMask.ValueInt64() != 0 {
		t.Errorf("expected usage_mask to resolve to 0 when absent from response, got %+v", final.UsageMask)
	}
}

func Test_CMKeyRead_AliasFieldsMissingBecomeNull(t *testing.T) {
	state := &CMKeyTFSDK{
		ID:   types.StringValue("key-1"),
		Name: types.StringValue("tf-key"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("configured-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	// Response alias has "alias" but omits "index" and "type" entirely.
	final := readCapture(t, state, `{"id":"key-1","aliases":[{"alias":"configured-alias"}]}`)
	if len(final.Aliases) != 1 {
		t.Fatalf("expected 1 hydrated alias, got %+v", final.Aliases)
	}
	if !final.Aliases[0].Index.IsNull() || !final.Aliases[0].Type.IsNull() {
		t.Errorf("expected index/type to be null when absent from response, got %+v", final.Aliases[0])
	}
}

func Test_CMKeyRead_AliasSortHandlesEntriesNotInStateOrder(t *testing.T) {
	state := &CMKeyTFSDK{
		ID:   types.StringValue("key-1"),
		Name: types.StringValue("tf-key"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("known-alias"), Index: types.StringValue("0"), Type: types.StringValue("string")},
		},
	}
	// Response includes extra aliases the prior state never knew about (not equal to the
	// key name, so not filtered) — exercises the sort comparator's "not in stateOrder" path.
	final := readCapture(t, state, `{"id":"key-1","aliases":[`+
		`{"alias":"surprise-one","index":"1","type":"string"},`+
		`{"alias":"known-alias","index":"0","type":"string"},`+
		`{"alias":"surprise-two","index":"2","type":"string"}]}`)
	if len(final.Aliases) != 3 {
		t.Fatalf("expected all 3 response aliases hydrated, got %+v", final.Aliases)
	}
}

func Test_CMKeyRead_AliasesNilWhenOnlyAutoKeyNameAliasPresent(t *testing.T) {
	state := &CMKeyTFSDK{
		ID:   types.StringValue("key-1"),
		Name: types.StringValue("tf-key"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("configured-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	// Response's only alias is the server-auto-created key-name alias, which gets
	// filtered out — leaving zero hydrated aliases (the "aliases != nil" false branch).
	final := readCapture(t, state, `{"id":"key-1","name":"tf-key","aliases":[{"alias":"tf-key","index":"0","type":"string"}]}`)
	if final.Aliases != nil {
		t.Errorf("expected aliases to be nil when only the auto key-name alias is returned, got %+v", final.Aliases)
	}
}

func Test_CMKeyRead_AliasesNilWhenResponseOmitsAliases(t *testing.T) {
	state := &CMKeyTFSDK{
		ID:   types.StringValue("key-1"),
		Name: types.StringValue("tf-key"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("configured-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	final := readCapture(t, state, `{"id":"key-1"}`) // no "aliases" key at all
	if final.Aliases != nil {
		t.Errorf("expected aliases to be nil when response omits the aliases field entirely, got %+v", final.Aliases)
	}
}

func Test_CMKeyRead_MetaEmptyObjectYieldsNullOwnerAndNilBlocks(t *testing.T) {
	state := &CMKeyTFSDK{
		ID:       types.StringValue("key-1"),
		Metadata: &KeyMetadataTFSDK{OwnerId: types.StringValue("stale-owner")},
	}
	final := readCapture(t, state, `{"id":"key-1","meta":{}}`)
	if final.Metadata == nil {
		t.Fatal("expected meta to still be hydrated (non-nil) since the response has a meta object")
	}
	if !final.Metadata.OwnerId.IsNull() {
		t.Errorf("expected meta.ownerId to be null when absent from response, got %+v", final.Metadata.OwnerId)
	}
	if final.Metadata.Permissions != nil {
		t.Errorf("expected meta.permissions to be nil when absent from response, got %+v", final.Metadata.Permissions)
	}
	if final.Metadata.CTE != nil {
		t.Errorf("expected meta.cte to be nil when absent from response, got %+v", final.Metadata.CTE)
	}
}

func Test_CMKeyRead_MetaCTEEmptyObjectYieldsNullFields(t *testing.T) {
	state := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Metadata: &KeyMetadataTFSDK{
			CTE: &KeyMetadataCTETFSDK{
				PersistentOnClient: types.BoolValue(true),
				EncryptionMode:     types.StringValue("CBC"),
				CTEVersioned:       types.BoolValue(true),
			},
		},
	}
	final := readCapture(t, state, `{"id":"key-1","meta":{"cte":{}}}`)
	if final.Metadata == nil || final.Metadata.CTE == nil {
		t.Fatalf("expected meta.cte to still be hydrated (non-nil), got %+v", final.Metadata)
	}
	if !final.Metadata.CTE.PersistentOnClient.IsNull() || !final.Metadata.CTE.EncryptionMode.IsNull() || !final.Metadata.CTE.CTEVersioned.IsNull() {
		t.Errorf("expected all meta.cte fields to be null when absent from an empty cte object, got %+v", final.Metadata.CTE)
	}
}

func Test_CMKeyRead_LabelsResponseNullBecomesStateNull(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"id":"key-1","labels":null}`)
	})
	state := &CMKeyTFSDK{
		ID:     types.StringValue("key-1"),
		Labels: strMap(map[string]string{"env": "x"}),
	}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if !final.Labels.IsNull() {
		t.Errorf("expected labels to become null when response labels is null, got %+v", final.Labels)
	}
}

func Test_CMKeyRead_LabelsEmptyAfterFilterBecomesEmptyMap(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"id":"key-1","labels":{"ncryptify-reserved/x":"y"}}`)
	})
	state := &CMKeyTFSDK{
		ID:     types.StringValue("key-1"),
		Labels: strMap(map[string]string{"env": "x"}),
	}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if final.Labels.IsNull() {
		t.Fatal("expected labels to be an empty map, not null")
	}
	if len(final.Labels.Elements()) != 0 {
		t.Errorf("expected labels to be empty after filtering reserved keys, got %+v", final.Labels.Elements())
	}
}

func Test_CMKeyRead_MetaClearedWhenServerNoLongerReturnsIt(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"id":"key-1"}`) // no meta
	})
	state := &CMKeyTFSDK{
		ID:       types.StringValue("key-1"),
		Metadata: &KeyMetadataTFSDK{OwnerId: types.StringValue("owner-1")},
	}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if final.Metadata != nil {
		t.Errorf("expected meta cleared when server no longer returns it, got %+v", final.Metadata)
	}
}

func Test_CMKeyRead_PublicKeyParametersPreservedFromState(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, `{"id":"key-1"}`)
	})
	state := &CMKeyTFSDK{
		ID:                  types.StringValue("key-1"),
		PublicKeyParameters: &PublicKeyParametersTFSDK{Name: types.StringValue("pub-key-name")},
	}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if final.PublicKeyParameters == nil || final.PublicKeyParameters.Name.ValueString() != "pub-key-name" {
		t.Errorf("expected public_key_parameters preserved from state, got %+v", final.PublicKeyParameters)
	}
}

func Test_CMKeyRead_TransportErrorSurfaces(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"boom"}`)
	})
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	req := resource.ReadRequest{State: mustState(t, ctx, schemaResp, state)}
	resp := &resource.ReadResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Read(ctx, req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic on transport failure")
	}
	found := false
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Summary(), "Error Reading CipherTrust Key") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected read error, got: %v", resp.Diagnostics.Errors())
	}
}

// ---------------------------------------------------------------------------
// Update()
// ---------------------------------------------------------------------------

// updateCapture runs Update() with the given plan/state against a fake 200 response body
// and returns the captured PATCH body plus the final hydrated state. Shared by the focused
// Update() tests below so each test only needs to state its own plan/state/response.
func updateCapture(t *testing.T, plan, state *CMKeyTFSDK, responseBody string) (CMKeyJSON, CMKeyTFSDK) {
	t.Helper()
	var capturedBody string
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		b := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(b)
		// A plan/state pair with a changed revocation_reason/revocation_message
		// triggers a second, separate POST to the /revoke endpoint (see revokeKey)
		// right after the PATCH. Handle it distinctly so it doesn't clobber the
		// PATCH body below.
		if strings.HasSuffix(req.URL.Path, "/revoke") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{}`)
			return
		}
		capturedBody = string(b)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, responseBody)
	})
	req := resource.UpdateRequest{
		Plan:  mustPlan(t, ctx, schemaResp, plan),
		State: mustState(t, ctx, schemaResp, state),
	}
	resp := &resource.UpdateResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var payload CMKeyJSON
	if err := json.Unmarshal([]byte(capturedBody), &payload); err != nil {
		t.Fatalf("failed to unmarshal PATCH payload: %v", err)
	}
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	return payload, final
}

func aliasIndexByName(aliases []KeyAliasJSON) map[string]*int64 {
	m := make(map[string]*int64, len(aliases))
	for _, a := range aliases {
		m[a.Alias] = a.Index
	}
	return m
}

func Test_CMKeyUpdate_NewAliasEmitsAddWithNoIndex(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("new-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	payload, _ := updateCapture(t, plan, state, `{"id":"key-1","aliases":[{"alias":"new-alias","index":"5","type":"string"}]}`)
	idx, ok := aliasIndexByName(payload.Aliases)["new-alias"]
	if !ok || idx != nil {
		t.Errorf("expected new-alias sent as ADD with no index, got %+v", payload.Aliases)
	}
}

func Test_CMKeyUpdate_RemovedAliasEmitsDeleteWithIndexOnly(t *testing.T) {
	state := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("removed-alias"), Index: types.StringValue("2"), Type: types.StringValue("string")},
		},
	}
	plan := &CMKeyTFSDK{ID: types.StringValue("key-1")} // alias removed from plan
	payload, _ := updateCapture(t, plan, state, `{"id":"key-1"}`)
	if len(payload.Aliases) != 1 || payload.Aliases[0].Alias != "" || payload.Aliases[0].Index == nil || *payload.Aliases[0].Index != 2 {
		t.Errorf("expected a single DELETE entry with index=2 and no alias name, got %+v", payload.Aliases)
	}
}

func Test_CMKeyUpdate_UnchangedAliasNotResent(t *testing.T) {
	state := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("unchanged-alias"), Index: types.StringValue("0"), Type: types.StringValue("string")},
		},
	}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("unchanged-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	payload, _ := updateCapture(t, plan, state, `{"id":"key-1"}`)
	if len(payload.Aliases) != 0 {
		t.Errorf("expected unchanged-alias to NOT be re-sent in the PATCH payload, got %+v", payload.Aliases)
	}
}

func Test_CMKeyUpdate_DescriptionClearedOnTransitionToNull(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1"), Description: types.StringValue("old description")}
	plan := &CMKeyTFSDK{ID: types.StringValue("key-1"), Description: types.StringNull()}
	payload, _ := updateCapture(t, plan, state, `{"id":"key-1"}`)
	if payload.Description == nil || *payload.Description != "" {
		t.Errorf("expected description explicitly cleared to \"\" when transitioning set -> null, got %+v", payload.Description)
	}
}

func Test_CMKeyUpdate_MetadataCTEInPayload(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Metadata: &KeyMetadataTFSDK{
			OwnerId: types.StringValue("owner-2"),
			CTE: &KeyMetadataCTETFSDK{
				PersistentOnClient: types.BoolValue(true),
				EncryptionMode:     types.StringValue("XTS"),
				CTEVersioned:       types.BoolValue(false),
			},
		},
	}
	payload, _ := updateCapture(t, plan, state, `{"id":"key-1"}`)
	if payload.Metadata == nil || payload.Metadata.OwnerId != "owner-2" {
		t.Fatalf("expected meta.ownerId=owner-2 in PATCH payload, got %+v", payload.Metadata)
	}
	if payload.Metadata.CTE == nil || payload.Metadata.CTE.EncryptionMode != "XTS" || !payload.Metadata.CTE.PersistentOnClient {
		t.Errorf("expected meta.cte in PATCH payload, got %+v", payload.Metadata.CTE)
	}
}

func Test_CMKeyUpdate_MetadataPermissionsInPayload(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Metadata: &KeyMetadataTFSDK{
			Permissions: &KeyMetadataPermissionsTFSDK{
				DecryptWithKey:    strList("user1"),
				EncryptWithKey:    strList("user1"),
				ExportKey:         strList("user1"),
				MACVerifyWithKey:  strList("user1"),
				MACWithKey:        strList("user1"),
				ReadKey:           strList("user1"),
				SignVerifyWithKey: strList("user1"),
				SignWithKey:       strList("user1"),
				UseKey:            strList("user1"),
			},
		},
	}
	payload, _ := updateCapture(t, plan, state, `{"id":"key-1"}`)
	if payload.Metadata == nil || payload.Metadata.Permissions == nil {
		t.Fatalf("expected meta.permissions in PATCH payload, got %+v", payload.Metadata)
	}
	p := payload.Metadata.Permissions
	for _, tc := range []struct {
		name string
		got  []string
	}{
		{"decrypt_with_key", p.DecryptWithKey},
		{"encrypt_with_key", p.EncryptWithKey},
		{"export_key", p.ExportKey},
		{"mac_verify_with_key", p.MACVerifyWithKey},
		{"mac_with_key", p.MACWithKey},
		{"read_key", p.ReadKey},
		{"sign_verify_with_key", p.SignVerifyWithKey},
		{"sign_with_key", p.SignWithKey},
		{"use_key", p.UseKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.got) != 1 || tc.got[0] != "user1" {
				t.Errorf("expected [\"user1\"], got %+v", tc.got)
			}
		})
	}
}

func Test_CMKeyUpdate_RemainingScalarFieldsInPayload(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{
		ID:                       types.StringValue("key-1"),
		ActivationDate:           types.StringValue("2024-01-01T00:00:00Z"),
		ArchiveDate:              types.StringValue("2024-02-01T00:00:00Z"),
		CompromiseOccurrenceDate: types.StringValue("2024-03-01T00:00:00Z"),
		DeactivationDate:         types.StringValue("2025-01-01T00:00:00Z"),
		KeyId:                    types.StringValue("1234"),
		MUID:                     types.StringValue("muid-1"),
		ProcessStartDate:         types.StringValue("2024-01-01T00:00:00Z"),
		ProtectStopDate:          types.StringValue("2030-01-01T00:00:00Z"),
		RotationFrequencyDays:    types.StringValue("30"),
		UnDeletable:              types.BoolValue(true),
		UnExportable:             types.BoolValue(true),
		UsageMask:                types.Int64Value(12),
		AllVersions:              types.BoolValue(true),
		Labels:                   strMap(map[string]string{"env": "test"}),
	}
	payload, _ := updateCapture(t, plan, state, `{"id":"key-1"}`)
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to re-marshal captured payload: %v", err)
	}
	body := string(payloadJSON)
	for _, tc := range []struct{ name, want string }{
		{"activation_date", `"activationDate":"2024-01-01T00:00:00Z"`},
		{"archive_date", `"archiveDate":"2024-02-01T00:00:00Z"`},
		{"compromise_occurrence_date", `"compromiseOccurrenceDate":"2024-03-01T00:00:00Z"`},
		{"deactivation_date", `"deactivationDate":"2025-01-01T00:00:00Z"`},
		{"key_id", `"keyId":"1234"`},
		{"muid", `"muid":"muid-1"`},
		{"process_start_date", `"processStartDate":"2024-01-01T00:00:00Z"`},
		{"protect_stop_date", `"protectStopDate":"2030-01-01T00:00:00Z"`},
		{"rotation_frequency_days", `"rotationFrequencyDays":"30"`},
		{"undeletable", `"undeletable":true`},
		{"unexportable", `"unexportable":true`},
		{"usage_mask", `"usageMask":12`},
		{"all_versions", `"allVersions":true`},
		{"labels", `"env":"test"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !strings.Contains(body, tc.want) {
				t.Errorf("expected PATCH payload to contain %s, got: %s", tc.want, body)
			}
		})
	}
}

func Test_CMKeyUpdate_RevocationSentToRevokeEndpointOnChange(t *testing.T) {
	// Mirrors the revocationChanged gate in Update(): revocation is a dedicated CM
	// operation (see revokeKey), resent only when reason/message actually changed —
	// not on every apply — so an already-revoked key isn't re-revoked repeatedly.
	for _, tc := range []struct {
		name          string
		state         *CMKeyTFSDK
		plan          *CMKeyTFSDK
		expectRevoked bool
	}{
		{
			name:          "unchanged revocation is not resent",
			state:         &CMKeyTFSDK{ID: types.StringValue("key-1"), RevocationReason: types.StringValue("KeyCompromise"), RevocationMessage: types.StringValue("revoked for testing")},
			plan:          &CMKeyTFSDK{ID: types.StringValue("key-1"), RevocationReason: types.StringValue("KeyCompromise"), RevocationMessage: types.StringValue("revoked for testing")},
			expectRevoked: false,
		},
		{
			name:          "newly set revocation is sent",
			state:         &CMKeyTFSDK{ID: types.StringValue("key-1")},
			plan:          &CMKeyTFSDK{ID: types.StringValue("key-1"), RevocationReason: types.StringValue("KeyCompromise"), RevocationMessage: types.StringValue("revoked for testing")},
			expectRevoked: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var revokeCalled bool
			var revokeBody string
			r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
				b := make([]byte, req.ContentLength)
				_, _ = req.Body.Read(b)
				if strings.HasSuffix(req.URL.Path, "/revoke") {
					revokeCalled = true
					revokeBody = string(b)
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{}`)
					return
				}
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"id":"key-1"}`)
			})
			req := resource.UpdateRequest{
				Plan:  mustPlan(t, ctx, schemaResp, tc.plan),
				State: mustState(t, ctx, schemaResp, tc.state),
			}
			resp := &resource.UpdateResponse{State: mustState(t, ctx, schemaResp, tc.state)}
			r.Update(ctx, req, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}
			if revokeCalled != tc.expectRevoked {
				t.Fatalf("expected revokeCalled=%v, got %v", tc.expectRevoked, revokeCalled)
			}
			if tc.expectRevoked && (!strings.Contains(revokeBody, `"reason":"KeyCompromise"`) || !strings.Contains(revokeBody, `"message":"revoked for testing"`)) {
				t.Errorf(`expected revoke body to contain "reason":"KeyCompromise" and "message":"revoked for testing", got: %s`, revokeBody)
			}
		})
	}
}

func Test_CMKeyUpdate_AliasRehydrationHandlesMissingIndexAndType(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("new-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	// PATCH response echoes the new alias but omits index/type.
	_, final := updateCapture(t, plan, state, `{"id":"key-1","aliases":[{"alias":"new-alias"}]}`)
	if len(final.Aliases) != 1 {
		t.Fatalf("expected 1 hydrated alias, got %+v", final.Aliases)
	}
	if !final.Aliases[0].Index.IsNull() || !final.Aliases[0].Type.IsNull() {
		t.Errorf("expected index/type to be null when absent from PATCH response, got %+v", final.Aliases[0])
	}
}

func Test_CMKeyUpdate_AliasRehydrationSortsMultipleAliases(t *testing.T) {
	state := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("unchanged-alias"), Index: types.StringValue("0"), Type: types.StringValue("string")},
		},
	}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("unchanged-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
			{Alias: types.StringValue("new-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	// Two entries in the final hydrated list forces sort.Slice to actually invoke its
	// comparator (a single-element slice never does).
	_, final := updateCapture(t, plan, state, `{"id":"key-1","aliases":[{"alias":"new-alias","index":"5","type":"string"}]}`)
	if len(final.Aliases) != 2 || final.Aliases[0].Alias.ValueString() != "unchanged-alias" || final.Aliases[1].Alias.ValueString() != "new-alias" {
		t.Errorf("expected both aliases hydrated in plan order, got %+v", final.Aliases)
	}
}

func Test_CMKeyUpdate_XTSResolvedFromUnknownToPriorStateValue(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1"), XTS: types.BoolValue(true)}
	plan := &CMKeyTFSDK{ID: types.StringValue("key-1"), XTS: types.BoolUnknown()}
	// Update() has no response-hydration branch for xts (unlike undeletable/unexportable):
	// it is only ever resolved from Unknown back to the prior state value.
	_, final := updateCapture(t, plan, state, `{"id":"key-1"}`)
	if !final.XTS.ValueBool() {
		t.Errorf("expected xts resolved from unknown to prior state value (true), got %+v", final.XTS)
	}
}

func Test_CMKeyUpdate_UnDeletableResolvedFromUnknownThenHydratedFromResponse(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1"), UnDeletable: types.BoolValue(false)}
	plan := &CMKeyTFSDK{ID: types.StringValue("key-1"), UnDeletable: types.BoolUnknown()}
	_, final := updateCapture(t, plan, state, `{"id":"key-1","undeletable":true}`)
	if !final.UnDeletable.ValueBool() {
		t.Errorf("expected undeletable resolved from unknown to state, then overridden by PATCH response, got %+v", final.UnDeletable)
	}
}

func Test_CMKeyUpdate_UnExportableResolvedFromUnknownThenHydratedFromResponse(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1"), UnExportable: types.BoolValue(false)}
	plan := &CMKeyTFSDK{ID: types.StringValue("key-1"), UnExportable: types.BoolUnknown()}
	_, final := updateCapture(t, plan, state, `{"id":"key-1","unexportable":true}`)
	if !final.UnExportable.ValueBool() {
		t.Errorf("expected unexportable resolved from unknown to state, then overridden by PATCH response, got %+v", final.UnExportable)
	}
}

func Test_CMKeyUpdate_UnchangedAliasPreservesStateIndexOnRehydration(t *testing.T) {
	state := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("unchanged-alias"), Index: types.StringValue("0"), Type: types.StringValue("string")},
		},
	}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("unchanged-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	// PATCH response omits the alias entirely (unchanged aliases are never re-sent), so
	// rehydration must come from state, not from the response.
	_, final := updateCapture(t, plan, state, `{"id":"key-1"}`)
	if len(final.Aliases) != 1 || final.Aliases[0].Index.ValueString() != "0" {
		t.Errorf("expected unchanged-alias preserved from state with index 0, got %+v", final.Aliases)
	}
}

func Test_CMKeyUpdate_NewAliasPicksUpServerAssignedIndexOnRehydration(t *testing.T) {
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{
		ID: types.StringValue("key-1"),
		Aliases: []*KeyAliasTFSDK{
			{Alias: types.StringValue("new-alias"), Index: types.StringNull(), Type: types.StringValue("string")},
		},
	}
	_, final := updateCapture(t, plan, state, `{"id":"key-1","aliases":[{"alias":"new-alias","index":"5","type":"string"}]}`)
	if len(final.Aliases) != 1 || final.Aliases[0].Index.ValueString() != "5" {
		t.Errorf("expected new-alias to pick up server-assigned index 5, got %+v", final.Aliases)
	}
}

func Test_CMKeyUpdate_DescriptionNeverSetStaysOmitted(t *testing.T) {
	var capturedBody string
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		b := make([]byte, req.ContentLength)
		_, _ = req.Body.Read(b)
		capturedBody = string(b)
		fmt.Fprint(w, `{"id":"key-1"}`)
	})
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	req := resource.UpdateRequest{
		Plan:  mustPlan(t, ctx, schemaResp, plan),
		State: mustState(t, ctx, schemaResp, state),
	}
	resp := &resource.UpdateResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Update(ctx, req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var payload CMKeyJSON
	_ = json.Unmarshal([]byte(capturedBody), &payload)
	if payload.Description != nil {
		t.Errorf("expected description to stay omitted from PATCH payload, got %+v", *payload.Description)
	}
}

func Test_CMKeyUpdate_TransportErrorSurfaces(t *testing.T) {
	r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"boom"}`)
	})
	state := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	plan := &CMKeyTFSDK{ID: types.StringValue("key-1")}
	req := resource.UpdateRequest{
		Plan:  mustPlan(t, ctx, schemaResp, plan),
		State: mustState(t, ctx, schemaResp, state),
	}
	resp := &resource.UpdateResponse{State: mustState(t, ctx, schemaResp, state)}
	r.Update(ctx, req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error diagnostic on transport failure")
	}
	found := false
	for _, e := range resp.Diagnostics.Errors() {
		if strings.Contains(e.Summary(), "Error updating key on CipherTrust Manager") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected update error, got: %v", resp.Diagnostics.Errors())
	}
}

// ---------------------------------------------------------------------------
// Delete()
// ---------------------------------------------------------------------------

func Test_CMKeyDelete_Scenarios(t *testing.T) {
	tests := []struct {
		name                     string
		status                   int
		body                     string
		removeFromStateOnDestroy bool
		wantError                bool
		wantWarning              bool
		wantSummaryContains      string
	}{
		{"success", http.StatusNoContent, "", false, false, false, ""},
		{"not_found", http.StatusNotFound, `{"error":"not found"}`, false, false, true, common.NotFoundDeleteWarningSummary},
		{"not_deletable_with_flag", http.StatusBadRequest, `{"error":"key is not deletable"}`, true, false, true, "removed from state"},
		{"not_deletable_without_flag", http.StatusBadRequest, `{"error":"key is not deletable"}`, false, true, false, "Error Deleting CipherTrust Key"},
		{"insufficient_permissions_with_flag", http.StatusForbidden, `{"error":"InsufficientPermissions"}`, true, false, true, "insufficient permissions"},
		{"generic_error", http.StatusInternalServerError, `{"error":"boom"}`, false, true, false, "Error Deleting CipherTrust Key"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			state := &CMKeyTFSDK{
				ID:                       types.StringValue("key-1"),
				RemoveFromStateOnDestroy: types.BoolValue(tc.removeFromStateOnDestroy),
			}
			req := resource.DeleteRequest{State: mustState(t, ctx, schemaResp, state)}
			resp := &resource.DeleteResponse{State: mustState(t, ctx, schemaResp, state)}
			r.Delete(ctx, req, resp)

			if tc.wantError && !resp.Diagnostics.HasError() {
				t.Fatalf("expected an error diagnostic, got none: %v", resp.Diagnostics)
			}
			if !tc.wantError && resp.Diagnostics.HasError() {
				t.Fatalf("expected no error diagnostic, got: %v", resp.Diagnostics.Errors())
			}
			if tc.wantWarning && len(resp.Diagnostics.Warnings()) == 0 {
				t.Fatalf("expected a warning diagnostic, got none")
			}
			if tc.wantSummaryContains != "" {
				found := false
				for _, d := range resp.Diagnostics {
					if strings.Contains(d.Summary(), tc.wantSummaryContains) || strings.Contains(d.Detail(), tc.wantSummaryContains) {
						found = true
					}
				}
				if !found {
					t.Errorf("expected diagnostics to mention %q, got: %v", tc.wantSummaryContains, resp.Diagnostics)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ImportState() / Configure() / Metadata() / NewResourceCMKey()
// ---------------------------------------------------------------------------

func Test_CMKeyImportState_SetsIDFromRequest(t *testing.T) {
	_, ctx, schemaResp := newTestCMKeyResource(t, func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("ImportState should not hit the network")
	})
	r := &resourceCMKey{}
	// ImportStatePassthroughID calls State.SetAttribute on an existing value tree, so
	// the response state must start out as a fully-typed null object (matching the
	// schema), not a zero-value tfsdk.State{} with no Raw set.
	resp := &resource.ImportStateResponse{State: mustState(t, ctx, schemaResp, &CMKeyTFSDK{})}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "imported-id"}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
	}
	var final CMKeyTFSDK
	resp.State.Get(ctx, &final)
	if final.ID.ValueString() != "imported-id" {
		t.Errorf("expected id=imported-id, got %q", final.ID.ValueString())
	}
}

func Test_CMKeyConfigure_Scenarios(t *testing.T) {
	t.Run("nil_provider_data_is_noop", func(t *testing.T) {
		r := &resourceCMKey{}
		resp := &resource.ConfigureResponse{}
		r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: nil}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("expected no diagnostics, got: %v", resp.Diagnostics)
		}
		if r.client != nil {
			t.Errorf("expected client to remain nil")
		}
	})
	t.Run("wrong_type_errors", func(t *testing.T) {
		r := &resourceCMKey{}
		resp := &resource.ConfigureResponse{}
		r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: "not-a-client"}, resp)
		if !resp.Diagnostics.HasError() {
			t.Error("expected an error diagnostic for wrong provider data type")
		}
	})
	t.Run("correct_type_sets_client", func(t *testing.T) {
		r := &resourceCMKey{}
		resp := &resource.ConfigureResponse{}
		client := &common.Client{}
		r.Configure(context.Background(), resource.ConfigureRequest{ProviderData: client}, resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("unexpected diagnostics: %v", resp.Diagnostics)
		}
		if r.client != client {
			t.Errorf("expected client to be set to the provided *common.Client")
		}
	})
}

func Test_CMKeyMetadata_And_NewResourceCMKey(t *testing.T) {
	res := NewResourceCMKey()
	if res == nil {
		t.Fatal("expected NewResourceCMKey() to return a non-nil resource")
	}
	var resp resource.MetadataResponse
	res.Metadata(context.Background(), resource.MetadataRequest{ProviderTypeName: "ciphertrust"}, &resp)
	if resp.TypeName != "ciphertrust_cm_key" {
		t.Errorf("expected TypeName=ciphertrust_cm_key, got %q", resp.TypeName)
	}
}
