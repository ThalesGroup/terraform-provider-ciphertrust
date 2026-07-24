// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// Test_CM_UserSchema_PasswordWriteOnly verifies that ciphertrust_user.password is
// marked WriteOnly (never stored in state/plan artifacts, per H-2 remediation) and
// that password_version exists as the companion state-tracked rotation trigger.
func Test_CM_UserSchema_PasswordWriteOnly(t *testing.T) {
	var resp resource.SchemaResponse
	(&resourceCMUser{}).Schema(context.Background(), resource.SchemaRequest{}, &resp)

	passwordAttr, ok := resp.Schema.Attributes["password"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected password attribute to be schema.StringAttribute, got %T", resp.Schema.Attributes["password"])
	}
	if !passwordAttr.WriteOnly {
		t.Error("expected password schema attribute to be marked WriteOnly: true")
	}
	if !passwordAttr.Sensitive {
		t.Error("expected password schema attribute to remain marked Sensitive: true")
	}

	if _, ok := resp.Schema.Attributes["password_version"].(schema.Int64Attribute); !ok {
		t.Fatalf("expected password_version attribute to be schema.Int64Attribute, got %T", resp.Schema.Attributes["password_version"])
	}
}

// newCMUserRawState builds a tftypes.Value covering every attribute declared in
// resourceCMUser's Schema(), so tests can construct a properly-typed initial state.
func newCMUserRawState(ctx context.Context, schemaResp resource.SchemaResponse, isDomainUser bool, metadata map[string]tftypes.Value) tftypes.Value {
	stateType := schemaResp.Schema.Type().TerraformType(ctx)
	return tftypes.NewValue(stateType, map[string]tftypes.Value{
		"id":                       tftypes.NewValue(tftypes.String, "user-id-1"),
		"user_id":                  tftypes.NewValue(tftypes.String, "user-id-1"),
		"username":                 tftypes.NewValue(tftypes.String, "testuser"),
		"nickname":                 tftypes.NewValue(tftypes.String, "nick"),
		"email":                    tftypes.NewValue(tftypes.String, "testuser@example.com"),
		"name":                     tftypes.NewValue(tftypes.String, "Test User"),
		"password":                 tftypes.NewValue(tftypes.String, "s3cr3t!"),
		"password_version":         tftypes.NewValue(tftypes.Number, 1),
		"is_domain_user":           tftypes.NewValue(tftypes.Bool, isDomainUser),
		"prevent_ui_login":         tftypes.NewValue(tftypes.Bool, false),
		"password_change_required": tftypes.NewValue(tftypes.Bool, false),
		"user_metadata":            tftypes.NewValue(tftypes.Map{ElementType: tftypes.String}, metadata),
	})
}

// Test_CM_UserRead_IsDomainUserPreservedWhenCMOmitsKey guards against the bug where
// CM's GET /usermgmt/users/{id} response never includes "is_domain_user" for local
// users, which previously caused Read() to always overwrite state with false via
// Go's json.Unmarshal zero-value fallback (silently discarding a true value set by
// Terraform). Read() must now preserve the existing state value in that case.
func Test_CM_UserRead_IsDomainUserPreservedWhenCMOmitsKey(t *testing.T) {
	// Fake CM response for a local user: no "is_domain_user" key at all.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{
			"user_id":"user-id-1",
			"username":"testuser",
			"nickname":"nick",
			"email":"testuser@example.com",
			"name":"Test User",
			"login_flags":{"prevent_ui_login":false},
			"password_change_required":false
		}`)
	}))
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMUser{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	rawState := newCMUserRawState(ctx, schemaResp, true, map[string]tftypes.Value{})

	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    rawState,
		},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    rawState,
		},
	}

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read(): %v", resp.Diagnostics)
	}

	var newState CMUserTFSDK
	if diags := resp.State.Get(ctx, &newState); diags.HasError() {
		t.Fatalf("unexpected diagnostics reading back state: %v", diags)
	}

	if !newState.IsDomainUser.ValueBool() {
		t.Errorf("is_domain_user: expected true to be preserved when CM omits the key, got %v", newState.IsDomainUser)
	}
}

// Test_CM_UserRead_MetadataNestedObjectRegression guards against a fixed crash
// ("cannot use type json.RawMessage as schema type basetypes.StringType") that
// occurred when CM returned a nested JSON object as a user_metadata value.
func Test_CM_UserRead_MetadataNestedObjectRegression(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintln(w, `{
			"user_id":"user-id-1",
			"username":"testuser",
			"nickname":"nick",
			"email":"testuser@example.com",
			"name":"Test User",
			"is_domain_user":false,
			"login_flags":{"prevent_ui_login":false},
			"password_change_required":false,
			"user_metadata":{"current_domain":{"id":"d1","name":"domain1"},"custom_key":"new_value"}
		}`)
	}))
	defer server.Close()

	client := &common.Client{
		CipherTrustURL: server.URL,
		HTTPClient:     server.Client(),
		Log:            hclog.NewNullLogger(),
	}

	r := &resourceCMUser{client: client}
	ctx := context.Background()

	var schemaResp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}

	initialMetadata := map[string]tftypes.Value{
		"custom_key": tftypes.NewValue(tftypes.String, "old_value"),
	}
	rawState := newCMUserRawState(ctx, schemaResp, false, initialMetadata)

	req := resource.ReadRequest{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    rawState,
		},
	}
	resp := &resource.ReadResponse{
		State: tfsdk.State{
			Schema: schemaResp.Schema,
			Raw:    rawState,
		},
	}

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("regression: user_metadata crash reintroduced: %v", rec)
		}
	}()

	r.Read(ctx, req, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics from Read(): %v", resp.Diagnostics)
	}
}
