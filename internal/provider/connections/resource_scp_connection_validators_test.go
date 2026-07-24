// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package connections

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// int64ValidatorsAttribute is satisfied by schema.Int64Attribute; used to pull
// the configured Validators back out of the built schema without depending on
// the concrete attribute struct.
type int64ValidatorsAttribute interface {
	Int64Validators() []validator.Int64
}

// listValidatorsAttribute is satisfied by schema.ListAttribute; used to pull
// the configured Validators back out of the built schema without depending on
// the concrete attribute struct.
type listValidatorsAttribute interface {
	ListValidators() []validator.List
}

func scpConnectionSchema(t *testing.T) map[string]schemaAttribute {
	t.Helper()
	ctx := context.Background()
	var schemaResp resource.SchemaResponse
	(&resourceCMScpConnection{}).Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	if schemaResp.Diagnostics.HasError() {
		t.Fatalf("unexpected diagnostics building schema: %v", schemaResp.Diagnostics)
	}
	attrs := make(map[string]schemaAttribute, len(schemaResp.Schema.Attributes))
	for name, a := range schemaResp.Schema.Attributes {
		attrs[name] = a
	}
	return attrs
}

// schemaAttribute is the minimal interface satisfied by every entry in
// resource.Schema.Attributes; used only to store attributes of differing
// concrete types (StringAttribute, Int64Attribute, ListAttribute) in one map.
type schemaAttribute interface{}

func runStringValidators(t *testing.T, attrs map[string]schemaAttribute, field string, value types.String) diag.Diagnostics {
	t.Helper()
	attr, ok := attrs[field]
	if !ok {
		t.Fatalf("%s attribute not found in schema", field)
	}
	withValidators, ok := attr.(stringValidatorsAttribute)
	if !ok {
		t.Fatalf("%s attribute (%T) does not expose StringValidators", field, attr)
	}
	validators := withValidators.StringValidators()
	if len(validators) == 0 {
		t.Fatalf("%s has no validators", field)
	}
	ctx := context.Background()
	var diags diag.Diagnostics
	for _, v := range validators {
		req := validator.StringRequest{Path: path.Root(field), ConfigValue: value}
		var resp validator.StringResponse
		v.ValidateString(ctx, req, &resp)
		diags.Append(resp.Diagnostics...)
	}
	return diags
}

func runInt64Validators(t *testing.T, attrs map[string]schemaAttribute, field string, value types.Int64) diag.Diagnostics {
	t.Helper()
	attr, ok := attrs[field]
	if !ok {
		t.Fatalf("%s attribute not found in schema", field)
	}
	withValidators, ok := attr.(int64ValidatorsAttribute)
	if !ok {
		t.Fatalf("%s attribute (%T) does not expose Int64Validators", field, attr)
	}
	validators := withValidators.Int64Validators()
	if len(validators) == 0 {
		t.Fatalf("%s has no validators", field)
	}
	ctx := context.Background()
	var diags diag.Diagnostics
	for _, v := range validators {
		req := validator.Int64Request{Path: path.Root(field), ConfigValue: value}
		var resp validator.Int64Response
		v.ValidateInt64(ctx, req, &resp)
		diags.Append(resp.Diagnostics...)
	}
	return diags
}

func runListValidators(t *testing.T, attrs map[string]schemaAttribute, field string, value types.List) diag.Diagnostics {
	t.Helper()
	attr, ok := attrs[field]
	if !ok {
		t.Fatalf("%s attribute not found in schema", field)
	}
	withValidators, ok := attr.(listValidatorsAttribute)
	if !ok {
		t.Fatalf("%s attribute (%T) does not expose ListValidators", field, attr)
	}
	validators := withValidators.ListValidators()
	if len(validators) == 0 {
		t.Fatalf("%s has no validators", field)
	}
	ctx := context.Background()
	var diags diag.Diagnostics
	for _, v := range validators {
		req := validator.ListRequest{Path: path.Root(field), ConfigValue: value}
		var resp validator.ListResponse
		v.ValidateList(ctx, req, &resp)
		diags.Append(resp.Diagnostics...)
	}
	return diags
}

// Test_CM_ScpConnection_AuthMethodValidator verifies auth_method accepts only
// "key"/"password" (matching CM's own case-insensitive check in
// citrus/scp_connections.go), so a config like "certificate" is now rejected
// at plan time instead of surfacing a 400 only at apply.
func Test_CM_ScpConnection_AuthMethodValidator(t *testing.T) {
	attrs := scpConnectionSchema(t)

	for _, valid := range []string{"key", "password", "Password", "KEY"} {
		t.Run("accepts \""+valid+"\"", func(t *testing.T) {
			if diags := runStringValidators(t, attrs, "auth_method", types.StringValue(valid)); diags.HasError() {
				t.Errorf("unexpected error for %q: %v", valid, diags)
			}
		})
	}
	t.Run("rejects an unsupported method", func(t *testing.T) {
		if diags := runStringValidators(t, attrs, "auth_method", types.StringValue("certificate")); !diags.HasError() {
			t.Error("expected an error for \"certificate\", got none")
		}
	})
}

// Test_CM_ScpConnection_ProtocolValidator verifies protocol accepts only
// "sftp"/"scp" (matching validateFileTransferProtocol in
// citrus/scp_connections.go), case-insensitively.
func Test_CM_ScpConnection_ProtocolValidator(t *testing.T) {
	attrs := scpConnectionSchema(t)

	for _, valid := range []string{"sftp", "scp", "SFTP"} {
		t.Run("accepts \""+valid+"\"", func(t *testing.T) {
			if diags := runStringValidators(t, attrs, "protocol", types.StringValue(valid)); diags.HasError() {
				t.Errorf("unexpected error for %q: %v", valid, diags)
			}
		})
	}
	t.Run("rejects an unsupported protocol", func(t *testing.T) {
		if diags := runStringValidators(t, attrs, "protocol", types.StringValue("ftp")); !diags.HasError() {
			t.Error("expected an error for \"ftp\", got none")
		}
	})
	t.Run("unset (null) config value is left to Optional+Computed defaulting", func(t *testing.T) {
		if diags := runStringValidators(t, attrs, "protocol", types.StringNull()); diags.HasError() {
			t.Errorf("unexpected error for a null config value: %v", diags)
		}
	})
}

// Test_CM_ScpConnection_NonEmptyStringFields verifies host, username, and
// public_key reject an empty string at plan time instead of only failing the
// apply-time CM REST call.
func Test_CM_ScpConnection_NonEmptyStringFields(t *testing.T) {
	attrs := scpConnectionSchema(t)

	for _, field := range []string{"host", "username", "public_key"} {
		t.Run(field+" rejects empty string", func(t *testing.T) {
			if diags := runStringValidators(t, attrs, field, types.StringValue("")); !diags.HasError() {
				t.Errorf("expected an error for empty %s, got none", field)
			}
		})
		t.Run(field+" accepts a real value", func(t *testing.T) {
			if diags := runStringValidators(t, attrs, field, types.StringValue("a-real-value")); diags.HasError() {
				t.Errorf("unexpected error for %s: %v", field, diags)
			}
		})
	}
}

// Test_CM_ScpConnection_PortRangeValidator verifies port is restricted to the
// valid TCP range (matching validatePort in citrus/utils.go: 1-65535).
func Test_CM_ScpConnection_PortRangeValidator(t *testing.T) {
	attrs := scpConnectionSchema(t)

	for _, valid := range []int64{1, 22, 65535} {
		t.Run("accepts a valid port", func(t *testing.T) {
			if diags := runInt64Validators(t, attrs, "port", types.Int64Value(valid)); diags.HasError() {
				t.Errorf("unexpected error for port %d: %v", valid, diags)
			}
		})
	}
	for _, invalid := range []int64{-1, 0, 65536, 99999} {
		t.Run("rejects an out-of-range port", func(t *testing.T) {
			if diags := runInt64Validators(t, attrs, "port", types.Int64Value(invalid)); !diags.HasError() {
				t.Errorf("expected an error for port %d, got none", invalid)
			}
		})
	}
	t.Run("unset (null) config value is left to Optional+Computed defaulting", func(t *testing.T) {
		if diags := runInt64Validators(t, attrs, "port", types.Int64Null()); diags.HasError() {
			t.Errorf("unexpected error for a null config value: %v", diags)
		}
	})
}

// Test_CM_ScpConnection_ProductsValidator verifies each element of products is
// restricted to CM's documented product enum (matching resource_aws_connection.go's
// existing pattern), and that an empty list remains valid since CM's own
// validateProducts short-circuits on an empty slice.
func Test_CM_ScpConnection_ProductsValidator(t *testing.T) {
	attrs := scpConnectionSchema(t)
	ctx := context.Background()

	listOf := func(t *testing.T, values ...string) types.List {
		t.Helper()
		elems := make([]types.String, len(values))
		for i, v := range values {
			elems[i] = types.StringValue(v)
		}
		l, diags := types.ListValueFrom(ctx, types.StringType, elems)
		if diags.HasError() {
			t.Fatalf("unexpected error building test list: %v", diags)
		}
		return l
	}

	t.Run("accepts the documented backup/restore value", func(t *testing.T) {
		if diags := runListValidators(t, attrs, "products", listOf(t, "backup/restore")); diags.HasError() {
			t.Errorf("unexpected error: %v", diags)
		}
	})
	t.Run("rejects an unsupported product", func(t *testing.T) {
		if diags := runListValidators(t, attrs, "products", listOf(t, "invalid_product")); !diags.HasError() {
			t.Error("expected an error for \"invalid_product\", got none")
		}
	})
	t.Run("accepts an empty list", func(t *testing.T) {
		if diags := runListValidators(t, attrs, "products", listOf(t)); diags.HasError() {
			t.Errorf("unexpected error for an empty products list: %v", diags)
		}
	})
}
