// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// Test_CM_Unit_DataSourceUsers_PasswordIsSensitive verifies that the nested
// password attribute in ciphertrust_cm_users_list is marked Sensitive so it
// is redacted from plan/show/state output.
func Test_CM_Unit_DataSourceUsers_PasswordIsSensitive(t *testing.T) {
	var schemaResp datasource.SchemaResponse
	(&dataSourceUsers{}).Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)

	usersAttr, ok := schemaResp.Schema.Attributes["users"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("expected users attribute to be schema.ListNestedAttribute, got %T", schemaResp.Schema.Attributes["users"])
	}

	passwordAttr, ok := usersAttr.NestedObject.Attributes["password"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected password attribute to be schema.StringAttribute, got %T", usersAttr.NestedObject.Attributes["password"])
	}

	if !passwordAttr.Sensitive {
		t.Error("expected users[].password attribute to be marked Sensitive")
	}
}
