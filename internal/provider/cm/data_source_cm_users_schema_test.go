package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
)

// Test_CM_UsersSchema_PasswordSensitive verifies that the nested password
// attribute in ciphertrust_cm_users_list schema is marked Sensitive: true
// and marked as deprecated/unpopulated.
func Test_CM_UsersSchema_PasswordSensitive(t *testing.T) {
	var resp datasource.SchemaResponse
	(&dataSourceUsers{}).Schema(context.Background(), datasource.SchemaRequest{}, &resp)

	usersAttr, ok := resp.Schema.Attributes["users"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("expected users attribute to be schema.ListNestedAttribute, got %T", resp.Schema.Attributes["users"])
	}

	passwordAttr, ok := usersAttr.NestedObject.Attributes["password"].(schema.StringAttribute)
	if !ok {
		t.Fatalf("expected password attribute to be schema.StringAttribute, got %T", usersAttr.NestedObject.Attributes["password"])
	}

	if !passwordAttr.Sensitive {
		t.Error("expected users[].password schema attribute to be marked Sensitive: true")
	}
}
