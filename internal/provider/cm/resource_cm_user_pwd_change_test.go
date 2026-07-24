// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func Test_CM_PwdChangeSchema_PasswordsAreSensitive(t *testing.T) {
	r := &resourceCMPwdChange{}
	ctx := context.Background()
	var resp resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &resp)

	for _, attrName := range []string{"password", "new_password"} {
		attr, ok := resp.Schema.Attributes[attrName]
		if !ok {
			t.Fatalf("attribute %q was not found in ciphertrust_cm_user_password_change schema", attrName)
		}

		strAttr, ok := attr.(schema.StringAttribute)
		if !ok {
			t.Fatalf("attribute %q is not a StringAttribute", attrName)
		}

		if !strAttr.Sensitive {
			t.Errorf("security regression: attribute %q is not marked as Sensitive: true", attrName)
		}
	}
}
