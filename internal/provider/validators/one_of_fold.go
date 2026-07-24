// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package validators

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// OneOfFold returns a String validator that checks the configured value
// against a set of allowed values, ignoring case. Use this instead of
// stringvalidator.OneOf when CipherTrust Manager itself normalizes the
// value's case before comparing (e.g. auth_method/protocol on
// ciphertrust_scp_connection), so a differently-cased value that CM would
// accept isn't rejected at plan time.
func OneOfFold(values ...string) validator.String {
	return oneOfFoldValidator{values: values}
}

type oneOfFoldValidator struct {
	values []string
}

func (v oneOfFoldValidator) Description(_ context.Context) string {
	return fmt.Sprintf("value must be one of: %s (case-insensitive)", strings.Join(v.values, ", "))
}

func (v oneOfFoldValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v oneOfFoldValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	value := req.ConfigValue.ValueString()
	for _, allowed := range v.values {
		if strings.EqualFold(value, allowed) {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(
		req.Path,
		"Invalid Attribute Value",
		fmt.Sprintf("value must be one of: %s (case-insensitive), got: %q", strings.Join(v.values, ", "), value),
	)
}
