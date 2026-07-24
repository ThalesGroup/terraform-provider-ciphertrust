// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cckm

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// retainOrDefaultInt64 is a plan modifier for an Optional+Computed Int64 attribute that
// should default to a fixed value on first create, then retain its state value when the
// attribute is removed from config on subsequent updates.
//
// Behaviour:
//   - Config value present: use the configured value (no-op).
//   - Config value absent, state value present (update): retain the state value.
//   - Config value absent, state value absent (create): use the supplied default.
type retainOrDefaultInt64 struct {
	defaultVal int64
}

func (m retainOrDefaultInt64) Description(_ context.Context) string {
	return "Retains the prior state value when the attribute is removed from config; uses the default on first create."
}

func (m retainOrDefaultInt64) MarkdownDescription(_ context.Context) string {
	return "Retains the prior state value when the attribute is removed from config; uses the default on first create."
}

func (m retainOrDefaultInt64) PlanModifyInt64(_ context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// Attribute is explicitly set in config - nothing to do.
	if !req.ConfigValue.IsNull() {
		return
	}
	// Attribute absent from config: retain prior state if available.
	if !req.StateValue.IsNull() && !req.StateValue.IsUnknown() {
		resp.PlanValue = req.StateValue
		return
	}
	// No prior state (first create): apply the default value.
	resp.PlanValue = types.Int64Value(m.defaultVal)
}
