// Package modifiers (this file): RequiresReplaceUnlessNewMapEntry addresses a gap
// in the framework's built-in stringplanmodifier.RequiresReplace() when it is used
// on an attribute nested inside a MapNestedAttribute. The built-in modifier cannot
// distinguish "an existing map element's value actually changed" from "this map
// element is a brand-new addition" -- in both cases req.PlanValue != req.StateValue
// (StateValue is null for a key that never existed in prior state), so the built-in
// modifier requires a whole-resource replace for a pure addition too, even though
// nothing about any existing element changed. RequiresReplaceUnlessNewMapEntry fixes
// this by only requiring replace when the element already existed in prior state.
package modifiers

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
)

// RequiresReplaceUnlessNewMapEntry returns a String plan modifier for an attribute
// nested inside a MapNestedAttribute (e.g. guard_point_type inside a
// map-of-guard-points attribute). It requires a whole-resource replace when the
// value changes for a map element that already existed in prior state (a genuine
// change to an existing entry), but does NOT require replace when the change is
// solely because the containing map element is new -- i.e. req.StateValue is null
// because there was no prior element at this path at all, not because the value
// was legitimately absent.
//
// This relies on the containing attribute being Required (or otherwise guaranteed
// non-null once an element has ever converged): for an element that previously
// existed in state, this attribute's StateValue can only be null if the value was
// never populated, which cannot happen for a Required attribute. So StateValue
// being null here reliably means "brand-new map key," not "existing key with an
// absent value."
//
// Use this instead of stringplanmodifier.RequiresReplace() when the resource's own
// Update() logic already knows how to create brand-new map entries in place
// (so a pure addition must never force a destroy-then-recreate of the whole
// resource), while a genuine change to an existing entry's value still needs
// protecting -- either via this replace, or via the resource's own Update() logic,
// depending on what the resource can safely support. Check the specific resource's
// Update() before relying on this alone to protect existing-entry changes.
func RequiresReplaceUnlessNewMapEntry() planmodifier.String {
	return requiresReplaceUnlessNewMapEntryModifier{}
}

type requiresReplaceUnlessNewMapEntryModifier struct{}

func (m requiresReplaceUnlessNewMapEntryModifier) Description(_ context.Context) string {
	return "If this value changes for a map entry that already existed, Terraform will destroy and recreate the whole resource. Adding a brand-new map entry (with any value) does not force a replace."
}

func (m requiresReplaceUnlessNewMapEntryModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m requiresReplaceUnlessNewMapEntryModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// Do not replace on resource creation (no prior resource state at all).
	if req.State.Raw.IsNull() {
		return
	}

	// Do not replace on resource destroy.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Do not replace if the plan and state values are equal (no change at all).
	if req.PlanValue.Equal(req.StateValue) {
		return
	}

	// StateValue is null here precisely when this containing map element (e.g. the
	// guard_path key) did not exist in prior state -- a brand-new addition. Do not
	// force a whole-resource replace for that; let the resource's own Update()
	// logic create the new entry in place.
	if req.StateValue.IsNull() {
		return
	}

	// The element already existed in prior state and its value has genuinely
	// changed -- protect it the same way the built-in RequiresReplace() would.
	resp.RequiresReplace = true
}
