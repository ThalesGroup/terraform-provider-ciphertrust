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

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
)

// isNewMapEntry reports whether the map entry containing the attribute at
// attrPath is a brand-new addition -- i.e. the map key itself (not just this
// one field) did not exist in prior state.
//
// This is deliberately NOT the same check as "is req.StateValue for this
// specific attribute null." For a Required attribute, those two questions
// happen to have the same answer (a Required field can only be null in state
// if the containing element never existed). But for an Optional-only field
// (no Computed, no Default), an EXISTING map entry where the user simply
// never set that one field also has a null StateValue for that field --
// indistinguishable from a brand-new map key under a naive check. That false
// positive would let a genuine, plan-time-visible change to an existing
// entry's Optional field skip the replace-protection logic entirely,
// reproducing exactly the kind of silent-no-op-via-generic-PATCH drift this
// package exists to prevent.
//
// To avoid that, this walks up from the field's own path to the map entry's
// path (dropping the field-name step and, for attributes nested inside a
// SingleNestedAttribute such as guard_point_params, the object step above
// it) and checks presence/nullness there instead. A map key that was never
// present in prior state resolves to a null value of the expected type (the
// framework swallows the "no such key" error for this purpose), so this
// reliably distinguishes "brand-new map key" from "existing key, absent
// field value" regardless of whether the field itself is Required or
// Optional.
func isNewMapEntry(ctx context.Context, attrPath path.Path, state tfsdk.State) bool {
	// attrPath is .../<map>/<key>/guard_point_params/<field>. Drop the field
	// name step and the guard_point_params object step to land on the map
	// entry's own path: .../<map>/<key>.
	entryPath := attrPath.ParentPath().ParentPath()

	var entryValue attr.Value
	diags := state.GetAttribute(ctx, entryPath, &entryValue)
	if diags.HasError() || entryValue == nil {
		// Should not happen in practice (a missing map key resolves to a
		// null value of the expected type, not an error), but if it ever
		// did, don't assume "new entry" -- fall back to the conservative
		// choice of treating it as existing, which routes into the
		// replace/immutability protection this package exists to provide
		// rather than silently risking a no-op update.
		return false
	}

	return entryValue.IsNull()
}

// RequiresReplaceUnlessNewMapEntry returns a String plan modifier for an attribute
// nested inside a MapNestedAttribute (e.g. guard_point_type inside a
// map-of-guard-points attribute). It requires a whole-resource replace when the
// value changes for a map element that already existed in prior state (a genuine
// change to an existing entry), but does NOT require replace when the change is
// solely because the containing map element is new.
//
// See isNewMapEntry's doc comment for how "already existed in prior state" is
// determined -- notably, this works correctly for Optional-only fields too,
// not just Required ones.
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

func (m requiresReplaceUnlessNewMapEntryModifier) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
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

	// A brand-new map entry (the guard_path key did not exist in prior
	// state) is created in place by the resource's own Update() logic --
	// never force a whole-resource replace for that.
	if isNewMapEntry(ctx, req.Path, req.State) {
		return
	}

	// The element already existed in prior state and its value has genuinely
	// changed -- protect it the same way the built-in RequiresReplace() would.
	resp.RequiresReplace = true
}

// BoolRequiresReplaceUnlessNewMapEntry is the Bool counterpart of
// RequiresReplaceUnlessNewMapEntry, for boolean attributes nested inside a
// MapNestedAttribute (e.g. automount_enabled, etc. inside a
// map-of-guard-points attribute). See RequiresReplaceUnlessNewMapEntry's doc
// comment for the full rationale; the logic is identical, just typed for Bool.
func BoolRequiresReplaceUnlessNewMapEntry() planmodifier.Bool {
	return boolRequiresReplaceUnlessNewMapEntryModifier{}
}

type boolRequiresReplaceUnlessNewMapEntryModifier struct{}

func (m boolRequiresReplaceUnlessNewMapEntryModifier) Description(_ context.Context) string {
	return "If this value changes for a map entry that already existed, Terraform will destroy and recreate the whole resource. Adding a brand-new map entry (with any value) does not force a replace."
}

func (m boolRequiresReplaceUnlessNewMapEntryModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m boolRequiresReplaceUnlessNewMapEntryModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
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

	// A brand-new map entry (the guard_path key did not exist in prior
	// state) is created in place by the resource's own Update() logic --
	// never force a whole-resource replace for that.
	if isNewMapEntry(ctx, req.Path, req.State) {
		return
	}

	// The element already existed in prior state and its value has genuinely
	// changed -- protect it the same way the built-in RequiresReplace() would.
	resp.RequiresReplace = true
}

// BoolRequiresReplaceOnFalseToTrueUnlessNewMapEntry is a Bool plan modifier for
// attributes nested inside a MapNestedAttribute where CM exposes a dedicated,
// one-directional "turn off" endpoint (e.g. preserve_sparse_regions: CM can turn
// it off in place at any time via a dedicated endpoint, but once off it can
// never be turned back on for that same existing GuardPoint via any API call --
// the only way to get a "true" GuardPoint back is to destroy and recreate it).
//
// Unlike RequiresReplaceUnlessNewMapEntry (which forces replace on ANY genuine
// change to an existing entry), this only forces replace on a false-to-true
// transition for an existing entry. A true-to-false transition for an existing
// entry does NOT force replace -- the resource's own Update() logic is expected
// to call the dedicated "turn off" endpoint for that direction instead.
func BoolRequiresReplaceOnFalseToTrueUnlessNewMapEntry() planmodifier.Bool {
	return boolRequiresReplaceOnFalseToTrueUnlessNewMapEntryModifier{}
}

type boolRequiresReplaceOnFalseToTrueUnlessNewMapEntryModifier struct{}

func (m boolRequiresReplaceOnFalseToTrueUnlessNewMapEntryModifier) Description(_ context.Context) string {
	return "If this value changes from false to true for a map entry that already existed, Terraform will destroy and recreate the whole resource, since this transition cannot be applied in place on an existing entry. A true-to-false change is applied in place. Adding a brand-new map entry (with any value) does not force a replace."
}

func (m boolRequiresReplaceOnFalseToTrueUnlessNewMapEntryModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m boolRequiresReplaceOnFalseToTrueUnlessNewMapEntryModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
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

	// A brand-new map entry is created in place by the resource's own
	// Update() logic -- never force a whole-resource replace for that,
	// regardless of direction.
	if isNewMapEntry(ctx, req.Path, req.State) {
		return
	}

	// Only a false-to-true transition on an existing entry is impossible to
	// apply in place; true-to-false is handled by Update() via the dedicated
	// "turn off" endpoint and must not force a replace here.
	if !req.StateValue.ValueBool() && req.PlanValue.ValueBool() {
		resp.RequiresReplace = true
	}
}
