// Package modifiers provides shared Terraform plan modifiers for the
// CipherTrust provider. ImmutableString, ImmutableInt64, ImmutableBool,
// ImmutableList, ImmutableMap, and ImmutableObject each enforce that a
// given schema attribute cannot change after resource creation, emitting
// a plan-time diagnostic error so no API call is made and no
// destroy+recreate occurs. MergePatchObject is looser: it allows in-place
// changes/additions to an object attribute and only blocks clearing a
// previously-set field by omitting it, matching CM's JSON merge-PATCH
// endpoints where omitted keys are left untouched rather than cleared.
package modifiers

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ImmutableString returns a plan modifier that prevents a string attribute from
// changing after the resource is created. A plan-time diagnostic error is emitted
// if the value differs from state, preventing destroy+recreate.
func ImmutableString() planmodifier.String {
	return immutableStringModifier{}
}

type immutableStringModifier struct{}

func (m immutableStringModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableStringModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableStringModifier) PlanModifyString(_ context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	// If the full prior resource state is null, this is a brand-new resource being
	// created for the first time — allow any value. We use req.State.Raw.IsNull()
	// rather than req.StateValue.IsNull() so that we correctly reject the case where
	// an Optional field was omitted on create (StateValue is null but State is not —
	// i.e. the resource already exists) and the user tries to add it on a subsequent
	// plan, which must be blocked as an immutable change.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroy plan: the resource is being torn down, not updated. Config may have
	// drifted from state on this immutable field, but destroy never applies planned
	// attribute values — blocking it here would prevent legitimate teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	// Guard against null or unknown PlanValue — covers framework-internal null-plan
	// phases and any future scenario where Read() nullifies state before a plan.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		fmt.Sprintf(
			"This attribute cannot be changed after creation (old: %q, new: %q). "+
				"To change this attribute, destroy and recreate the resource.",
			req.StateValue.ValueString(),
			req.PlanValue.ValueString(),
		),
	)
	resp.PlanValue = req.StateValue
}

// ImmutableInt64 returns a plan modifier that prevents an int64 attribute from
// changing after the resource is created.
func ImmutableInt64() planmodifier.Int64 {
	return immutableInt64Modifier{}
}

type immutableInt64Modifier struct{}

func (m immutableInt64Modifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableInt64Modifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableInt64Modifier) PlanModifyInt64(_ context.Context, req planmodifier.Int64Request, resp *planmodifier.Int64Response) {
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroy plan — do not block teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	// Allow plan values that are null or unknown (e.g., Optional field removed from config
	// with no default, or value not yet known). The framework will resolve these; do not
	// block them here.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	// No change — allow.
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		fmt.Sprintf(
			"This attribute cannot be changed after creation (old: %d, new: %d). "+
				"To change this attribute, destroy and recreate the resource.",
			req.StateValue.ValueInt64(),
			req.PlanValue.ValueInt64(),
		),
	)
	resp.PlanValue = req.StateValue
}

// ImmutableBool returns a plan modifier that prevents a bool attribute from
// changing after the resource is created.
func ImmutableBool() planmodifier.Bool {
	return immutableBoolModifier{}
}

type immutableBoolModifier struct{}

func (m immutableBoolModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableBoolModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableBoolModifier) PlanModifyBool(_ context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroy plan — do not block teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	// When an Optional+Computed bool is omitted from config, the framework sets
	// the plan value to Unknown before UseStateForUnknown resolves it. Allow
	// null/unknown plan values so that only an explicit user-supplied change fires
	// the immutability error.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		fmt.Sprintf(
			"This attribute cannot be changed after creation (old: %v, new: %v). "+
				"To change this attribute, destroy and recreate the resource.",
			req.StateValue.ValueBool(),
			req.PlanValue.ValueBool(),
		),
	)
	resp.PlanValue = req.StateValue
}

// ImmutableList returns a plan modifier that prevents a list attribute from
// changing after the resource is created.
func ImmutableList() planmodifier.List {
	return immutableListModifier{}
}

type immutableListModifier struct{}

func (m immutableListModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableListModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableListModifier) PlanModifyList(_ context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroy plan — do not block teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		"This list attribute cannot be changed after creation. "+
			"To change this attribute, destroy and recreate the resource.",
	)
	resp.PlanValue = req.StateValue
}

// ImmutableMap returns a Map plan modifier that prevents in-place changes
// to a map attribute after resource creation. Any attempt to change the
// value after creation results in a plan-time error directing the user to
// destroy and recreate the resource.
func ImmutableMap() planmodifier.Map {
	return immutableMapModifier{}
}

type immutableMapModifier struct{}

func (m immutableMapModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableMapModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableMapModifier) PlanModifyMap(_ context.Context, req planmodifier.MapRequest, resp *planmodifier.MapResponse) {
	// Brand-new resource: no prior resource state — allow any value.
	if req.State.Raw.IsNull() {
		return
	}
	// Destroy plan — do not block teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	// Guard against null or unknown PlanValue — covers framework-internal null-plan
	// phases and any future scenario where Read() nullifies state before a plan.
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		"This map attribute cannot be changed after creation. "+
			"To change this attribute, destroy and recreate the resource.",
	)
	resp.PlanValue = req.StateValue
}

// ImmutableObject returns an Object plan modifier that prevents in-place changes
// to an object attribute after resource creation.
func ImmutableObject() planmodifier.Object {
	return immutableObjectModifier{}
}

type immutableObjectModifier struct{}

func (m immutableObjectModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

func (m immutableObjectModifier) MarkdownDescription(_ context.Context) string {
	return "Attribute is immutable after resource creation."
}

// PlanModifyObject fires an error when a non-null state value is changed.
// The IsUnknown() early-return prevents false errors when plan sub-attributes
// are Unknown (e.g. populated by UseStateForUnknown() on nested attributes).
func (m immutableObjectModifier) PlanModifyObject(_ context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	// Destroy plan — do not block teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	if req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.IsUnknown() {
		return
	}
	if req.PlanValue.Equal(req.StateValue) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		"This object attribute cannot be changed after creation. "+
			"To change this attribute, destroy and recreate the resource.",
	)
	resp.PlanValue = req.StateValue
}

// ImmutableObjectExceptWriteOnly returns an Object plan modifier that behaves like
// ImmutableObject, but ignores the named child attributes when computing equality.
// Use this when an otherwise-immutable nested object contains a WriteOnly child:
// WriteOnly attribute values are always null in state (the framework nullifies them on
// the way out), but PlanModifyObject runs before that nullification, so req.PlanValue
// still carries the real configured value for the write-only child. Comparing the whole
// object directly (as ImmutableObject does) would then always find a "difference" purely
// from that field and misfire an immutability error on every subsequent plan — the same
// class of bug fixed for a bare WriteOnly string attribute by removing ImmutableString()
// in commit d3c9e26. Excluding the named children from the comparison keeps immutability
// enforcement on the object's other fields while letting the write-only fields vary
// freely (their own value can never be diffed against a prior value anyway).
func ImmutableObjectExceptWriteOnly(writeOnlyChildren ...string) planmodifier.Object {
	return immutableObjectExceptWriteOnlyModifier{writeOnlyChildren: writeOnlyChildren}
}

type immutableObjectExceptWriteOnlyModifier struct {
	writeOnlyChildren []string
}

func (m immutableObjectExceptWriteOnlyModifier) Description(_ context.Context) string {
	return "Attribute is immutable after resource creation, except for write-only child attributes."
}

func (m immutableObjectExceptWriteOnlyModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m immutableObjectExceptWriteOnlyModifier) PlanModifyObject(_ context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	// Destroy plan — do not block teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	if req.StateValue.IsNull() {
		return
	}
	if req.PlanValue.IsUnknown() {
		return
	}
	if objectsEqualIgnoring(req.PlanValue, req.StateValue, m.writeOnlyChildren) {
		return
	}
	resp.Diagnostics.AddError(
		"Attribute is immutable",
		"This object attribute cannot be changed after creation. "+
			"To change this attribute, destroy and recreate the resource.",
	)
	resp.PlanValue = req.StateValue
}

// objectsEqualIgnoring reports whether two Object values are equal, ignoring the named
// child attribute names entirely (neither their presence nor their values affect the
// result).
func objectsEqualIgnoring(a, b types.Object, ignore []string) bool {
	if a.IsNull() != b.IsNull() || a.IsUnknown() != b.IsUnknown() {
		return false
	}
	skip := make(map[string]bool, len(ignore))
	for _, name := range ignore {
		skip[name] = true
	}
	aAttrs, bAttrs := a.Attributes(), b.Attributes()
	for name, aVal := range aAttrs {
		if skip[name] {
			continue
		}
		bVal, ok := bAttrs[name]
		if !ok || !aVal.Equal(bVal) {
			return false
		}
	}
	for name := range bAttrs {
		if skip[name] {
			continue
		}
		if _, ok := aAttrs[name]; !ok {
			return false
		}
	}
	return true
}

// MergePatchObject returns an Object plan modifier for attributes backed by a CM endpoint
// that uses JSON merge-PATCH semantics: a key present in the PATCH body is set/replaced
// in place, but a key absent from the body leaves the server's existing value untouched.
// This means adding or changing a (sub-)field works fine in place, but clearing a
// previously-set field by omitting it from config can never converge — Read() will keep
// re-hydrating the stale server value forever. MergePatchObject allows the former and
// blocks the latter with a plan-time error, checked recursively through nested objects.
func MergePatchObject() planmodifier.Object {
	return mergePatchObjectModifier{}
}

type mergePatchObjectModifier struct{}

func (m mergePatchObjectModifier) Description(_ context.Context) string {
	return "Fields already set cannot be cleared by omitting them (CM merge-PATCH); changing or adding fields is allowed."
}

func (m mergePatchObjectModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m mergePatchObjectModifier) PlanModifyObject(_ context.Context, req planmodifier.ObjectRequest, resp *planmodifier.ObjectResponse) {
	// Destroy plan — do not block teardown (TFIN-552).
	if req.Plan.Raw.IsNull() {
		return
	}
	if req.StateValue.IsNull() {
		return // create path
	}
	if req.PlanValue.IsUnknown() {
		return
	}
	cleared := clearedMergePatchFields(req.PathExpression.String(), req.StateValue, req.PlanValue)
	if len(cleared) == 0 {
		return
	}
	sort.Strings(cleared)
	resp.Diagnostics.AddError(
		"Cannot Clear Field After Creation",
		fmt.Sprintf(
			"The following field(s) were set and cannot be removed by omitting them from "+
				"config: %s. CM's merge-PATCH leaves omitted fields unchanged on the server, "+
				"so removing them here would never converge. Restore the previous value, or "+
				"destroy and recreate the resource.",
			strings.Join(cleared, ", "),
		),
	)
	resp.PlanValue = req.StateValue
}

// clearedMergePatchFields recursively finds attribute paths that were non-null in state
// and are null (entirely absent) in plan. It does not descend into non-Object values
// (lists, primitives) — a changed or shrunk list/value is a legitimate in-place update
// under JSON merge-patch semantics, since a *present* key is fully replaced, not merged.
func clearedMergePatchFields(path string, stateVal, planVal attr.Value) []string {
	if stateVal == nil || stateVal.IsNull() {
		return nil
	}
	if planVal == nil || planVal.IsNull() {
		return []string{path}
	}
	if planVal.IsUnknown() {
		return nil
	}
	stateObj, ok := stateVal.(types.Object)
	if !ok {
		return nil
	}
	planObj, ok := planVal.(types.Object)
	if !ok {
		return nil
	}
	var cleared []string
	for name, sAttr := range stateObj.Attributes() {
		pAttr, exists := planObj.Attributes()[name]
		if !exists {
			cleared = append(cleared, path+"."+name)
			continue
		}
		cleared = append(cleared, clearedMergePatchFields(path+"."+name, sAttr, pAttr)...)
	}
	return cleared
}
