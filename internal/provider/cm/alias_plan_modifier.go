package cm

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// aliasListIndexModifier fixes up the Computed `index` field of each entry in the
// top-level `aliases` ListNestedAttribute. Terraform's built-in list-element
// correlation is positional, but CM's aliases are identified by `alias` name — so
// stringplanmodifier.UseStateForUnknown() on the per-item `index` field is wrong:
// for a genuinely new alias appended to an existing list, there's no state element
// at that position, and the built-in modifier overwrites the correctly-computed
// Unknown with a null placeholder, causing a "Provider produced inconsistent result
// after apply" crash once Update() assigns a real index.
//
// This modifier instead matches plan aliases to state aliases by `alias` name
// (same correlation Update() already uses) and explicitly sets `index`: the
// matched state value for an existing alias (regardless of position — this also
// fixes index-scrambling on pure reorders), or Unknown for a genuinely new one.
type aliasListIndexModifier struct{}

func (m aliasListIndexModifier) Description(_ context.Context) string {
	return "Correlates aliases by name (not position) so a new alias's index is left Unknown rather than incorrectly null."
}

func (m aliasListIndexModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (m aliasListIndexModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.State.Raw.IsNull() {
		return // brand-new resource — nothing to correlate against
	}
	if req.PlanValue.IsNull() || req.PlanValue.IsUnknown() {
		return
	}

	var stateAliases []KeyAliasTFSDK
	if diags := req.StateValue.ElementsAs(ctx, &stateAliases, false); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	var planAliases []KeyAliasTFSDK
	if diags := req.PlanValue.ElementsAs(ctx, &planAliases, false); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if len(planAliases) == 0 {
		return
	}

	stateIndexByName := make(map[string]types.String, len(stateAliases))
	for _, sa := range stateAliases {
		stateIndexByName[sa.Alias.ValueString()] = sa.Index
	}

	for i := range planAliases {
		if idx, ok := stateIndexByName[planAliases[i].Alias.ValueString()]; ok {
			planAliases[i].Index = idx
		} else {
			planAliases[i].Index = types.StringUnknown()
		}
	}

	newList, diags := types.ListValueFrom(ctx, req.PlanValue.ElementType(ctx), planAliases)
	resp.Diagnostics.Append(diags...)
	if diags.HasError() {
		return
	}
	resp.PlanValue = newList
}
