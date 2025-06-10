package cckm

import (
	"context"
	"encoding/json"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

func getFreeformTagsFromPlan(ctx context.Context, planTags *types.Map, diags *diag.Diagnostics) map[string]string {
	tags := make(map[string]string, len(planTags.Elements()))
	if len(planTags.Elements()) == 0 {
		return tags
	}
	diags.Append(planTags.ElementsAs(ctx, &tags, false)...)
	if diags.HasError() {
		return nil
	}
	return tags
}

func getFreeformTagsFromJSON(ctx context.Context, tagsJSON gjson.Result, diags *diag.Diagnostics) map[string]string {
	tags := make(map[string]string)
	if len(tagsJSON.String()) > 0 {
		err := json.Unmarshal([]byte(tagsJSON.Raw), &tags)
		if err != nil {
			msg := "Error parsing 'freeform_tags', invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "tags": tagsJSON.String()})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return nil
		}
	}
	return tags
}

func setFreeformTagsState(ctx context.Context, tags map[string]string, state *types.Map, diags *diag.Diagnostics) {
	tfMapValue, dg := types.MapValueFrom(ctx, types.StringType, tags)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*state = tfMapValue
}

func getDefinedTagsFromPlan(ctx context.Context, planTags *types.Set, diags *diag.Diagnostics) map[string]map[string]string {
	definedTags := make(map[string]map[string]string)
	if len(planTags.Elements()) == 0 {
		return definedTags
	}
	planParams := make([]models.DefinedTagTFSDK, 0, len(planTags.Elements()))
	dg := planTags.ElementsAs(ctx, &planParams, false)
	if dg.HasError() {
		diags.Append(dg...)
		return nil
	}
	for _, df := range planParams {
		values := make(map[string]string, len(df.Values.Elements()))
		if len(planTags.Elements()) == 0 {
			continue
		}
		diags.Append(df.Values.ElementsAs(ctx, &values, false)...)
		if diags.HasError() {
			return nil
		}
		definedTags[df.Tag.ValueString()] = values
	}
	return definedTags
}

func getDefinedTagsFromJSON(ctx context.Context, tagsJSON gjson.Result, diags *diag.Diagnostics) map[string]map[string]string {
	tags := make(map[string]map[string]string)
	if len(tagsJSON.String()) > 0 {
		err := json.Unmarshal([]byte(tagsJSON.Raw), &tags)
		if err != nil {
			msg := "Error parsing 'defined_tags', invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "tags": tagsJSON.String()})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return nil
		}
	}
	return tags
}

func setDefinedTagsState(ctx context.Context, tags map[string]map[string]string, state *types.Set, diags *diag.Diagnostics) {
	var definedTagsTFSDK []models.DefinedTagTFSDK
	for namespace, valueMap := range tags {
		tfMapValue, dg := types.MapValueFrom(ctx, types.StringType, valueMap)
		if dg.HasError() {
			diags.Append(dg...)
			return
		}
		definedTagTFSDK := models.DefinedTagTFSDK{
			Tag:    types.StringValue(namespace),
			Values: tfMapValue,
		}
		definedTagsTFSDK = append(definedTagsTFSDK, definedTagTFSDK)
	}
	tfSetValue, dg := types.SetValueFrom(ctx,
		types.ObjectType{AttrTypes: models.DefinedTagAttribs}, definedTagsTFSDK)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	tagSet, dg := tfSetValue.ToSetValue(ctx)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*state = tagSet
}
