package cckm

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

// setNativeAndByokKeyCommonState populates the top-level Terraform state fields shared by
// the aws_key and aws_byok_key resources. It writes into AWSNativeAndByokKeyCommonTFSDK.
func setNativeAndByokKeyCommonState(ctx context.Context, client *common.Client, response string, state *AWSNativeAndByokKeyCommonTFSDK, diags *diag.Diagnostics) {
	keyID := gjson.Get(response, "id").String()
	state.EnableKey = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.ExternalAccounts = utils.StringSliceJSONToSetValue(gjson.Get(response, "external_accounts").Array(), diags)
	state.KeyAdmins = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins").Array(), diags)
	state.KeyAdminsRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins_roles").Array(), diags)
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	state.KeySource = types.StringValue(gjson.Get(response, "key_source").String())
	state.KeyType = types.StringValue(gjson.Get(response, "key_type").String())
	state.KeyUsers = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users").Array(), diags)
	state.KeyUsersRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users_roles").Array(), diags)
	state.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	state.KMSName = types.StringValue(gjson.Get(response, "kms").String())
	setKeyLabels(ctx, client, response, keyID, &state.Labels, diags)
	state.Region = types.StringValue(gjson.Get(response, "region").String())
	state.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	state.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_from").String())
	state.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	state.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
}

// setKeyStoreResourceCommonTopLevel sets all top-level fields on AWSKeyStoreResourceCommonTFSDK
// from the API response JSON. Fields sourced from the aws_param block (arn, key_id, etc.) are
// NOT set here; they are set by the caller inside the aws_param nested object.
func setKeyStoreResourceCommonTopLevel(ctx context.Context, client *common.Client, response string, state *AWSKeyStoreResourceCommonTFSDK, diags *diag.Diagnostics) {
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.ExternalAccounts = utils.StringSliceJSONToSetValue(gjson.Get(response, "external_accounts").Array(), diags)
	state.KeyAdmins = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins").Array(), diags)
	state.KeyAdminsRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins_roles").Array(), diags)
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	state.KeySource = types.StringValue(gjson.Get(response, "key_source").String())
	state.KeyType = types.StringValue(gjson.Get(response, "key_type").String())
	state.KeyUsers = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users").Array(), diags)
	state.KeyUsersRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users_roles").Array(), diags)
	state.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	state.KMSName = types.StringValue(gjson.Get(response, "kms").String())
	setKeyLabels(ctx, client, response, state.ID.ValueString(), &state.Labels, diags)
	state.Region = types.StringValue(gjson.Get(response, "region").String())
	state.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	state.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_from").String())
	state.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	state.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.CustomKeyStoreID = types.StringValue(gjson.Get(response, "custom_key_store_id").String())
	state.KeySourceContainerID = types.StringValue(gjson.Get(response, "key_source_container_id").String())
	state.KeySourceContainerName = types.StringValue(gjson.Get(response, "key_source_container_name").String())
	state.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	state.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	state.Linked = types.BoolValue(gjson.Get(response, "linked_state").Bool())
	state.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())
}

// setKeyLabels parses the CipherTrust Manager labels from the API response and stores them in Terraform state.
func setKeyLabels(ctx context.Context, client *common.Client, response string, keyID string, stateLabels *types.Map, diags *diag.Diagnostics) {
	labels := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			msg := "Error setting state for key labels, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
	}
	labelMap, d := types.MapValueFrom(ctx, types.StringType, labels)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateLabels = labelMap
}

// multiRegionKeyAttrTypes defines the attr types for a single ARN/region entry
// used in multi_region_configuration.primary_key and multi_region_configuration.replica_keys.
var multiRegionKeyAttrTypes = map[string]attr.Type{
	"arn":    types.StringType,
	"region": types.StringType,
}

// multiRegionConfigAttrTypes defines the attr types for the multi_region_configuration object.
// All callers that need to construct a null or unknown object must use this map so that
// the Framework type system is satisfied.
var multiRegionConfigAttrTypes = map[string]attr.Type{
	"multi_region_key_type": types.StringType,
	"primary_key":           types.ObjectType{AttrTypes: multiRegionKeyAttrTypes},
	"replica_keys":          types.SetType{ElemType: types.ObjectType{AttrTypes: multiRegionKeyAttrTypes}},
}

// setMultiRegionConfig builds a types.Object representing multi_region_configuration
// from the API response JSON. Returns a null Object when the key is not a multi-region key.
// Any type-construction errors are appended to diags so callers can surface them.
// Used by resourceAWSKey, resourceAWSByokKey, resourceAWSKeyForImportMaterial, and the aws_key data source.
func setMultiRegionConfig(keyJSON string, diags *diag.Diagnostics) types.Object {
	if !gjson.Get(keyJSON, "aws_param.MultiRegion").Bool() {
		return types.ObjectNull(multiRegionConfigAttrTypes)
	}

	// Build primary_key object.
	primaryKeyObj, d := types.ObjectValue(multiRegionKeyAttrTypes, map[string]attr.Value{
		"arn":    types.StringValue(gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()),
		"region": types.StringValue(gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()),
	})
	if d.HasError() {
		diags.Append(d...)
		return types.ObjectNull(multiRegionConfigAttrTypes)
	}

	// Build replica_keys list.
	replicaElemType := types.ObjectType{AttrTypes: multiRegionKeyAttrTypes}
	replicaElems := make([]attr.Value, 0)
	for _, r := range gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array() {
		replicaObj, rd := types.ObjectValue(multiRegionKeyAttrTypes, map[string]attr.Value{
			"arn":    types.StringValue(r.Get("Arn").String()),
			"region": types.StringValue(r.Get("Region").String()),
		})
		if rd.HasError() {
			diags.Append(rd...)
			return types.ObjectNull(multiRegionConfigAttrTypes)
		}
		replicaElems = append(replicaElems, replicaObj)
	}
	replicaList, d := types.SetValue(replicaElemType, replicaElems)
	if d.HasError() {
		diags.Append(d...)
		return types.ObjectNull(multiRegionConfigAttrTypes)
	}

	cfgObj, d := types.ObjectValue(multiRegionConfigAttrTypes, map[string]attr.Value{
		"multi_region_key_type": types.StringValue(gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String()),
		"primary_key":           primaryKeyObj,
		"replica_keys":          replicaList,
	})
	if d.HasError() {
		diags.Append(d...)
		return types.ObjectNull(multiRegionConfigAttrTypes)
	}
	return cfgObj
}

// setKeyTags populates the user-managed tags in state from the AWS response.
// If stateTags already contains a known set of keys (from the plan or prior state), only response
// tags whose keys are present in stateTags are stored. This prevents AWS-policy-added tags (e.g.
// an organisation-wide "owner" tag) from causing "inconsistent result after apply" errors when
// those tags are not in the Terraform config. On first use (null or unknown state, e.g. import),
// all response tags are stored as-is.
func setKeyTags(ctx context.Context, response string, stateTags *types.Map, diags *diag.Diagnostics) {
	// Read all user-visible tags from the response (exclude internal policy-template tag).
	allTags := make(map[string]string)
	for _, tag := range gjson.Get(response, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != policyTemplateTagKey {
			allTags[tagKey] = tagValue
		}
	}

	// When stateTags is already a known map (plan value or prior state), filter to only those keys.
	// An empty but known map (user set tags = {}) results in an empty filtered map - correct behaviour.
	filteredTags := allTags
	if !stateTags.IsNull() && !stateTags.IsUnknown() {
		priorKeys := stateTags.Elements()
		filteredTags = make(map[string]string, len(priorKeys))
		for k := range priorKeys {
			if v, ok := allTags[k]; ok {
				filteredTags[k] = v
			}
		}
	}

	tagMap, d := types.MapValueFrom(ctx, types.StringType, filteredTags)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	// If the result is an empty map but the prior state/plan had null, keep null.
	// This prevents "was null, but now cty.MapValEmpty" inconsistency errors when
	// tags are not configured and the API returns no tags.
	if !tagMap.IsNull() && len(tagMap.Elements()) == 0 && stateTags.IsNull() {
		*stateTags = types.MapNull(types.StringType)
		return
	}
	*stateTags = tagMap
}

// setAliases parses alias values from the API response JSON and stores them in the Terraform state set.
func setAliases(response string, stateAlias *types.Set, diags *diag.Diagnostics) {
	var aliases []attr.Value
	aliasesJSON := gjson.Get(response, "aws_param.Alias").Array()
	for _, item := range aliasesJSON {
		alias := item.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		aliases = append(aliases, types.StringValue(alias))
	}
	aliasSet, d := types.SetValue(types.StringType, aliases)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateAlias = aliasSet
}
