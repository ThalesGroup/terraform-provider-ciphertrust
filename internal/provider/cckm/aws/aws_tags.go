package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// updateTags reconciles the plan's tag map against the key's current tags, adding and removing as needed.
// The internal policy-template tag (cckm_policy_template_id) is excluded from reconciliation and is
// never added or removed by this function. Used by resourceAWSKey, resourceAWSXKSKey (linked only), resourceAWSCloudHSMKey (linked only).
func updateTags(ctx context.Context, id string, client *common.Client, planTags map[string]string, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_tags.go -> updateTags]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_tags.go -> updateTags]["+id+"]")
	var (
		addTagsPayload    AddTagsJSON
		removeTagsPayload RemoveTagsJSON
	)
	keyID := gjson.Get(keyJSON, "id").String()
	keyTags := make(map[string]string)
	for _, tag := range gjson.Get(keyJSON, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != policyTemplateTagKey {
			keyTags[tagKey] = tagValue
		}
	}
	for keyTagKey, keyTagValue := range keyTags {
		found := false
		for planKey, planValue := range planTags {
			if planKey == keyTagKey && planValue == keyTagValue {
				found = true
				break
			}
		}
		if !found {
			t := keyTagKey
			removeTagsPayload.Tags = append(removeTagsPayload.Tags, &t)
		}
	}
	if len(removeTagsPayload.Tags) != 0 {
		payloadJSON, err := json.Marshal(removeTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to remove tags, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/remove-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to remove tags."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Info(ctx, fmt.Sprintf("[aws_tags.go -> updateTags] tags removed successfully. key_id: %s", keyID))
		tflog.Debug(ctx, "[aws_tags.go -> updateTags][response:"+redactAWSResponse(response))
	}
	for planKey, planValue := range planTags {
		found := false
		for keyTagKey, keyTagValue := range keyTags {
			if planKey == keyTagKey && planValue == keyTagValue {
				found = true
				break
			}
		}
		if !found {
			t := AddTagPayloadJSON{
				TagKey:   planKey,
				TagValue: planValue,
			}
			addTagsPayload.Tags = append(addTagsPayload.Tags, t)
		}
	}
	if len(addTagsPayload.Tags) != 0 {
		payloadJSON, err := json.Marshal(addTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to add tags, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/add-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to add tags."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Info(ctx, fmt.Sprintf("[aws_tags.go -> updateTags] tags added successfully. key_id: %s", keyID))
		tflog.Debug(ctx, "[aws_tags.go -> updateTags][response:"+redactAWSResponse(response))
	}
}

// getTagsParam converts a tags map into a slice of AWSKeyParamTagJSON structs for the API payload.
// Used by resourceAWSKey, resourceAWSByokKey, resourceAWSXKSKey, resourceAWSCloudHSMKey.
func getTagsParam(ctx context.Context, tags types.Map, diags *diag.Diagnostics) []AWSKeyParamTagJSON {
	if len(tags.Elements()) == 0 {
		return nil
	}
	tagMap := make(map[string]string, len(tags.Elements()))
	diags.Append(tags.ElementsAs(ctx, &tagMap, false)...)
	if diags.HasError() {
		return nil
	}
	var awsTags []AWSKeyParamTagJSON
	for k, v := range tagMap {
		key := k
		value := v
		tag := AWSKeyParamTagJSON{
			TagKey:   key,
			TagValue: value,
		}
		awsTags = append(awsTags, tag)
	}
	return awsTags
}

// setPolicyTemplateTag finds and stores the policy-template tag from the AWS key's tag list in Terraform state.
func setPolicyTemplateTag(ctx context.Context, response string, statePolicyTemplateTag *types.Map, diags *diag.Diagnostics) {
	statePolicyTemplateTagMap := types.MapNull(types.StringType)
	tags := gjson.Get(response, "aws_param.Tags").Array()
	for _, tag := range tags {
		tagKey := gjson.Get(tag.String(), "TagKey").String()
		if tagKey == policyTemplateTagKey {
			tagValue := gjson.Get(tag.String(), "TagValue").String()
			elements := map[string]attr.Value{
				tagKey: types.StringValue(tagValue),
			}
			policyTemplateTagMap, d := types.MapValueFrom(ctx, types.StringType, elements)
			if d.HasError() {
				diags.Append(d...)
				return
			}
			statePolicyTemplateTagMap = policyTemplateTagMap
			break
		}
	}
	*statePolicyTemplateTag = statePolicyTemplateTagMap
}

// removeKeyPolicyTemplateTag removes the policy template tag (cckm_policy_template_id) from an AWS key
// prior to scheduled deletion. Errors are downgraded to warnings so that deletion proceeds even if tag
// removal fails. Used by resourceAWSKey, resourceAWSXKSKey (linked only), resourceAWSCloudHSMKey (linked only).
func removeKeyPolicyTemplateTag(ctx context.Context, id string, client *common.Client, keyJSON string, diags *diag.Diagnostics) {
	var policyTemplateID string
	for _, tag := range gjson.Get(keyJSON, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		if tagKey == policyTemplateTagKey {
			policyTemplateID = tagKey
			break
		}
	}
	if policyTemplateID != "" {
		var removeTagsPayload RemoveTagsJSON
		keyID := gjson.Get(keyJSON, "id").String()
		tagKey := policyTemplateTagKey
		removeTagsPayload.Tags = append(removeTagsPayload.Tags, &tagKey)
		payloadJSON, err := json.Marshal(removeTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to remove policy template tag, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			return
		}
		_, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/remove-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to remove policy template tag."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		} else {
			tflog.Info(ctx, fmt.Sprintf("[aws_tags.go -> removeKeyPolicyTemplateTag] policy template tag removed successfully. key_id: %s", keyID))
		}
	}
}
