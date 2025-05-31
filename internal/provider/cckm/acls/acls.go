package acls

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

func EncodeContainerAclID(containerID, userID, group string) string {
	if userID != "" {
		return containerID + "::" + "user" + "::" + userID
	} else {
		return containerID + "::" + "group" + "::" + group
	}
}

func DecodeContainerAclID(resourceID string) (containerID string, aclType string, userIDorGroup string, err error) {
	idParts := strings.Split(resourceID, "::")
	if len(idParts) != 3 {
		err = fmt.Errorf("%s is not a valid ACL resource id", resourceID)
	}
	containerID = idParts[0]
	aclType = idParts[1]
	userIDorGroup = idParts[2]
	return
}

func SetAclsStateFromJSON(ctx context.Context, acslJSON gjson.Result, aclsStateList *types.Set, diags *diag.Diagnostics) {
	var aclsTFSDK []AclCommonTFSDK
	for _, aclJSON := range acslJSON.Array() {
		var actions []attr.Value
		for _, item := range gjson.Get(aclJSON.String(), "actions").Array() {
			actions = append(actions, types.StringValue(item.String()))
		}
		var dg diag.Diagnostics
		actionSet, dg := types.SetValue(types.StringType, actions)
		if dg.HasError() {
			diags.Append(dg...)
			return
		}
		aclTfsdk := AclCommonTFSDK{
			UserID:  types.StringValue(gjson.Get(aclJSON.String(), "user_id").String()),
			Group:   types.StringValue(gjson.Get(aclJSON.String(), "group").String()),
			Actions: actionSet,
		}
		aclsTFSDK = append(aclsTFSDK, aclTfsdk)
	}
	SetAclsStateFromList(ctx, aclsTFSDK, aclsStateList, diags)
}

func SetAclsStateFromList(ctx context.Context, aclsTFSDK []AclCommonTFSDK, aclsStateList *types.Set, diags *diag.Diagnostics) {
	var dg diag.Diagnostics
	aclsListValue, dg := types.SetValueFrom(ctx,
		types.ObjectType{AttrTypes: map[string]attr.Type{
			"user_id": types.StringType,
			"group":   types.StringType,
			"actions": types.SetType{ElemType: types.StringType},
		}}, aclsTFSDK)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*aclsStateList, dg = aclsListValue.ToSetValue(ctx)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
}

func GetUnPermittedActionsPayloadJSON(ctx context.Context, resourceID string, aclsJSON string, newActions []string, diags *diag.Diagnostics) []byte {
	_, aclType, userIDOrGroup, err := DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error updating ACL list, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}

	var currentAcls []ContainerAclJSON
	err = json.Unmarshal([]byte(aclsJSON), &currentAcls)
	if err != nil {
		msg := "Error updating ACL list, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}

	var currentActions []string
	if len(currentAcls) != 0 {
		for _, acl := range currentAcls {
			if aclType == "user" && acl.UserID == userIDOrGroup || aclType == "group" && acl.Group == userIDOrGroup {
				currentActions = acl.Actions
				break
			}
		}
	}
	tflog.Info(ctx, fmt.Sprintf("SARAH currentActions %v", currentActions))

	// Discover currently set but now not permitted actions
	var notPermittedActions []string
	for _, currentAction := range currentActions {
		found := false
		for _, newAction := range newActions {
			if newAction == currentAction {
				found = true
			}
		}
		if !found {
			notPermittedActions = append(notPermittedActions, currentAction)
		}
	}

	var payloadJSON []byte
	if len(notPermittedActions) != 0 {
		acl := ContainerAclJSON{
			Permit:  false,
			Actions: notPermittedActions,
		}
		if aclType == "user" {
			acl.UserID = userIDOrGroup
		} else {
			acl.Group = userIDOrGroup
		}
		payload := BaseAclsJSON{
			ContainerAcls: []ContainerAclJSON{acl},
		}
		payloadJSON, err = json.Marshal(payload)
		if err != nil {
			msg := "Error updating ACL list, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return nil
		}
		return payloadJSON
	}
	return nil
}

func GetPermittedActionsPayloadJSON(ctx context.Context, resourceID string, newActions []string, diags *diag.Diagnostics) []byte {
	_, aclType, userIDOrGroup, err := DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error updating ACL list, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	acl := ContainerAclJSON{
		Permit:  true,
		Actions: newActions,
	}
	if aclType == "user" {
		acl.UserID = userIDOrGroup
	} else {
		acl.Group = userIDOrGroup
	}
	payload := BaseAclsJSON{
		ContainerAcls: []ContainerAclJSON{acl},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating ACL list, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	return payloadJSON

}

func SetAclCommonState(ctx context.Context, resourceID string, responseJSON string, state *AclCommonTFSDK, diags *diag.Diagnostics) {
	_, aclType, userIDOrGroup, err := DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error setting state for ACL, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	var aclTFSDK AclCommonTFSDK
	if gjson.Get(responseJSON, "acls").Exists() {
		aclsJSON := gjson.Get(responseJSON, "acls").Array()
		found := false
		for _, aclJSON := range aclsJSON {
			group := gjson.Get(aclJSON.String(), "group").String()
			userID := gjson.Get(aclJSON.String(), "user_id").String()
			if aclType == "group" && group == userIDOrGroup {
				aclTFSDK.Group = types.StringValue(group)
				found = true
			} else if aclType == "user" && userID == userIDOrGroup {
				aclTFSDK.UserID = types.StringValue(userID)
				found = true
			}
			if found {
				aclTFSDK.Actions = utils.StringSliceJSONToSetValue(gjson.Get(aclJSON.String(), "actions").Array(), diags)
				break
			}
		}
	}
	*state = aclTFSDK
}
