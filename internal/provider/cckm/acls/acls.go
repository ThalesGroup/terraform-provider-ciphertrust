package acls

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// EncodeContainerAclID builds a composite ACL resource ID from a container ID and either a user ID or a group name.
func EncodeContainerAclID(containerID, userID, group string) string {
	if userID != "" {
		return containerID + "::" + "user" + "::" + userID
	} else {
		return containerID + "::" + "group" + "::" + group
	}
}

// DecodeContainerAclID splits a composite ACL resource ID back into its container ID, type ("user" or "group"), and identity.
func DecodeContainerAclID(resourceID string) (containerID string, aclType string, userIDorGroup string, err error) {
	idParts := strings.Split(resourceID, "::")
	if len(idParts) != 3 {
		err = fmt.Errorf("%s is not a valid ACL resource id", resourceID)
		return
	}
	containerID = idParts[0]
	aclType = idParts[1]
	userIDorGroup = idParts[2]
	return
}

// SetAclsStateFromJSON populates a Terraform Set value with ACL entries parsed from a gjson ACL array result.
func SetAclsStateFromJSON(ctx context.Context, aclsJSON gjson.Result, aclSet *types.Set, diags *diag.Diagnostics) {
	var aclsTFSDK []AclTFSDK
	for _, aclJSON := range aclsJSON.Array() {
		actionSet := utils.StringSliceJSONToSetValue(gjson.Get(aclJSON.String(), "actions").Array(), diags)
		if diags.HasError() {
			return
		}
		aclTfsdk := AclTFSDK{
			UserID:  types.StringValue(gjson.Get(aclJSON.String(), "user_id").String()),
			Group:   types.StringValue(gjson.Get(aclJSON.String(), "group").String()),
			Actions: actionSet,
		}
		aclsTFSDK = append(aclsTFSDK, aclTfsdk)
	}
	aclsSetValue, dg := types.SetValueFrom(ctx,
		types.ObjectType{AttrTypes: AclAttributes}, aclsTFSDK)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*aclSet = aclsSetValue
}

// GetUnPermittedAcl returns an ACL revocation entry for any actions currently granted that are absent from newActions.
func GetUnPermittedAcl(ctx context.Context, resourceID string, aclsJSON string, newActions []string, diags *diag.Diagnostics) *ContainerAclJSON {
	_, aclType, userIDOrGroup, err := DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error updating ACL list, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}

	var currentAcls []ContainerAclJSON
	if len(aclsJSON) != 0 {
		err = json.Unmarshal([]byte(aclsJSON), &currentAcls)
		if err != nil {
			msg := "Error updating ACL list, invalid data output."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return nil
		}
	}

	var currentActions []string
	if len(currentAcls) != 0 {
		for _, acl := range currentAcls {
			if (aclType == "user" && acl.UserID == userIDOrGroup) || (aclType == "group" && acl.Group == userIDOrGroup) {
				currentActions = acl.Actions
				break
			}
		}
	}

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
		return &acl
	}
	return nil
}

// GetPermittedAcl builds an ACL permit entry granting the supplied actions to the user or group encoded in resourceID.
func GetPermittedAcl(ctx context.Context, resourceID string, newActions []string, diags *diag.Diagnostics) *ContainerAclJSON {
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
	return &acl
}

// AclExistsInResponse returns true if the ACL entry for the user or group encoded in resourceID
// is present in the acls array of the API response JSON.
func AclExistsInResponse(responseJSON string, resourceID string) bool {
	_, aclType, userIDOrGroup, err := DecodeContainerAclID(resourceID)
	if err != nil {
		return false
	}
	aclsResult := gjson.Get(responseJSON, "acls")
	if !aclsResult.Exists() {
		return false
	}
	for _, aclJSON := range aclsResult.Array() {
		if aclType == "group" && gjson.Get(aclJSON.String(), "group").String() == userIDOrGroup {
			return true
		}
		if aclType == "user" && gjson.Get(aclJSON.String(), "user_id").String() == userIDOrGroup {
			return true
		}
	}
	return false
}

// SetAclCommonState populates an AclTFSDK state struct by locating the matching ACL entry within the API response JSON.
func SetAclCommonState(ctx context.Context, resourceID string, responseJSON string, state *AclTFSDK, diags *diag.Diagnostics) {
	_, aclType, userIDOrGroup, err := DecodeContainerAclID(resourceID)
	if err != nil {
		msg := "Error setting state for ACL, invalid resource ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": resourceID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	if gjson.Get(responseJSON, "acls").Exists() {
		var aclTFSDK AclTFSDK
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
				if diags.HasError() {
					return
				}
				break
			}
		}
		if found {
			*state = aclTFSDK
		}
	}
}
