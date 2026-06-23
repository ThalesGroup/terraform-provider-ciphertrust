package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// getKeyPolicyParams extracts key policy fields (admins, users, external accounts, policy JSON, policy template)
// from a key_policy block. Returns a zero-value struct when the block is nil.
// Used by resourceAWSKey, resourceAWSByokKey, resourceAWSXKSKey, resourceAWSCloudHSMKey.
func getKeyPolicyParams(ctx context.Context, keyPolicy *AWSKeyPolicyTFSDK, diags *diag.Diagnostics) *KeyPolicyPayloadJSON {
	var policy KeyPolicyPayloadJSON
	if keyPolicy != nil {
		kp := keyPolicy
		if !kp.ExternalAccounts.IsNull() && len(kp.ExternalAccounts.Elements()) != 0 {
			accounts := make([]string, 0, len(kp.ExternalAccounts.Elements()))
			diags.Append(kp.ExternalAccounts.ElementsAs(ctx, &accounts, false)...)
			if diags.HasError() {
				return nil
			}
			policy.ExternalAccounts = &accounts
		}
		if !kp.KeyAdmins.IsNull() && len(kp.KeyAdmins.Elements()) != 0 {
			keyAdmins := make([]string, 0, len(kp.KeyAdmins.Elements()))
			diags.Append(kp.KeyAdmins.ElementsAs(ctx, &keyAdmins, false)...)
			if diags.HasError() {
				return nil
			}
			policy.KeyAdmins = &keyAdmins
		}
		if !kp.KeyAdminsRoles.IsNull() && len(kp.KeyAdminsRoles.Elements()) != 0 {
			keyAdminsRoles := make([]string, 0, len(kp.KeyAdminsRoles.Elements()))
			diags.Append(kp.KeyAdminsRoles.ElementsAs(ctx, &keyAdminsRoles, false)...)
			if diags.HasError() {
				return nil
			}
			policy.KeyAdminsRoles = &keyAdminsRoles
		}
		if !kp.KeyUsers.IsNull() && len(kp.KeyUsers.Elements()) != 0 {
			keyUsers := make([]string, 0, len(kp.KeyUsers.Elements()))
			diags.Append(kp.KeyUsers.ElementsAs(ctx, &keyUsers, false)...)
			if diags.HasError() {
				return nil
			}
			policy.KeyUsers = &keyUsers
		}
		if !kp.KeyUsersRoles.IsNull() && len(kp.KeyUsersRoles.Elements()) != 0 {
			keyUsersRoles := make([]string, 0, len(kp.KeyUsersRoles.Elements()))
			diags.Append(kp.KeyUsersRoles.ElementsAs(ctx, &keyUsersRoles, false)...)
			if diags.HasError() {
				return nil
			}
			policy.KeyUsersRoles = &keyUsersRoles
		}
		if !kp.PolicyTemplate.IsNull() && len(kp.PolicyTemplate.ValueString()) != 0 {
			policy.PolicyTemplate = kp.PolicyTemplate.ValueStringPointer()
		}
		if !kp.Policy.IsNull() && len(kp.Policy.ValueString()) != 0 {
			policyStr := kp.Policy.ValueString()
			policyBytes := json.RawMessage(policyStr)
			policy.Policy = &policyBytes
		}
	}
	return &policy
}

// updateKeyPolicy applies a new key policy to an AWS key when the policy parameters have changed.
func updateKeyPolicy(ctx context.Context, id string, client *common.Client, planInput *AWSKeyUpdateInputTFSDK, stateInput *AWSKeyUpdateInputTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_policy.go -> updateKeyPolicy]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_policy.go -> updateKeyPolicy]["+id+"]")
	statePolicy := getKeyPolicyParams(ctx, stateInput.KeyPolicy, diags)
	if diags.HasError() {
		return
	}
	planPolicyPayload := getKeyPolicyParams(ctx, planInput.KeyPolicy, diags)
	if diags.HasError() {
		return
	}
	if keyPolicyHasChanged(planPolicyPayload, statePolicy) {
		keyID := planInput.KeyID
		payloadJSON, err := json.Marshal(planPolicyPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to update key policy, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/policy", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to update key policy."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		planInput.KeyID = gjson.Get(response, "id").String()
		tflog.Info(ctx, fmt.Sprintf("[aws_policy.go -> updateKeyPolicy] key policy updated successfully. key_id: %s", keyID))
		tflog.Debug(ctx, "[aws_policy.go -> updateKeyPolicy][response:"+redactAWSResponse(response))
	}
}

// keyPolicyHasChanged reports whether any key policy field differs between two KeyPolicyPayloadJSON values.
func keyPolicyHasChanged(a *KeyPolicyPayloadJSON, b *KeyPolicyPayloadJSON) bool {
	if !utils.SlicesAreEqual(a.ExternalAccounts, b.ExternalAccounts) ||
		!utils.SlicesAreEqual(a.KeyAdmins, b.KeyAdmins) ||
		!utils.SlicesAreEqual(a.KeyAdminsRoles, b.KeyAdminsRoles) ||
		!utils.SlicesAreEqual(a.KeyUsers, b.KeyUsers) ||
		!utils.SlicesAreEqual(a.KeyUsersRoles, b.KeyUsersRoles) ||
		!utils.StringsEqual(a.PolicyTemplate, b.PolicyTemplate) ||
		!utils.BytesAreEqual(a.Policy, b.Policy) {
		return true
	}
	return false
}
