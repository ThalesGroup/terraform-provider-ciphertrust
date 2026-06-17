package cckm

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// getAwsKey fetches an AWS key from CipherTrust Manager by its CM resource UUID (new format).
// Returns (keyJSON, false) on success.
// If the key is not found (404):
//   - opLabel "deleting": warning added, ("", false) returned - resource will be removed from state.
//   - opLabel "reading" + KMS 404: warning added, ("", true) returned - caller should preserve state.
//   - opLabel "reading" + KMS reachable error: error added, ("", false) returned.
//   - other opLabels + kmsID set: KMS is checked for a specific error; error added, ("", false) returned.
//   - kmsID empty: generic error added, ("", false) returned.
//
// A non-404 key error is always a hard error. ("", false) is returned.
func getAwsKey(ctx context.Context, id string, client *common.Client, kmsID string, keyID string, opLabel string, diags *diag.Diagnostics) (string, bool) {
	keyJSON, err := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			if opLabel == "deleting" {
				msg := "AWS key was not found. It will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else if kmsID != "" {
				_, kmsErr := client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
				if kmsErr != nil {
					if strings.Contains(kmsErr.Error(), notFoundError) {
						if opLabel == "reading" {
							// KMS gone - key is hidden. Signal caller to preserve existing state.
							msg := "AWS KMS was not found while reading AWS key. Key state preserved until KMS is recovered."
							details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID, "key_id": keyID})
							tflog.Warn(ctx, details)
							diags.AddWarning(details, "")
							return "", true
						}
						msg := "AWS KMS was not found while " + opLabel + " AWS key."
						details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID, "key_id": keyID})
						tflog.Error(ctx, details)
						diags.AddError(details, "")
					} else {
						msg := "Error reading AWS KMS while " + opLabel + " AWS key."
						details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID, "key_id": keyID, "error": kmsErr.Error()})
						tflog.Error(ctx, details)
						diags.AddError(details, "")
					}
				} else {
					// KMS is reachable but the key is gone - use terraform state rm to remove.
					msg := "AWS key was not found in CipherTrust Manager while " + opLabel + ". Use terraform state rm to remove this resource from state if the key no longer exists."
					details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID, "key_id": keyID})
					tflog.Error(ctx, details)
					diags.AddError(details, "")
				}
			} else {
				msg := "AWS key was not found while " + opLabel + "."
				details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return "", false
		}
		msg := "Error " + opLabel + " AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return "", false
	}
	return keyJSON, false
}

// findCMKeyIDByAWSKeyID looks up the CipherTrust Manager resource ID for an AWS key given its
// AWS key ID (the short ID such as "abc12345-..." or an MR key ID starting with "mrk-").
//
// For a standard key the filter "keyid" is sufficient to uniquely identify it.
// For a multi-region key (an aws key_id starts with "mrk-") the same "keyid" filter is used but
// the additional filters "multi_region=true" and "multi_region_key_type=PRIMARY" are added so
// that only the primary key record is returned (each replica shares the same mrk- key ID prefix).
//
// Returns the CM UUID string on success, or "" after adding an error diagnostic on failure.
func findCMKeyIDByAWSKeyID(ctx context.Context, id string, client *common.Client, awsKeyID string, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_read.go -> findCMKeyIDByAWSKeyID]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_read.go -> findCMKeyIDByAWSKeyID]["+id+"]")

	filters := url.Values{}
	filters.Add("keyid", awsKeyID)
	if strings.HasPrefix(awsKeyID, "mrk-") {
		filters.Add("multi_region", "true")
		filters.Add("multi_region_key_type", "PRIMARY")
	}

	listJSON, err := client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Error looking up AWS key in CipherTrust Manager by AWS key ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": awsKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}

	total := gjson.Get(listJSON, "total").Int()
	if total == 0 {
		msg := "AWS key not found in CipherTrust Manager. Ensure the key has been registered in CM before managing its key material."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": awsKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	if total > 1 {
		msg := "Multiple AWS keys found in CipherTrust Manager with the same AWS key ID."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": awsKeyID, "count": total})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}

	cmKeyID := gjson.Get(listJSON, "resources.0.id").String()
	if cmKeyID == "" {
		msg := "CipherTrust Manager key ID was empty in list response."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": awsKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return cmKeyID
}

// findKeyCMIDByRegion finds the CipherTrust Manager resource ID of the multi-region key in a specific region.
// awsMrkKeyID is the shared mrk-xxx key ID present on all keys in the set (from aws_param.KeyId).
// Returns the CCKM UUID on success, or "" after adding a warning diagnostic on failure (non-fatal).
func findKeyCMIDByRegion(ctx context.Context, id string, client *common.Client, awsMrkKeyID string, region string, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_read.go -> findKeyCMIDByRegion]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_read.go -> findKeyCMIDByRegion]["+id+"]")
	tflog.Debug(ctx, fmt.Sprintf("findKeyCMIDByRegion: region: %s", region))
	filters := url.Values{}
	filters.Add("keyid", awsMrkKeyID)
	filters.Add("region", region)
	listJSON, err := client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Error looking up key in CipherTrust Manager by region."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": awsMrkKeyID, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	total := gjson.Get(listJSON, "total").Int()
	if total == 0 {
		msg := "Key not found by region in CipherTrust Manager."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": awsMrkKeyID, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	cmKeyID := gjson.Get(listJSON, "resources.0.id").String()
	if cmKeyID == "" {
		msg := "CipherTrust Manager key ID was empty looking up key by region."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": awsMrkKeyID, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return cmKeyID
}

// getPrimaryKey looks up and returns the primary key JSON for a multi-region AWS key given any key in the set.
func getPrimaryKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_read.go -> getPrimaryKey]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_read.go -> getPrimaryKey]["+id+"]")
	response, err := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Failed get primary key ID of AWS key " + keyID + ", error reading key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	primaryKeyRegion := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	primaryKeyARN := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()
	primaryKeyArnParts := strings.Split(primaryKeyARN, ":")
	if len(primaryKeyArnParts) != 6 {
		msg := "Failed get primary key of AWS key, unexpected primary key ARN format."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "arn": primaryKeyARN})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	kidParts := strings.Split(primaryKeyArnParts[5], "/")
	if len(kidParts) != 2 {
		msg := "Failed get primary key of AWS key, unexpected primary key ARN format."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "arn": primaryKeyArnParts[5]})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	filters := url.Values{}
	filters.Add("keyid", kidParts[1])
	filters.Add("region", primaryKeyRegion)
	response, err = client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Error reading AWS primary key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kid": kidParts[1], "region": primaryKeyRegion})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total == 0 {
		msg := "Error reading AWS primary key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	if total != 1 {
		msg := "Error reading AWS primary key, failed to list just one key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	resources := gjson.Get(response, "resources").Array()
	for _, keyResourceJSON := range resources {
		response = keyResourceJSON.Raw
	}
	tflog.Debug(ctx, "[aws_read.go -> getPrimaryKey][response:"+redactAWSResponse(response))
	return response
}
