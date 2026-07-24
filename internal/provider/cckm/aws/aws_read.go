// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

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

// getAwsKey fetches an AWS key from CipherTrust Manager by its CM resource UUID.
// Returns (keyJSON, false) on success.
// If the key is not found (404):
//   - opLabel "deleting": warning added, ("", false) returned - resource will be removed from state.
//   - any other opLabel: error added, ("", false) returned - state is preserved.
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
						msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS KMS")
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
					// KMS is reachable but the key is gone.
					msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS key")
					details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID, "key_id": keyID})
					tflog.Error(ctx, details)
					diags.AddError(details, "")
				}
			} else {
				msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS key")
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

// getAwsPolicyTemplate fetches an AWS key policy template by its CipherTrust Manager ID.
// On success the template JSON is returned.
// On a 404 error:
//   - opLabel "deleting": warning added, "" returned - Terraform removes the resource from state.
//   - any other opLabel: error added, "" returned - state is preserved.
//
// Any non-404 error adds an error diagnostic and returns "".
func getAwsPolicyTemplate(ctx context.Context, id string, client *common.Client, templateID string, opLabel string, diags *diag.Diagnostics) string {
	response, err := client.GetById(ctx, id, templateID, common.URL_AWS_POLICY_TEMPLATES)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			var msg string
			if opLabel == "deleting" {
				msg = "AWS policy template was not found. It will be removed from state."
			} else {
				msg = fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS policy template")
			}
			details := utils.ApiError(msg, map[string]interface{}{"template_id": templateID})
			if opLabel == "deleting" {
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else {
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + opLabel + " AWS policy template, failed to read AWS policy template."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "template_id": templateID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// getAwsKms fetches an AWS KMS by its CipherTrust Manager ID.
// On success the KMS JSON is returned.
// On a 404 error:
//   - opLabel "deleting": warning added, "" returned - Terraform removes the resource from state.
//   - any other opLabel: error added, "" returned - state is preserved.
//
// Any non-404 error adds an error diagnostic and returns "".
func getAwsKms(ctx context.Context, id string, client *common.Client, kmsID string, opLabel string, diags *diag.Diagnostics) string {
	response, err := client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			var msg string
			if opLabel == "deleting" {
				msg = "AWS KMS was not found. It will be removed from state."
			} else {
				msg = fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS KMS")
			}
			details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID})
			if opLabel == "deleting" {
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else {
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + opLabel + " AWS KMS, failed to read AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// getAwsXksKey fetches an AWS XKS key from CipherTrust Manager by its resource ID.
// If keystoreID is non-empty, the custom key store is verified to exist before fetching the key;
// a missing or unreachable key store is always a hard error regardless of opLabel.
// A 404 on the key itself is treated according to opLabel: when opLabel is "deleting" a warning is
// added and an empty string is returned; for any other opLabel an error is added and an empty string is returned.
func (r *resourceAWSXKSKey) getAwsXksKey(ctx context.Context, id string, keystoreID string, keyID string, opLabel string, diags *diag.Diagnostics) string {
	if keystoreID != "" {
		getAwsCustomKeyStore(ctx, r.client, id, keystoreID, "reading", diags)
		if diags.HasError() {
			return ""
		}
	}

	keyJSON, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			var msg string
			if opLabel == "deleting" {
				msg = "AWS XKS key was not found. It will be removed from state."
			} else {
				msg = fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS XKS key")
			}
			details := utils.ApiError(msg, map[string]interface{}{"keystore_id": keystoreID, "key_id": keyID})
			if opLabel == "deleting" {
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else {
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + opLabel + " AWS XKS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return keyJSON
}

// getAwsCloudHsmKey fetches an AWS CloudHSM key from CipherTrust Manager using the Terraform resource ID.
// If customKeyStoreID is not empty, the custom key store is verified to exist before fetching the key;
// a missing or unreachable key store is always a hard error regardless of opLabel.
// If terraformID has no backslash (new format - CM resource UUID), the key is fetched directly by ID.
// If terraformID has a backslash (legacy region\aws-key-id format), the key is fetched via list query.
// A 404 on the key itself is treated according to opLabel: when opLabel is "deleting" a warning is
// added and an empty string is returned; for any other opLabel an error is added and an empty string is returned.
func (r *resourceAWSCloudHSMKey) getAwsCloudHsmKey(ctx context.Context, id string, customKeyStoreID string, terraformID string, opLabel string, diags *diag.Diagnostics) string {
	if customKeyStoreID != "" {
		getAwsCustomKeyStore(ctx, r.client, id, customKeyStoreID, "reading", diags)
		if diags.HasError() {
			return ""
		}
	}
	region, kid, err := r.decodeCloudHSMKeyTerraformResourceID(terraformID)
	if err != nil {
		diags.AddError("Failed to decode terraform ID "+terraformID+".", err.Error())
		return ""
	}
	if region == "" {
		// New format: terraformID is the CM resource UUID. Fetch directly.
		keyJSON, err := r.client.GetById(ctx, id, terraformID, common.URL_AWS_KEY)
		if err != nil {
			if strings.Contains(err.Error(), notFoundError) {
				if opLabel == "deleting" {
					msg := "AWS CloudHSM key (" + terraformID + ") was not found. It will be removed from state."
					details := utils.ApiError(msg, map[string]interface{}{"key_id": terraformID})
					tflog.Warn(ctx, details)
					diags.AddWarning(details, "")
				} else {
					msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS CloudHSM key")
					details := utils.ApiError(msg, map[string]interface{}{"key_id": terraformID})
					tflog.Error(ctx, details)
					diags.AddError(details, "")
				}
				return ""
			}
			msg := "Error reading AWS CloudHSM key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": terraformID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return ""
		}
		return keyJSON
	}
	// Legacy format: region\aws-key-id. Use list query for backwards compatibility.
	filters := url.Values{}
	filters.Add("keyid", kid)
	filters.Add("region", region)
	response, err := r.client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Failed to read AWS CloudHSM key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kid": kid, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total == 0 {
		var msg string
		if opLabel == "deleting" {
			msg = "AWS CloudHSM key was not found. It will be removed from state."
		} else {
			msg = fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS CloudHSM key")
		}
		details := utils.ApiError(msg, map[string]interface{}{"kid": kid, "region": region})
		if opLabel == "deleting" {
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		} else {
			tflog.Error(ctx, details)
			diags.AddError(details, "")
		}
		return ""
	}
	if total != 1 {
		msg := "Error reading AWS CloudHSM key, failed to list just one key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kid, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	resources := gjson.Get(response, "resources").Array()
	var keyJSON string
	for _, keyResourceJSON := range resources {
		keyJSON = keyResourceJSON.Raw
	}
	return keyJSON
}
