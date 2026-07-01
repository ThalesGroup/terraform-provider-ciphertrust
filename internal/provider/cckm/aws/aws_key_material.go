package cckm

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// rotationHistoryNativeSummaryElemType matches rotationHistoryNativeSummarySchemaAttribute:
// 5 fields for native symmetric keys. Used by the aws_key resource.
var rotationHistoryNativeSummaryElemType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"key_material_id":    types.StringType,
		"rotation_date":      types.StringType,
		"key_material_state": types.StringType,
		"import_state":       types.StringType,
		"last_import_status": types.StringType,
	},
}

// rotationHistoryByokSummaryElemType matches rotationHistoryByokSummarySchemaAttribute:
// 7 fields for EXTERNAL (BYOK) keys. Used by the aws_byok_key resource.
var rotationHistoryByokSummaryElemType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"key_material_id":       types.StringType,
		"rotation_date":         types.StringType,
		"key_material_state":    types.StringType,
		"import_state":          types.StringType,
		"last_import_status":    types.StringType,
		"source_key_identifier": types.StringType,
		"source_key_tier":       types.StringType,
	},
}

// rotationHistoryNativeFullElemType matches rotationHistoryNativeFullSchemaAttribute:
// 18 flat fields for native symmetric key rotation records. No source (BYOK) fields,
// no uri, no account. Used by the aws_key_rotation resource.
var rotationHistoryNativeFullElemType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"id":                       types.StringType,
		"created_at":               types.StringType,
		"updated_at":               types.StringType,
		"local_key_id":             types.StringType,
		"kms_id":                   types.StringType,
		"key_material_origin":      types.StringType,
		"last_import_status":       types.StringType,
		"last_import_error":        types.StringType,
		"last_import_at":           types.StringType,
		"key_id":                   types.StringType,
		"rotation_date":            types.StringType,
		"rotation_type":            types.StringType,
		"key_material_id":          types.StringType,
		"key_material_description": types.StringType,
		"valid_to":                 types.StringType,
		"expiration_model":         types.StringType,
		"key_material_state":       types.StringType,
		"import_state":             types.StringType,
	},
}

// byokRotationAwsParamAttrTypes defines the attribute types for the aws_params nested object
// inside each BYOK full rotation_history entry. It must match KeyRotationAwsParamTFSDK exactly.
var byokRotationAwsParamAttrTypes = map[string]attr.Type{
	"expiration_model":         types.StringType,
	"import_state":             types.StringType,
	"key_id":                   types.StringType,
	"key_material_description": types.StringType,
	"key_material_id":          types.StringType,
	"key_material_state":       types.StringType,
	"rotation_date":            types.StringType,
	"rotation_type":            types.StringType,
	"valid_to":                 types.StringType,
}

// rotationHistoryByokFullElemType matches rotationHistoryByokFullSchemaAttribute:
// top-level fields for EXTERNAL (BYOK) key rotation records plus an aws_params nested
// object for AWSKeyRotationParams fields. No uri, no account.
// Must match RotationHistoryEntryFullTFSDK exactly.
var rotationHistoryByokFullElemType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		// Resource identity (no uri, no account)
		"id":         types.StringType,
		"created_at": types.StringType,
		"updated_at": types.StringType,
		// Top-level AWSKeyRotation fields
		"local_key_id":              types.StringType,
		"kms_id":                    types.StringType,
		"source_key_identifier":     types.StringType,
		"source_key_name":           types.StringType,
		"source_key_tier":           types.StringType,
		"key_source":                types.StringType,
		"key_material_origin":       types.StringType,
		"key_source_container_name": types.StringType,
		"key_source_container_id":   types.StringType,
		"last_import_status":        types.StringType,
		"last_import_error":         types.StringType,
		"last_import_at":            types.StringType,
		// AWSKeyRotationParams nested under aws_params
		"aws_params": types.ObjectType{AttrTypes: byokRotationAwsParamAttrTypes},
	},
}

// fetchRotationHistoryByokFull retrieves the full rotation history for an EXTERNAL (BYOK) key
// and returns a list of RotationHistoryEntryFullTFSDK objects (rotationHistoryByokFullElemType).
// Used by the aws_key_material resource and internally for classify/repair logic.
// All fields from AWSKeyRotation and AWSKeyRotationParams are populated (no uri, no account).
// Returns (list, apiFailed) where apiFailed is true when the rotations API call fails.
func fetchRotationHistoryByokFull(ctx context.Context, id string, client *common.Client, keyID string) (types.List, bool) {

	emptyList, _ := types.ListValue(rotationHistoryByokFullElemType, []attr.Value{})

	filters := url.Values{
		"skip":  []string{"0"},
		"limit": []string{"-1"},
		"sort":  []string{"-RotationDate"},
	}
	endpoint := "api/v1/cckm/aws/keys/" + keyID + "/rotations"
	rotationsJSON, err := client.ListWithFilters(ctx, id, endpoint, filters)
	if err != nil {
		msg := "Warning: could not fetch rotation history for key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		return emptyList, true
	}

	resources := gjson.Get(rotationsJSON, "resources").Array()

	elems := make([]attr.Value, 0, len(resources))
	for _, res := range resources {
		awsParamsObj, awsParamsDiag := types.ObjectValue(byokRotationAwsParamAttrTypes, map[string]attr.Value{
			"expiration_model":         types.StringValue(res.Get("aws_param.ExpirationModel").String()),
			"import_state":             types.StringValue(res.Get("aws_param.ImportState").String()),
			"key_id":                   types.StringValue(res.Get("aws_param.KeyId").String()),
			"key_material_description": types.StringValue(res.Get("aws_param.KeyMaterialDescription").String()),
			"key_material_id":          types.StringValue(res.Get("aws_param.KeyMaterialId").String()),
			"key_material_state":       types.StringValue(res.Get("aws_param.KeyMaterialState").String()),
			"rotation_date":            types.StringValue(res.Get("aws_param.RotationDate").String()),
			"rotation_type":            types.StringValue(res.Get("aws_param.RotationType").String()),
			"valid_to":                 types.StringValue(res.Get("aws_param.ValidTo").String()),
		})
		if awsParamsDiag.HasError() {
			tflog.Warn(ctx, "Warning: could not build BYOK full rotation history aws_params object.")
			return emptyList, false
		}
		obj, d := types.ObjectValue(rotationHistoryByokFullElemType.AttrTypes, map[string]attr.Value{
			// Resource identity (no uri, no account)
			"id":         types.StringValue(res.Get("id").String()),
			"created_at": types.StringValue(res.Get("createdAt").String()),
			"updated_at": types.StringValue(res.Get("updatedAt").String()),
			// Top-level AWSKeyRotation fields
			"local_key_id":              types.StringValue(res.Get("local_key_id").String()),
			"kms_id":                    types.StringValue(res.Get("kms_id").String()),
			"source_key_identifier":     types.StringValue(res.Get("source_key_identifier").String()),
			"source_key_name":           types.StringValue(res.Get("source_key_name").String()),
			"source_key_tier":           types.StringValue(res.Get("source_key_tier").String()),
			"key_source":                types.StringValue(res.Get("key_source").String()),
			"key_material_origin":       types.StringValue(res.Get("key_material_origin").String()),
			"key_source_container_name": types.StringValue(res.Get("key_source_container_name").String()),
			"key_source_container_id":   types.StringValue(res.Get("key_source_container_id").String()),
			"last_import_status":        types.StringValue(res.Get("last_import_status").String()),
			"last_import_error":         types.StringValue(res.Get("last_import_error").String()),
			"last_import_at":            types.StringValue(res.Get("last_import_at").String()),
			// AWSKeyRotationParams nested under aws_params
			"aws_params": awsParamsObj,
		})
		if d.HasError() {
			tflog.Warn(ctx, "Warning: could not build BYOK full rotation history entry object.")
			return emptyList, false
		}
		elems = append(elems, obj)
	}
	listVal, d := types.ListValue(rotationHistoryByokFullElemType, elems)
	if d.HasError() {
		tflog.Warn(ctx, "Warning: could not build BYOK full rotation history list.")
		return emptyList, false
	}
	return listVal, false
}

// fetchRotationHistoryNativeFullFetch retrieves the rotation history for a native symmetric key
// and returns a list using rotationHistoryNativeFullElemType. Used by the aws_key_rotation resource.
// Returns (list, apiFailed) where apiFailed is true when the API call fails.
func fetchRotationHistoryNativeFull(ctx context.Context, id string, client *common.Client, keyID string) (types.List, bool) {

	emptyList, _ := types.ListValue(rotationHistoryNativeFullElemType, []attr.Value{})

	filters := url.Values{
		"skip":  []string{"0"},
		"limit": []string{"-1"},
		"sort":  []string{"-RotationDate"},
	}
	endpoint := "api/v1/cckm/aws/keys/" + keyID + "/rotations"
	rotationsJSON, err := client.ListWithFilters(ctx, id, endpoint, filters)
	if err != nil {
		msg := "Warning: could not fetch rotation history for key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		return emptyList, true
	}

	resources := gjson.Get(rotationsJSON, "resources").Array()

	elems := make([]attr.Value, 0, len(resources))
	for _, res := range resources {
		obj, d := types.ObjectValue(rotationHistoryNativeFullElemType.AttrTypes, map[string]attr.Value{
			"id":                       types.StringValue(res.Get("id").String()),
			"created_at":               types.StringValue(res.Get("createdAt").String()),
			"updated_at":               types.StringValue(res.Get("updatedAt").String()),
			"local_key_id":             types.StringValue(res.Get("local_key_id").String()),
			"kms_id":                   types.StringValue(res.Get("kms_id").String()),
			"key_material_origin":      types.StringValue(res.Get("key_material_origin").String()),
			"last_import_status":       types.StringValue(res.Get("last_import_status").String()),
			"last_import_error":        types.StringValue(res.Get("last_import_error").String()),
			"last_import_at":           types.StringValue(res.Get("last_import_at").String()),
			"key_id":                   types.StringValue(res.Get("aws_param.KeyId").String()),
			"rotation_date":            types.StringValue(res.Get("aws_param.RotationDate").String()),
			"rotation_type":            types.StringValue(res.Get("aws_param.RotationType").String()),
			"key_material_id":          types.StringValue(res.Get("aws_param.KeyMaterialId").String()),
			"key_material_description": types.StringValue(res.Get("aws_param.KeyMaterialDescription").String()),
			"valid_to":                 types.StringValue(res.Get("aws_param.ValidTo").String()),
			"expiration_model":         types.StringValue(res.Get("aws_param.ExpirationModel").String()),
			"key_material_state":       types.StringValue(res.Get("aws_param.KeyMaterialState").String()),
			"import_state":             types.StringValue(res.Get("aws_param.ImportState").String()),
		})
		if d.HasError() {
			tflog.Warn(ctx, "Warning: could not build native full rotation history entry object.")
			return emptyList, false
		}
		elems = append(elems, obj)
	}
	listVal, d := types.ListValue(rotationHistoryNativeFullElemType, elems)
	if d.HasError() {
		tflog.Warn(ctx, "Warning: could not build native full rotation history list.")
		return emptyList, false
	}
	return listVal, false
}

// fetchRotationHistoryByokSummary retrieves the rotation history summary for an EXTERNAL (BYOK)
// AWS key from CipherTrust Manager. The most recent 10 entries are fetched, sorted by rotation
// date descending. Returns (list, apiFailed) where apiFailed is true when the API call fails.
// Used by the aws_byok_key resource.
func fetchRotationHistoryByokSummary(ctx context.Context, id string, client *common.Client, keyID string) (types.List, bool) {

	emptyList, _ := types.ListValue(rotationHistoryByokSummaryElemType, []attr.Value{})

	filters := url.Values{
		"skip":  []string{"0"},
		"limit": []string{"10"},
		"sort":  []string{"-RotationDate"},
	}
	endpoint := "api/v1/cckm/aws/keys/" + keyID + "/rotations"
	rotationsJSON, err := client.ListWithFilters(ctx, id, endpoint, filters)
	if err != nil {
		msg := "Warning: could not fetch rotation history for key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		return emptyList, true
	}
	resources := gjson.Get(rotationsJSON, "resources").Array()
	elems := make([]attr.Value, 0, len(resources))
	for _, r := range resources {
		obj, d := types.ObjectValue(rotationHistoryByokSummaryElemType.AttrTypes, map[string]attr.Value{
			"key_material_id":       types.StringValue(r.Get("aws_param.KeyMaterialId").String()),
			"rotation_date":         types.StringValue(r.Get("aws_param.RotationDate").String()),
			"key_material_state":    types.StringValue(r.Get("aws_param.KeyMaterialState").String()),
			"import_state":          types.StringValue(r.Get("aws_param.ImportState").String()),
			"last_import_status":    types.StringValue(r.Get("last_import_status").String()),
			"source_key_identifier": types.StringValue(r.Get("source_key_identifier").String()),
			"source_key_tier":       types.StringValue(r.Get("source_key_tier").String()),
		})
		if d.HasError() {
			tflog.Warn(ctx, "Warning: could not build BYOK rotation history summary entry object.")
			return emptyList, false
		}
		elems = append(elems, obj)
	}
	listVal, d := types.ListValue(rotationHistoryByokSummaryElemType, elems)
	if d.HasError() {
		var diagWarn diag.Diagnostics
		diagWarn.Append(d...)
		tflog.Warn(ctx, "Warning: could not build BYOK rotation history summary list.")
		return emptyList, false
	}
	return listVal, false
}

// fetchRotationHistoryNativeSummary retrieves the rotation history summary for a native symmetric
// AWS key from CipherTrust Manager. The most recent 10 entries are fetched, sorted by rotation
// date descending. Returns (list, apiFailed). Used by the aws_key resource.
func fetchRotationHistoryNativeSummary(ctx context.Context, id string, client *common.Client, keyID string) (types.List, bool) {

	emptyList, _ := types.ListValue(rotationHistoryNativeSummaryElemType, []attr.Value{})

	filters := url.Values{
		"skip":  []string{"0"},
		"limit": []string{"10"},
		"sort":  []string{"-RotationDate"},
	}
	endpoint := "api/v1/cckm/aws/keys/" + keyID + "/rotations"
	rotationsJSON, err := client.ListWithFilters(ctx, id, endpoint, filters)
	if err != nil {
		msg := "Warning: could not fetch rotation history for key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		return emptyList, true
	}
	resources := gjson.Get(rotationsJSON, "resources").Array()
	elems := make([]attr.Value, 0, len(resources))
	for _, r := range resources {
		obj, d := types.ObjectValue(rotationHistoryNativeSummaryElemType.AttrTypes, map[string]attr.Value{
			"key_material_id":    types.StringValue(r.Get("aws_param.KeyMaterialId").String()),
			"rotation_date":      types.StringValue(r.Get("aws_param.RotationDate").String()),
			"key_material_state": types.StringValue(r.Get("aws_param.KeyMaterialState").String()),
			"import_state":       types.StringValue(r.Get("aws_param.ImportState").String()),
			"last_import_status": types.StringValue(r.Get("last_import_status").String()),
		})
		if d.HasError() {
			tflog.Warn(ctx, "Warning: could not build native rotation history summary entry object.")
			return emptyList, false
		}
		elems = append(elems, obj)
	}
	listVal, d := types.ListValue(rotationHistoryNativeSummaryElemType, elems)
	if d.HasError() {
		var diagWarn diag.Diagnostics
		diagWarn.Append(d...)
		tflog.Warn(ctx, "Warning: could not build native rotation history summary list.")
		return emptyList, false
	}
	return listVal, false
}

// fetchFullRotationHistoryJSON calls the rotations endpoint for keyID and returns the raw JSON
// response string. Returns ("", true) when the API call itself fails (apiFailed); an empty
// resources array is returned as ("", false) for the caller to handle gracefully.
func fetchFullRotationHistoryJSON(ctx context.Context, id string, client *common.Client, keyID string) (string, bool) {

	filters := url.Values{
		"skip":  []string{"0"},
		"limit": []string{"-1"},
		"sort":  []string{"-RotationDate"},
	}
	endpoint := "api/v1/cckm/aws/keys/" + keyID + "/rotations"
	rotJSON, err := client.ListWithFilters(ctx, id, endpoint, filters)
	if err != nil {
		msg := "Warning: could not fetch rotation history JSON for key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		return "", true
	}
	return rotJSON, false
}

// waitForRotationHistoryRecord polls the rotation history for keyID until an entry with a
// matching source_key_identifier appears, or until the poll budget is exhausted.
// Polling follows the same pattern as waitForMaterialRotation: an initial sleep, then up to
// maxPolls iterations separated by pollSeconds, with a token-refresh guard.
// If the API call fails on a given poll the failure is treated as transient and polling continues.
// A warning (not an error) is added to diags if the record is never found within the budget,
// because this function is called after upload-key where errors can no longer be returned.
func waitForRotationHistoryRecord(ctx context.Context, id string, client *common.Client, keyID string, sourceKeyIdentifier string, sourceKeyTier string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_key_material.go -> waitForRotationHistoryRecord]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_key_material.go -> waitForRotationHistoryRecord]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForRotationHistoryRecord] keyID: %s", keyID))

	const (
		maxPolls    = 30
		pollSeconds = shortAwsKeyOpSleep
	)

	// Give CCKM/AWS a head start before the first poll.
	time.Sleep(time.Duration(pollSeconds) * time.Second)

	for i := 0; i < maxPolls; i++ {
		list, apiFailed := fetchRotationHistoryByokFull(ctx, id, client, keyID)
		if !apiFailed {
			// Walk the entries looking for a match on source_key_identifier.
			var entries []RotationHistoryEntryFullTFSDK
			if convDiags := list.ElementsAs(ctx, &entries, false); !convDiags.HasError() {
				for _, entry := range entries {
					if entry.SourceKeyIdentifier.ValueString() == sourceKeyIdentifier {
						tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForRotationHistoryRecord] loop: %d found rotation history record for source_key_identifier: %s", i, sourceKeyIdentifier))
						return
					}
				}
			}
		}

		if i < maxPolls-1 {
			time.Sleep(time.Duration(pollSeconds) * time.Second)
		}
	}

	tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForRotationHistoryRecord] TIMED OUT after %d polls waiting for rotation history record for source_key_identifier: %s", maxPolls, sourceKeyIdentifier))

	msg := "Warning: could not confirm import material was successful - rotation history entry for source key not found within timeout."
	details := utils.ApiError(msg, map[string]interface{}{
		"key_id":                keyID,
		"source_key_identifier": sourceKeyIdentifier,
		"source_key_tier":       sourceKeyTier,
	})
	tflog.Warn(ctx, details)
	diags.AddWarning(details, "")
}

// waitForMaterialStateResolved polls rotation history for keyID until the rotation history
// entry for sourceKeyIdentifier reaches the desired state, or until the poll budget is
// exhausted. A warning (not an error) is added on timeout because the caller already
// reported the triggering API call as successful.
//
// stateField must be one of:
//   - "import_state"        - polls entry.ImportState
//   - "key_material_state"  - polls entry.KeyMaterialState
//
// Two polling modes are supported:
//   - leavingState != "", arrivingState == "": succeed when fieldVal != leavingState
//     (original behaviour - wait for the field to leave a specific state).
//   - arrivingState != "": succeed when fieldVal == arrivingState
//     (new behaviour - wait for the field to arrive at a specific state, regardless of
//     what state it was in before the call).
//
// Both leavingState and arrivingState may be set simultaneously; in that case arrivingState
// takes precedence for the success condition, and leavingState is used only in log messages.
func waitForMaterialStateResolved(ctx context.Context, id string, client *common.Client, keyID string, sourceKeyIdentifier string,
	stateField string, leavingState string, arrivingState string, diags *diag.Diagnostics) bool {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_key_material.go -> waitForMaterialStateResolved]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_key_material.go -> waitForMaterialStateResolved]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialStateResolved] enter: field: %s leavingState: %s arrivingState: %s keyID: %s srcKey: %s", stateField, leavingState, arrivingState, keyID, sourceKeyIdentifier))

	const (
		maxPolls    = 30
		pollSeconds = shortAwsKeyOpSleep
	)

	// Give CCKM/AWS a head start before the first poll.
	time.Sleep(time.Duration(pollSeconds) * time.Second)

	lastVal := "(not found)"

	for i := 0; i < maxPolls; i++ {
		list, apiFailed := fetchRotationHistoryByokFull(ctx, id, client, keyID)
		if !apiFailed {
			var entries []RotationHistoryEntryFullTFSDK
			if convDiags := list.ElementsAs(ctx, &entries, false); !convDiags.HasError() {
				foundEntry := false
				for _, entry := range entries {
					if entry.SourceKeyIdentifier.ValueString() != sourceKeyIdentifier {
						continue
					}
					tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialStateResolved] loop: %d import_state: %s key_material_state: %s", i, entry.AWSParams.ImportState.ValueString(), entry.AWSParams.KeyMaterialState.ValueString()))
					foundEntry = true
					var fieldVal string
					switch stateField {
					case "import_state":
						fieldVal = entry.AWSParams.ImportState.ValueString()
					case "key_material_state":
						fieldVal = entry.AWSParams.KeyMaterialState.ValueString()
					}
					lastVal = fieldVal
					// Success condition: arrivingState wins when set; otherwise succeed on leaving leavingState.
					resolved := false
					if arrivingState != "" {
						resolved = fieldVal == arrivingState
					} else {
						resolved = fieldVal != leavingState
					}
					if resolved {
						tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialStateResolved] resolved loop: %d field: %s value: %s keyID: %s srcKey: %s", i, stateField, fieldVal, keyID, sourceKeyIdentifier))
						return true
					}
					// Not yet resolved - keep polling.
				}
				if !foundEntry {
					tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialStateResolved] loop: %d TIMED OUT waiting for entry in history (total entries=%d) keyID: %s sourceKeyID: %s", i, len(entries), keyID, sourceKeyIdentifier))
				}
			}
		}

		if i < maxPolls-1 {
			time.Sleep(time.Duration(pollSeconds) * time.Second)
		}
	}

	// Build a meaningful timeout message from whichever params are set.
	waitDesc := ""
	if arrivingState != "" {
		waitDesc = "arrive at " + arrivingState
	} else {
		waitDesc = "leave " + leavingState
	}
	tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialStateResolved] TIMED OUT after %d loops. field: %s lastValue: %s waitDesc: %s keyID: %s sourceKeyID: %s", maxPolls, stateField, lastVal, waitDesc, keyID, sourceKeyIdentifier))
	msg := "Warning: could not confirm key material state resolved - rotation history entry for source key did not " + waitDesc + " after timeout."
	details := utils.ApiError(msg, map[string]interface{}{
		"key_id":                keyID,
		"source_key_identifier": sourceKeyIdentifier,
		"state_field":           stateField,
	})
	tflog.Warn(ctx, details)
	diags.AddWarning(details, "")
	return false
}

// waitForReplicasMaterialCurrent waits for every replica key in a multi-region set to
// have its key_material_state reach CURRENT. It is called after rotate-material succeeds
// on the primary during Create so that the resource is not saved to state until all
// replicas have received and activated the new material.
//
// primaryKeyJSON is the full JSON response for the primary key, already fetched before
// rotate-material was called. sourceKeyID is the CM source key identifier from the single
// key_material entry on create, used as the sourceKeyIdentifier when polling history.
//
// Replica lookup failures and individual poll timeouts are added as warnings only - the
// key was already created and rotate-material already called, so we must save state.
func waitForReplicasMaterialCurrent(ctx context.Context, id string, client *common.Client, primaryKeyID string, sourceKeyID string, primaryKeyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_key_material.go -> waitForReplicasMaterialCurrent]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_key_material.go -> waitForReplicasMaterialCurrent]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForReplicasMaterialCurrent] keyID: %s", primaryKeyID))

	replicaKeysResult := gjson.Get(primaryKeyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys")
	if !replicaKeysResult.Exists() || len(replicaKeysResult.Array()) == 0 {
		tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForReplicasMaterialCurrent] no replica keys found for primary keyID: %s", primaryKeyID))
		return
	}

	for _, replicaResult := range replicaKeysResult.Array() {

		replicaARN := replicaResult.Get("Arn").String()
		replicaRegion := replicaResult.Get("Region").String()
		if replicaARN == "" || replicaRegion == "" {
			tflog.Warn(ctx, "waitForReplicasMaterialCurrent: replica entry missing Arn or Region, skipping.")
			continue
		}

		// Extract the AWS key ID from the ARN (last path segment after "/").
		// ARN format: arn:aws:kms:<region>:<account>:key/<key-id>
		arnParts := strings.Split(replicaARN, ":")
		if len(arnParts) < 6 {
			tflog.Warn(ctx, fmt.Sprintf("waitForReplicasMaterialCurrent: Skipping replica CURRENT wait, unexpected replica ARN format: arn: %s", replicaARN))
			continue
		}
		kidParts := strings.Split(arnParts[5], "/")
		if len(kidParts) < 2 {
			tflog.Warn(ctx, fmt.Sprintf("waitForReplicasMaterialCurrent: Skipping replica CURRENT wait, could not extract key ID from replica ARN. arn: %s", replicaARN))
			continue
		}
		awsKeyID := kidParts[len(kidParts)-1]

		// Look up the replica key in CipherTrust Manager.
		filters := url.Values{}
		filters.Add("keyid", awsKeyID)
		filters.Add("region", replicaRegion)
		listJSON, listErr := client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
		if listErr != nil {
			tflog.Warn(ctx, fmt.Sprintf("waitForReplicasMaterialCurrent: Skipping replica CURRENT wait: error looking up replica key in CipherTrust Manager. arn: %s", replicaARN))
			continue
		}
		total := gjson.Get(listJSON, "total").Int()
		if total == 0 {
			tflog.Warn(ctx, fmt.Sprintf("waitForReplicasMaterialCurrent: Skipping replica CURRENT wait: replica key not found in CipherTrust Manager. arn: %s", replicaARN))
			continue
		}
		replicaCMKeyID := gjson.Get(listJSON, "resources.0.id").String()
		if replicaCMKeyID == "" {
			tflog.Warn(ctx, fmt.Sprintf("waitForReplicasMaterialCurrent: Skipping replica CURRENT wait: could not determine CipherTrust Manager key ID for replica. arn: %s", replicaARN))
			continue
		}

		waitForMaterialStateResolved(ctx, id, client, replicaCMKeyID, sourceKeyID, "key_material_state", "", "CURRENT", diags)
	}
}

// waitForMaterialRotation polls the rotate-material/status endpoint until overall_status is
// "success" or "failed", or until 30 polls x shortAwsKeyOpSleep seconds have elapsed.
// Returns true when the caller should continue (success or timeout), false on a hard failure:
//   - true when overall_status is "success"
//   - true when the timeout is reached (rotation may still complete asynchronously)
//   - false when overall_status is "failed" and error_details does NOT contain
//     "key material already exists" (an error is added to diags)
//   - false when overall_status is "failed" and error_details contains
//     "key material already exists" (a warning is added to diags, not an error)
func waitForMaterialRotation(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) bool {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_key_material.go -> waitForMaterialRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_key_material.go -> waitForMaterialRotation]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialRotation] keyID: %s", keyID))

	const (
		maxPolls    = 30
		pollSeconds = shortAwsKeyOpSleep
	)

	statusURL := keyID + "/rotate-material/status"

	// Give CCKM/AWS a head start before the first poll.
	time.Sleep(time.Duration(pollSeconds) * time.Second)

	var (
		err           error
		response      string
		overallStatus string
	)

	// Retry if acceptable error message and try to recover
	retryOperation := false

	for i := 0; i < maxPolls; i++ {
		response, err = client.GetById(ctx, id, statusURL, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error reading rotate-material status while waiting for material rotation."
			details := utils.ApiError(msg, map[string]interface{}{
				"error":  err.Error(),
				"key_id": keyID,
			})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return retryOperation
		}

		overallStatus = gjson.Get(response, "overall_status").String()
		tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialRotation] loop: %d overallStatus: %s", i, overallStatus))

		if strings.EqualFold(overallStatus, "success") {
			return retryOperation
		}
		if strings.EqualFold(overallStatus, "failed") {
			errorDetails := gjson.Get(response, "error_details").String()
			if strings.Contains(errorDetails, materialAlreadyExistsError) {
				tflog.Warn(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialRotation] key material already exists. error: %s", errorDetails))
				msg := "AWS key material rotation reported failure: key material already exists."
				details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "error_details": errorDetails})
				tflog.Warn(ctx, details)
				retryOperation = true
				return retryOperation
			}
			if strings.Contains(errorDetails, materialHasNotBeenImportedError) {
				tflog.Warn(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialRotation] material has not been imported (to replica). error: %s", errorDetails))
				msg := "AWS key material rotation reported failure: material has not been imported to replica."
				details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "error_details": errorDetails})
				tflog.Warn(ctx, details)
				retryOperation = true
				return retryOperation
			}
			msg := "AWS key material rotation failed."
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "error_details": errorDetails})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return retryOperation
		}
		if i < maxPolls-1 {
			time.Sleep(time.Duration(pollSeconds) * time.Second)
		}
	}
	tflog.Warn(ctx, fmt.Sprintf("[aws_key_material.go -> waitForMaterialRotation] TIMED OUT waiting for AWS key material rotation to complete after %d loops. Last overall_status: '%s'", maxPolls, overallStatus))
	msg := fmt.Sprintf("TIMED OUT waiting for AWS key material rotation to complete after %d loops. Last overall_status: '%s'", maxPolls, overallStatus)
	details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
	tflog.Warn(ctx, details)
	retryOperation = true
	return retryOperation
}

// keyRefreshTarget holds the snapshot data for one key (primary or replica) used by
// RefreshKeyAndWait to detect when CCKM has completed a refresh from AWS.
type keyRefreshTarget struct {
	cmKeyID string
	// sentinelSourceKeyID is the source_key_identifier of the rotation record used as the
	// change sentinel. Empty string means the first record in history was used as fallback
	// because no plan-known source key matched.
	sentinelSourceKeyID string
	// sentinelUpdatedAt is the updatedAt value of the sentinel record before the refresh
	// call. The poll loop watches for this value to change.
	sentinelUpdatedAt string
	// untrackable is true when the key had no rotation history at snapshot time.
	// The wait is skipped for untrackable keys; a warning is added instead.
	untrackable bool
}

// RefreshKeyAndWait calls the CCKM refresh API on cmKeyID (the primary CM key ID) and then
// polls until the rotation history's sentinel record updatedAt changes for all tracked keys
// (primary + known MR replicas). This ensures the provider works from AWS-current data on
// entry to the Update material-operation phases, rather than potentially stale CCKM cache.
//
// knownSrcIDs is the set of source_key_identifier values from the plan's key_material entries.
// It guides sentinel selection - see snapshotKeyForRefresh.
//
// keyJSON is the full CM key record for cmKeyID (already fetched by the caller). It is used
// to detect multi-region primary keys and enumerate replicas so they can also be tracked.
//
// POST refresh failure is a hard error. Poll timeouts are warnings only.
func RefreshKeyAndWait(ctx context.Context, id string, client *common.Client, keyID string, keyJSON string, knownSrcIDs []string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_key_material.go -> RefreshKeyAndWait]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_key_material.go -> RefreshKeyAndWait]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> RefreshKeyAndWait] keyID: %s knownSrcIDs: %v", keyID, knownSrcIDs))

	knownSet := make(map[string]struct{}, len(knownSrcIDs))
	for _, s := range knownSrcIDs {
		if s != "" {
			knownSet[s] = struct{}{}
		}
	}

	// A snapshot rotation history for primary and each known replica.
	var targets []keyRefreshTarget

	targets = append(targets, snapshotKeyForRefresh(ctx, id, client, keyID, knownSet))

	isMRPrimary := gjson.Get(keyJSON, "aws_param.MultiRegion").Bool() &&
		gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String() == "PRIMARY"
	if isMRPrimary {
		replicaKeysResult := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys")
		for _, replicaResult := range replicaKeysResult.Array() {
			replicaARN := replicaResult.Get("Arn").String()
			replicaRegion := replicaResult.Get("Region").String()
			if replicaARN == "" || replicaRegion == "" {
				continue
			}
			arnParts := strings.Split(replicaARN, ":")
			if len(arnParts) < 6 {
				continue
			}
			kidParts := strings.Split(arnParts[5], "/")
			if len(kidParts) < 2 {
				continue
			}
			awsKeyID := kidParts[len(kidParts)-1]
			filters := url.Values{}
			filters.Add("keyid", awsKeyID)
			filters.Add("region", replicaRegion)
			listJSON, listErr := client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
			if listErr != nil {
				msg := "RefreshKeyAndWait: could not look up replica key - skipping from refresh tracking."
				details := utils.ApiError(msg, map[string]interface{}{"error": listErr.Error(), "key_id": awsKeyID, "region": replicaRegion})
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
				continue
			}
			total := gjson.Get(listJSON, "total").Int()
			if total == 0 {
				msg := "RefreshKeyAndWait: replica key not found in CM - skipping from refresh tracking."
				details := utils.ApiError(msg, map[string]interface{}{"key_id": awsKeyID, "region": replicaRegion})
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
				continue
			}
			replicaCMKeyID := gjson.Get(listJSON, "resources.0.id").String()
			if replicaCMKeyID == "" {
				continue
			}
			targets = append(targets, snapshotKeyForRefresh(ctx, id, client, replicaCMKeyID, knownSet))
		}
	}

	// Call refresh on the primary key. This is a hard error because without a
	// successful refresh the subsequent material operations may act on stale data.
	_, refreshErr := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/refresh", []byte("{}"))
	if refreshErr != nil {
		msg := "Error calling refresh on AWS key in CipherTrust Manager."
		details := utils.ApiError(msg, map[string]interface{}{"error": refreshErr.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}

	// Poll until all tracked keys show an updated sentinel updatedAt value.
	const (
		maxPolls    = 30
		pollSeconds = shortAwsKeyOpSleep
	)

	done := make([]bool, len(targets))

	// Untrackable keys (no history at snapshot time) cannot be polled - warn and skip.
	for i, t := range targets {
		if t.untrackable {
			done[i] = true
			msg := "RefreshKeyAndWait: key had no rotation history at snapshot time - cannot confirm refresh completed."
			details := utils.ApiError(msg, map[string]interface{}{"key_id": t.cmKeyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		}
	}

	allDone := func() bool {
		for _, d := range done {
			if !d {
				return false
			}
		}
		return true
	}

	if allDone() {
		return
	}

	// Initial sleep to give CCKM/AWS time to process the refresh.
	time.Sleep(time.Duration(pollSeconds) * time.Second)

	for i := 0; i < maxPolls; i++ {
		for ti, t := range targets {
			if done[ti] {
				continue
			}
			rotJSON, apiFailed := fetchFullRotationHistoryJSON(ctx, id, client, t.cmKeyID)
			if apiFailed {
				continue
			}
			resources := gjson.Get(rotJSON, "resources").Array()
			if len(resources) == 0 {
				continue
			}
			for _, res := range resources {
				srcID := res.Get("source_key_identifier").String()
				// When sentinelSourceKeyID is non-empty, skip until the matching entry.
				// When it is empty (fallback sentinel), the first resource is always used.
				if t.sentinelSourceKeyID != "" && srcID != t.sentinelSourceKeyID {
					continue
				}
				newUpdatedAt := res.Get("updatedAt").String()
				if newUpdatedAt != t.sentinelUpdatedAt {
					done[ti] = true
				}
				tflog.Debug(ctx, fmt.Sprintf("[aws_key_material.go -> RefreshKeyAndWait] loop: %d oldUpdatedAt: %s newUpdatedAt: %s changed: %t", i, t.sentinelUpdatedAt, newUpdatedAt, done[ti]))
				break
			}
		}

		if allDone() {
			tflog.Info(ctx, fmt.Sprintf("[aws_key_material.go -> RefreshKeyAndWait] all keys confirmed refreshed after %d polls", i+1))
			return
		}
		if i < maxPolls-1 {
			time.Sleep(time.Duration(pollSeconds) * time.Second)
		}
	}

	// Timeout: add a warning for each key that did not show an updated sentinel record.
	for ti, t := range targets {
		if !done[ti] {
			msg := fmt.Sprintf("RefreshKeyAndWait: timed out after %d polls waiting for rotation history to reflect key refresh.", maxPolls)
			details := utils.ApiError(msg, map[string]interface{}{
				"key_id":              t.cmKeyID,
				"sentinel_source_key": t.sentinelSourceKeyID,
				"sentinel_updated_at": t.sentinelUpdatedAt,
			})
			tflog.Warn(ctx, fmt.Sprintf("RefreshKeyAndWait: TIMED OUT after %d polls waiting for rotation history to reflect key refresh.", maxPolls))
			diags.AddWarning(details, "")
		}
	}
}

// snapshotKeyForRefresh fetches the rotation history for cmKeyID using raw JSON and builds a
// keyRefreshTarget whose sentinel record is selected as follows:
//   - Walk history resources (most-recent first).
//   - Return the first resource whose source_key_identifier is in knownSrcIDs.
//   - If no resource matches, use the first (most-recent) resource as an out-of-band fallback
//     (sentinelSourceKeyID will be empty to signal "use first entry" during polling).
//   - If history is empty or the API fails, mark the target as untrackable.
func snapshotKeyForRefresh(ctx context.Context, id string, client *common.Client, cmKeyID string, knownSrcIDs map[string]struct{}) keyRefreshTarget {
	target := keyRefreshTarget{cmKeyID: cmKeyID}
	rotJSON, apiFailed := fetchFullRotationHistoryJSON(ctx, id, client, cmKeyID)
	if apiFailed {
		target.untrackable = true
		return target
	}
	resources := gjson.Get(rotJSON, "resources").Array()
	if len(resources) == 0 {
		target.untrackable = true
		return target
	}
	// Prefer an entry whose source key is known to the plan.
	for _, res := range resources {
		srcID := res.Get("source_key_identifier").String()
		if _, ok := knownSrcIDs[srcID]; ok {
			target.sentinelSourceKeyID = srcID
			target.sentinelUpdatedAt = res.Get("updatedAt").String()
			return target
		}
	}
	// Fallback: use the most-recent entry regardless of source key.
	// sentinelSourceKeyID stays empty - the poll loop uses the first resource.
	target.sentinelUpdatedAt = resources[0].Get("updatedAt").String()
	return target
}
