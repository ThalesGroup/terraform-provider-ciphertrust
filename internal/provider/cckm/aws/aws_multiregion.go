package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/tidwall/gjson"
)

// mrKeyRefreshLimitationNote is appended to schema descriptions for attributes that trigger
// update-primary-region. On CM < 2.22 individual key refresh (POST .../refresh) is not
// available, so multi-region configuration in Terraform state may be stale after the
// primary-region change until a KMS-wide synchronization is run.
const mrKeyRefreshLimitationNote = " On CipherTrust Manager versions earlier than 2.22," +
	" keys in the multi-region set may not reflect the correct multi-region configuration" +
	" in Terraform state after this operation. Individual key refresh was not introduced" +
	" until CM 2.22. To synchronize state, trigger a KMS-wide synchronization using a" +
	" ciphertrust_scheduler resource with operation = \"cckm_synchronization\"," +
	" then run terraform refresh."

// replicateKeyCommon calls the replicate-key API, waits for the replica to leave Creating state,
// waits for it to reach Enabled state, optionally promotes it to primary, and returns the final
// key JSON from a fresh GET. origin should be "AWS_KMS" for native keys or "EXTERNAL" for BYOK keys.
// The initial POST is a hard error; all subsequent steps produce only warnings.
func replicateKeyCommon(
	ctx context.Context,
	id string,
	client *common.Client,
	replicateKeyPlan *AWSReplicateKeyTFSDK,
	replicaRegion string,
	origin string,
	awsParams CommonAWSParamsJSON,
	keyPolicy *AWSKeyPolicyTFSDK,
	diags *diag.Diagnostics,
) string {
	client.Log.Debug(common.MSG_METHOD_START + "[aws_multiregion.go -> replicateKeyCommon][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[aws_multiregion.go -> replicateKeyCommon][" + id + "]")

	client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> replicateKeyCommon] region: %s", replicaRegion))

	primaryKeyID := replicateKeyPlan.KeyID.ValueString()
	kp := getKeyPolicyParams(ctx, keyPolicy, diags)
	if diags.HasError() {
		return ""
	}
	payload := CreateReplicaKeyPayloadJSON{
		AWSParams: AWSKeyParamJSON{
			CommonAWSParamsJSON: awsParams,
			Origin:              origin,
		},
		ExternalAccounts: kp.ExternalAccounts,
		KeyAdmins:        kp.KeyAdmins,
		KeyAdminsRoles:   kp.KeyAdminsRoles,
		KeyUsers:         kp.KeyUsers,
		KeyUsersRoles:    kp.KeyUsersRoles,
		PolicyTemplate:   kp.PolicyTemplate,
		ReplicaRegion:    &replicaRegion,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key. Failed to replicate key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"region":         replicaRegion,
		})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> replicateKeyCommon] Replicating AWS key %s to region %s", primaryKeyID, replicaRegion))
	replicaKeyResponse, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/replicate-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to replicate key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"region":         replicaRegion,
		})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}

	// Don't return errors after this

	replicaKeyID := gjson.Get(replicaKeyResponse, "id").String()
	client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> replicateKeyCommon] Replica key created, id: %s, region: %s", replicaKeyID, replicaRegion))
	// Keep the initial POST response as a fallback so we can always return a response
	// that contains the replica key ID, even if later polling steps fail.
	initialReplicaKeyResponse := replicaKeyResponse
	var waitForReplicationDiags diag.Diagnostics
	waitForReplication(ctx, id, client, replicaKeyID, &waitForReplicationDiags)
	if waitForReplicationDiags.HasError() {
		for _, d := range waitForReplicationDiags {
			diags.AddWarning(d.Summary(), d.Detail())
		}
		return initialReplicaKeyResponse
	}
	// Debug: read primary key and log its JSON before waiting for replica to become Enabled.
	primaryKeyJSON, err := client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
	if err != nil || primaryKeyJSON == "" {
		errMsg := "unknown error"
		if err != nil {
			errMsg = err.Error()
		}
		msg := "Error replicating AWS key, failed to read primary key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          errMsg,
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		client.Log.Error(details)
		diags.AddWarning(details, "")
		return initialReplicaKeyResponse
	}

	sourceKeyID := gjson.Get(primaryKeyJSON, "local_key_id").String()
	sourceKeyTier := gjson.Get(primaryKeyJSON, "source_key_tier").String()

	var replicateDiags diag.Diagnostics
	if origin == "EXTERNAL" && sourceKeyID != "" {

		// For BYOK replicas, wait for ALL primary key materials to appear on the replica with
		// import_state=IMPORTED before checking Enabled state. This ensures that all materials
		//  have fully settled, preventing a false CURRENT state on older materials
		waitForAllMaterialsImportedToReplica(ctx, id, client, primaryKeyID, replicaKeyID, &replicateDiags)

		// Only poll for Enabled if material actually landed on the replica.
		// If the import failed entirely (e.g. replica was still in Creating state),
		// replicaHasRotationHistoryEntry returns false and we go straight to the
		// PendingImport compensation path - saving 30 x poll-sleep of wasted time.
		// When an entry exists (including PENDING_IMPORT), we still poll for Enabled
		// normally so the compensation path can fire if needed.
		var firstEnabledDiags diag.Diagnostics
		var firstEnabledResponse string
		replicaEntryPresent := replicaHasRotationHistoryEntry(ctx, id, client, replicaKeyID, sourceKeyID)
		if replicaEntryPresent {
			firstEnabledResponse = waitForReplicatedKeyIsEnabled(ctx, id, client, replicaKeyID, &firstEnabledDiags)
		}

		if !replicaEntryPresent || gjson.Get(firstEnabledResponse, "aws_param.KeyState").String() != "Enabled" {
			// Replica is not yet Enabled. Re-fetch to check the current key state.
			replicaKeyJSON, getErr := client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
			replicaKeyState := ""
			if getErr == nil {
				replicaKeyState = gjson.Get(replicaKeyJSON, "aws_param.KeyState").String()
			}

			if replicaKeyState == "PendingImport" {
				// CCKM failed to import material to the replica (likely because the replica was
				// still in Creating state when CCKM attempted the import). Compensate by
				// importing all primary key materials directly to the replica, then re-wait.
				client.Log.Warn(fmt.Sprintf(
					"[aws_multiregion.go -> replicateKeyCommon] Replica key %s is still PendingImport. "+
						"CCKM may have failed to push material (eg: replica was still in Creating state). "+
						"Compensating: importing all primary key materials directly.",
					replicaKeyID))

				importAllMaterialsToReplica(ctx, id, client, primaryKeyID, replicaKeyID, &replicateDiags)

				// waitForRotationHistoryRecord and waitForMaterialStateResolved are already called
				// per-entry inside importAllMaterialsToReplica, so skipping them here.
				// waitForRotationHistoryRecord(ctx, id, client, replicaKeyID, sourceKeyID, sourceKeyTier, &historyDiags)
				// waitForMaterialStateResolved(ctx, id, client, replicaKeyID, sourceKeyID, "import_state", "", "IMPORTED", &historyDiags)
				secondEnabledResponse := waitForReplicatedKeyIsEnabled(ctx, id, client, replicaKeyID, &replicateDiags)

				if gjson.Get(secondEnabledResponse, "aws_param.KeyState").String() != "Enabled" {
					// Still not Enabled - fall back to refreshing the primary to trigger CCKM's
					// background sync, then make one final attempt at waiting for Enabled.
					sourceKeyIDs := listKeyMaterialSourceKeyIDs(ctx, id, client, primaryKeyID)
					refreshedPrimaryJSON, refreshErr := client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
					if refreshErr == nil {
						RefreshKeyAndWait(ctx, id, client, primaryKeyID, refreshedPrimaryJSON, sourceKeyIDs, &replicateDiags)
					}
					waitForReplicatedKeyIsEnabled(ctx, id, client, replicaKeyID, &replicateDiags)
				}
			} else {
				// Replica is not PendingImport (some other transient state). Use the existing
				// refresh-primary approach to trigger CCKM's background sync and retry.
				sourceKeyIDs := listKeyMaterialSourceKeyIDs(ctx, id, client, primaryKeyID)
				refreshedPrimaryJSON, refreshErr := client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
				if refreshErr == nil {
					RefreshKeyAndWait(ctx, id, client, primaryKeyID, refreshedPrimaryJSON, sourceKeyIDs, &replicateDiags)
				}
				waitForReplicatedKeyIsEnabled(ctx, id, client, replicaKeyID, &replicateDiags)
			}
		}
	} else {
		// For native (AWS_KMS) replica keys there is no material import; just wait for Enabled.
		waitForReplicatedKeyIsEnabled(ctx, id, client, replicaKeyID, &replicateDiags)
		if sourceKeyID != "" {
			waitForRotationHistoryRecord(ctx, id, client, replicaKeyID, sourceKeyID, sourceKeyTier, &replicateDiags)
		}
	}

	// Wait for all existing keys in the MR set to reflect the new replica region.
	// The CM forks a background task per key after replicate-key completes; this ensures
	// those tasks finish before the caller makes any subsequent multi-region key call.
	waitForReplicaRegionInAllMRKeys(ctx, id, client, primaryKeyID, replicaRegion, replicaKeyID, &replicateDiags)
	for _, d := range replicateDiags {
		diags.AddWarning(d.Summary(), d.Detail())
	}

	replicaKeyResponse, err = client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error creating AWS key, failed to read replicated key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		client.Log.Error(details)
		diags.AddWarning(details, "")
		return initialReplicaKeyResponse
	}

	if replicateKeyPlan.MakePrimary.ValueBool() {
		client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> replicateKeyCommon] make_primary is true, promoting replica in region %s to primary", replicaRegion))
		enabled := gjson.Get(replicaKeyResponse, "aws_param.Enabled").Bool()
		if enabled {
			// Let the newly created replica settle before making it primary
			time.Sleep(time.Duration(10) * time.Second)
			client.Log.Debug("[aws_multiregion.go -> replicateKeyCommon] replica key is enabled, proceeding with update-primary-region")
			makePrimaryDiags := diag.Diagnostics{}
			updatePrimaryRegion(ctx, id, client, primaryKeyID, replicaRegion, replicaKeyID, &makePrimaryDiags)
			diags.Append(makePrimaryDiags...)
			for _, d := range makePrimaryDiags {
				diags.AddWarning(d.Summary(), d.Detail())
			}
		} else {
			msg := "Replica key is not enabled. Unable to make it the primary key."
			details := utils.ApiError(msg, map[string]interface{}{
				"configured primary region": replicaRegion,
			})
			client.Log.Warn(details)
			diags.AddWarning(details, "")
		}
	}
	// Capture the current best response before the final GET in case it fails.
	finalFallback := replicaKeyResponse
	replicaKeyResponse, err = client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error creating AWS key, failed to read replicated key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		client.Log.Error(details)
		diags.AddWarning(details, "")
		return finalFallback
	}
	client.Log.Debug("[aws_multiregion.go -> replicateKeyCommon][response:" + redactAWSResponse(replicaKeyResponse))
	return replicaKeyResponse
}

// waitForReplication polls the replica key until its state leaves the "Creating" phase or a timeout is reached.
func waitForReplication(ctx context.Context, id string, client *common.Client, replicaKeyID string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[aws_multiregion.go -> waitForReplication][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[aws_multiregion.go -> waitForReplication][" + id + "]")
	var (
		err      error
		response string
		keyState string
	)

	// Give CCKM/AWS a head start before the first poll.
	time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
	ticker := time.NewTicker(time.Duration(shortAwsKeyOpSleep) * time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(time.Duration(110) * time.Second)
	for range ticker.C {
		if time.Now().After(deadline) {
			break
		}
		response, err = client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error creating AWS key. Error reading replicated key."
			details := utils.ApiError(msg, map[string]interface{}{
				"error":          err.Error(),
				"replica_key_id": replicaKeyID,
			})
			client.Log.Error(details)
			diags.AddWarning(details, "")
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
		client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> waitForReplication] Key state: %s", keyState))
		if keyState != "Creating" {
			client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> waitForReplication] resolved Key state: %s replicaKeyID: %s", keyState, replicaKeyID))
			client.Log.Debug("[aws_multiregion.go -> waitForReplication][response:" + redactAWSResponse(response))
			return response
		}
	}
	msg := fmt.Sprintf("Error replicating AWS key, key state is still '%s'.", keyState)
	details := utils.ApiError(msg, map[string]interface{}{"key_id": replicaKeyID})
	client.Log.Warn(details)
	diags.AddWarning(details, "")
	client.Log.Debug("[aws_multiregion.go -> waitForReplication][response:" + redactAWSResponse(response))
	return response
}

// waitForReplicatedKeyIsEnabled polls the replica key until its state reaches "Enabled" or a timeout is
// reached.
func waitForReplicatedKeyIsEnabled(ctx context.Context, id string, client *common.Client, replicaKeyID string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[aws_multiregion.go -> waitForReplicatedKeyIsEnabled][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[aws_multiregion.go -> waitForReplicatedKeyIsEnabled][" + id + "]")
	var (
		err      error
		response string
		keyState string
	)

	// time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second) // commented out to observe initial states
	ticker := time.NewTicker(time.Duration(shortAwsKeyOpSleep) * time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(time.Duration(60) * time.Second)
	loop := 0
	for range ticker.C {
		if time.Now().After(deadline) {
			break
		}
		response, err = client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error creating AWS key. Error reading replicated key."
			details := utils.ApiError(msg, map[string]interface{}{
				"error":          err.Error(),
				"replica_key_id": replicaKeyID,
			})
			client.Log.Error(details)
			diags.AddWarning(details, "")
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
		client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> waitForReplicatedKeyIsEnabled] loop: %d Key state: %s", loop, keyState))
		if keyState == "Enabled" {
			client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForReplicatedKeyIsEnabled] resolved loop: %d key is Enabled", loop))
			return response
		}
		loop++
	}
	msg := fmt.Sprintf("[aws_multiregion.go -> waitForReplicatedKeyIsEnabled] TIMED OUT waiting for Enabled, last state: '%s'.", keyState)
	details := utils.ApiError(msg, map[string]interface{}{"key_id": replicaKeyID})
	client.Log.Warn(details)
	diags.AddWarning(details, "")
	client.Log.Debug("[aws_multiregion.go -> waitForReplicatedKeyIsEnabled][response:" + redactAWSResponse(response))
	return response
}

// waitForAllMaterialsImportedToReplica waits for every key material on the primary to have a
// rotation history record on the replica with import_state=IMPORTED. It iterates oldest-to-newest
// so that each material's record is confirmed before moving on to the next. This prevents the
// provider from returning while older materials still show a transient CURRENT state on the replica.
// Failures are added as warnings (not errors) since the replicate-key call already succeeded.
func waitForAllMaterialsImportedToReplica(
	ctx context.Context,
	id string,
	client *common.Client,
	primaryKeyID string,
	replicaKeyID string,
	diags *diag.Diagnostics,
) {
	client.Log.Debug(common.MSG_METHOD_START + "[aws_multiregion.go -> waitForAllMaterialsImportedToReplica][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[aws_multiregion.go -> waitForAllMaterialsImportedToReplica][" + id + "]")

	primaryHistory, apiFailed := fetchRotationHistoryByokFull(ctx, id, client, primaryKeyID)
	if apiFailed {
		msg := "waitForAllMaterialsImportedToReplica: failed to fetch primary key rotation history."
		details := utils.ApiError(msg, map[string]interface{}{"primary_key_id": primaryKeyID})
		client.Log.Warn(details)
		diags.AddWarning(details, "")
		return
	}

	var entries []RotationHistoryEntryFullTFSDK
	if convDiags := primaryHistory.ElementsAs(ctx, &entries, false); convDiags.HasError() {
		msg := "waitForAllMaterialsImportedToReplica: failed to read primary key rotation history entries."
		details := utils.ApiError(msg, map[string]interface{}{"primary_key_id": primaryKeyID})
		client.Log.Warn(details)
		diags.AddWarning(details, "")
		return
	}

	if len(entries) == 0 {
		client.Log.Debug("[aws_multiregion.go -> waitForAllMaterialsImportedToReplica] no rotation history on primary, nothing to wait for")
		return
	}

	// Reverse to process oldest-to-newest (API returns newest-first).
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	for idx, entry := range entries {
		srcID := entry.SourceKeyIdentifier.ValueString()
		srcTier := entry.KeySource.ValueString()
		if srcID == "" {
			client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> waitForAllMaterialsImportedToReplica] entry[%d]: source_key_identifier empty, skipping", idx))
			continue
		}
		client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForAllMaterialsImportedToReplica] entry[%d]: waiting for srcID: %s to be IMPORTED on replica: %s", idx, srcID, replicaKeyID))
		waitForRotationHistoryRecord(ctx, id, client, replicaKeyID, srcID, srcTier, diags)
		waitForMaterialStateResolved(ctx, id, client, replicaKeyID, srcID, "import_state", "", "IMPORTED", diags)
	}

	client.Log.Debug("[aws_multiregion.go -> waitForAllMaterialsImportedToReplica] done")
}

// importAllMaterialsToReplica imports all key materials from the primary key to the replica key,
// in order from oldest to newest. This compensates for CCKM failing to push materials to the
// replica (e.g. because the replica was still in Creating state when CCKM attempted the import).
//
// For each rotation entry on the primary key that has a source_key_identifier:
//   - ImportByokKeyMaterial is called on the replica with EXISTING_KEY_MATERIAL.
//   - If AWS returns "is creating", the import is retried up to 5 times with a short sleep.
//   - After a successful import call, waitForRotationHistoryRecord and waitForMaterialStateResolved
//     are called on the replica to confirm the material was received before proceeding.
//
// All failures are added as warnings (not errors): the replicate-key call already succeeded and
// the caller must always save state.
func importAllMaterialsToReplica(ctx context.Context, id string, client *common.Client,
	primaryKeyID string, replicaKeyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[aws_multiregion.go -> importAllMaterialsToReplica][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[aws_multiregion.go -> importAllMaterialsToReplica][" + id + "]")

	client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> importAllMaterialsToReplica] primaryKeyID: %s replicaKeyID: %s", primaryKeyID, replicaKeyID))

	// Fetch primary rotation history (newest-first).
	primaryHistory, apiFailed := fetchRotationHistoryByokFull(ctx, id, client, primaryKeyID)
	if apiFailed {
		msg := "importAllMaterialsToReplica: failed to fetch primary key rotation history."
		details := utils.ApiError(msg, map[string]interface{}{"primary_key_id": primaryKeyID})
		client.Log.Warn(details)
		diags.AddWarning(details, "")
		return
	}

	var entries []RotationHistoryEntryFullTFSDK
	if convDiags := primaryHistory.ElementsAs(ctx, &entries, false); convDiags.HasError() {
		msg := "importAllMaterialsToReplica: failed to read primary key rotation history entries."
		details := utils.ApiError(msg, map[string]interface{}{"primary_key_id": primaryKeyID})
		client.Log.Warn(details)
		diags.AddWarning(details, "")
		return
	}

	if len(entries) == 0 {
		client.Log.Debug("[aws_multiregion.go -> importAllMaterialsToReplica] no rotation history on primary key, nothing to import")
		return
	}

	// Reverse so we process oldest-to-newest (API returns newest-first).
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}

	const (
		maxCreatingRetries = 5
		creatingRetryDelay = 10 // seconds
	)

	for idx, entry := range entries {
		srcID := entry.SourceKeyIdentifier.ValueString()
		srcTier := entry.KeySource.ValueString()
		if srcID == "" || srcTier == "" {
			client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> importAllMaterialsToReplica] entry[%d]: source_key_identifier or source_key_tier empty, skipping", idx))
			continue
		}

		client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> importAllMaterialsToReplica] entry[%d]: importing srcID: %s srcTier: %s to replicaKeyID: %s", idx, srcID, srcTier, replicaKeyID))

		// CM 2.23 rejects import_type for MR replica keys ("only supported for single region AES key.").
		// Suppress it by passing an empty string; ImportByokKeyMaterial omits the field when empty.
		importType := "EXISTING_KEY_MATERIAL"
		if !client.IsCDSPaaS && client.CMVersion < 224 {
			importType = ""
		}

		// Retry the import when AWS rejects with "is creating" (replica not yet fully provisioned).
		imported := false
		for attempt := 0; attempt < maxCreatingRetries; attempt++ {
			if attempt > 0 {
				client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> importAllMaterialsToReplica] entry[%d]: retry attempt %d for srcID: %s", idx, attempt, srcID))
				time.Sleep(time.Duration(creatingRetryDelay) * time.Second)
			}
			var importDiags diag.Diagnostics
			ImportByokKeyMaterial(ctx, id, client, replicaKeyID, srcID, srcTier, "", "", importType, &importDiags)
			if !importDiags.HasError() {
				imported = true
				break
			}
			// Check if the error is "is creating" - if so, retry; otherwise break immediately.
			retryable := false
			for _, d := range importDiags {
				if strings.Contains(d.Summary(), "is creating") || strings.Contains(d.Detail(), "is creating") {
					retryable = true
					break
				}
			}
			if !retryable {
				// Non-retryable error - log as warning and move on.
				for _, d := range importDiags {
					diags.AddWarning(d.Summary(), d.Detail())
				}
				break
			}
			client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> importAllMaterialsToReplica] entry[%d]: replica still in Creating state, will retry (attempt %d/%d). srcID: %s", idx, attempt+1, maxCreatingRetries, srcID))
		}

		if !imported {
			client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> importAllMaterialsToReplica] entry[%d]: could not import srcID: %s after retries, continuing to next entry", idx, srcID))
			continue
		}

		// Wait for the rotation history record to appear on the replica.
		waitForRotationHistoryRecord(ctx, id, client, replicaKeyID, srcID, srcTier, diags)

		// Wait for import_state to reach IMPORTED before importing the next material.
		waitForMaterialStateResolved(ctx, id, client, replicaKeyID, srcID, "import_state", "", "IMPORTED", diags)
	}

	client.Log.Debug("[aws_multiregion.go -> importAllMaterialsToReplica] done")
}

// waitForReplicaRegionInAllMRKeys polls every key already in the MR set (the primary plus
// all prior replicas, excluding the new replica itself which will not list its own region)
// until they all show replicaRegion in aws_param.MultiRegionConfiguration.ReplicaKeys.
//
// This ensures the CM's background task that propagates the new replica region to each
// existing key has finished before the caller returns. Without this wait, a subsequent
// update-primary-region call may read a stale replica list from the primary and only fork
// background update tasks for a subset of the existing replicas.
//
// On inner-loop timeout, refreshKeysForReplicaRegion is called on each unconfirmed key to
// force CM to re-sync from AWS. Failures are added as warnings (the replicate-key call
// already succeeded).
func waitForReplicaRegionInAllMRKeys(
	ctx context.Context,
	id string,
	client *common.Client,
	primaryKeyID string,
	replicaRegion string,
	replicaKeyID string,
	diags *diag.Diagnostics,
) {
	client.Log.Debug(common.MSG_METHOD_START + "[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys][" + id + "]")

	const maxInner = 30

	// Read primary to get the MRK key ID and the set of prior replicas.
	primaryJSON, err := client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "waitForReplicaRegionInAllMRKeys: failed to read primary key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "primary_key_id": primaryKeyID})
		client.Log.Warn(details)
		diags.AddWarning(details, "")
		return
	}
	awsMrkKeyID := gjson.Get(primaryJSON, "aws_param.KeyId").String()

	// Build poll set: primary + all prior replicas (skip the new replica - it will not list itself).
	allKeyIDs := []string{primaryKeyID}
	for _, rk := range gjson.Get(primaryJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array() {
		region := rk.Get("Region").String()
		if region == "" || region == replicaRegion {
			continue
		}
		localDiags := diag.Diagnostics{}
		cmID := findKeyCMIDByRegion(ctx, id, client, awsMrkKeyID, region, &localDiags)
		if cmID == "" {
			client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] could not find replica CCKM ID for region %s - skipping", region))
			continue
		}
		if cmID == replicaKeyID {
			continue
		}
		allKeyIDs = append(allKeyIDs, cmID)
	}

	client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] polling %d keys for new replica region %s", len(allKeyIDs), replicaRegion))

	confirmed := make([]bool, len(allKeyIDs))
	allConfirmed := func() bool {
		for _, c := range confirmed {
			if !c {
				return false
			}
		}
		return true
	}

	for loop := 0; loop < maxInner; loop++ {
		for i, keyID := range allKeyIDs {
			if confirmed[i] {
				continue
			}
			keyJSON, getErr := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
			if getErr != nil {
				client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] transient error reading key %s: %s",
					keyID, getErr.Error()))
				continue
			}
			for _, rk := range gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array() {
				if rk.Get("Region").String() == replicaRegion {
					client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] loop: %d found region: %s key: %s",
						loop, replicaRegion, keyID))
					confirmed[i] = true
					break
				}
			}
		}
		if allConfirmed() {
			client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] loop: %d All keys contain region: %s",
				loop, replicaRegion))
			return
		}
		time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
	}

	// Inner loop exhausted - call /refresh on each unconfirmed key and re-check.
	// CCKM saves the refreshed key synchronously before returning, so the GET after
	// each refresh call reflects current AWS state. Sleep between attempts gives AWS
	// additional time if the transition is still in progress.
	client.Log.Info("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] wait loop exhausted - refreshing unconfirmed keys")
	const refreshAttemptsReplica = 6
	const refreshSleepReplica = 10
	for loop := 0; loop < refreshAttemptsReplica; loop++ {
		for i, keyID := range allKeyIDs {
			if confirmed[i] {
				continue
			}
			_, refreshErr := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/refresh", []byte("{}"))
			if refreshErr != nil {
				client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] refresh loop %d: error refreshing key %s: %s",
					loop, keyID, refreshErr.Error()))
			}
			keyJSON, getErr := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
			if getErr != nil {
				client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] refresh loop %d: error reading key %s: %s",
					loop, keyID, getErr.Error()))
				continue
			}
			for _, replica := range gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array() {
				if replica.Get("Region").String() == replicaRegion {
					client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] refresh loop %d found region: %s key: %s",
						loop, replicaRegion, keyID))
					confirmed[i] = true
					break
				}
			}
		}
		if allConfirmed() {
			client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] refresh loop: %d All keys contain replica region %s",
				loop, replicaRegion))
			return
		}
		if loop < refreshAttemptsReplica-1 {
			time.Sleep(time.Duration(refreshSleepReplica) * time.Second)
		}
	}

	for i, keyID := range allKeyIDs {
		if !confirmed[i] {
			msg := fmt.Sprintf("waitForReplicaRegionInAllMRKeys: TIMED OUT waiting for region %s to appear in key %s.", replicaRegion, keyID)
			details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "replica_region": replicaRegion})
			client.Log.Warn(details)
			diags.AddWarning(details, "")
		}
	}
}

// updatePrimaryRegion changes the primary region of a multi-region AWS key and polls until the change
// is confirmed on ALL keys in the MR set.
//
// CCKM forks a background task after the update-primary-region API returns: it polls AWS separately for
// the old primary AND each replica. We mirror that behaviour by collecting the CCKM IDs of every key in
// the set (old primary + all replicas) before making the API call, then waiting in a single loop until
// every key reports the correct PrimaryKey.Region. Additionally:
//   - the new primary (newPrimaryKeyID) must report MultiRegionKeyType == "PRIMARY"
//   - the old primary (primaryKeyID) must report MultiRegionKeyType == "REPLICA"
func updatePrimaryRegion(ctx context.Context, id string, client *common.Client, primaryKeyID string, newPrimaryRegion string, newPrimaryKeyID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[aws_multiregion.go -> updatePrimaryRegion][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[aws_multiregion.go -> updatePrimaryRegion][" + id + "]")

	client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> updatePrimaryRegion] newPrimaryRegion: %s newPrimaryKeyID: %s", newPrimaryRegion, newPrimaryKeyID))

	// Step 1: read the current primary to discover all keys in the MR set.
	// awsMrkKeyID is the shared mrk-xxx key ID present on all keys in the set (aws_param.KeyId).
	// Each entry in ReplicaKeys has a Region field we use to look up the replica's CCKM UUID.
	primaryKeyJSON, readErr := client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
	if readErr != nil {
		msg := "Error updating primary region, failed to read primary key."
		details := utils.ApiError(msg, map[string]interface{}{"error": readErr.Error(), "key_id": primaryKeyID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	awsMrkKeyID := gjson.Get(primaryKeyJSON, "aws_param.KeyId").String()

	// allKeyIDs holds the CCKM UUIDs of every key we need to poll: old primary + all replicas.
	allKeyIDs := []string{primaryKeyID}
	for _, replicaResult := range gjson.Get(primaryKeyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array() {
		replicaRegion := replicaResult.Get("Region").String()
		if replicaRegion == "" {
			continue
		}
		// Use a local diags so a lookup failure is a warning, not a hard error.
		localDiags := diag.Diagnostics{}
		replicaCMID := findKeyCMIDByRegion(ctx, id, client, awsMrkKeyID, replicaRegion, &localDiags)
		if replicaCMID == "" {
			client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> updatePrimaryRegion] could not find replica key in CCKM for region %s - skipping from poll set", replicaRegion))
			continue
		}
		allKeyIDs = append(allKeyIDs, replicaCMID)
	}

	// Ensure newPrimaryKeyID is always in the poll set (defensive: it should already be a replica).
	newPrimaryInSet := false
	for _, kid := range allKeyIDs {
		if kid == newPrimaryKeyID {
			newPrimaryInSet = true
			break
		}
	}
	if !newPrimaryInSet {
		allKeyIDs = append(allKeyIDs, newPrimaryKeyID)
	}

	// Step 2: call update-primary-region.
	payload := UpdatePrimaryRegionPayloadJSON{
		PrimaryRegion: &newPrimaryRegion,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating primary region, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "primary key_id": primaryKeyID, "configured primary region": newPrimaryRegion})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> updatePrimaryRegion] Updating primary region of key %s to %s", primaryKeyID, newPrimaryRegion))
	_, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/update-primary-region", payloadJSON)
	if err != nil {
		if strings.Contains(err.Error(), notMultiRegionPrimaryException) {
			client.Log.Info("[aws_multiregion.go -> updatePrimaryRegion] notMultiRegionPrimaryException - retrying")
			// AWS might not have yet finished propagating a prior primary-region change.
			// Retry until the key is recognized as a primary key in AWS, or until timeout.
			retryTicker := time.NewTicker(time.Duration(shortAwsKeyOpSleep) * time.Second)
			defer retryTicker.Stop()
			retryDeadline := time.Now().Add(time.Duration(updatePrimaryRegionWaitSeconds) * time.Second)
			for range retryTicker.C {
				if time.Now().After(retryDeadline) {
					break
				}
				_, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/update-primary-region", payloadJSON)
				if err == nil || !strings.Contains(err.Error(), notMultiRegionPrimaryException) {
					break
				}
			}
		}
		if err != nil {
			msg := "Error updating primary region."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "primary key_id": primaryKeyID, "configured primary region": newPrimaryRegion})
			client.Log.Error(details)
			diags.AddError(details, "")
			return
		}
	}

	// Step 3: give CCKM/AWS a head start, then wait for all keys to confirm the primary region change.
	time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
	waitForPrimaryRegionUpdated(ctx, id, client, primaryKeyID, newPrimaryKeyID, newPrimaryRegion, allKeyIDs, diags)
}

// waitForPrimaryRegionUpdated polls all keys in the MR set until every one confirms the
// new primary region.
//
// A single inner poll loop runs up to maxInnerForPrimaryUpdate iterations. If all keys
// confirm, the function returns immediately. If the inner loop exhausts without full
// confirmation, refreshKeysForPrimaryRegion is called on each unconfirmed key to force
// CM to re-sync those keys from AWS, then one final check is logged. Warnings are added
// for any key that remains unconfirmed.
func waitForPrimaryRegionUpdated(
	ctx context.Context,
	id string,
	client *common.Client,
	primaryKeyID string,
	newPrimaryKeyID string,
	newPrimaryRegion string,
	allKeyIDs []string,
	diags *diag.Diagnostics,
) {
	const maxLoopsForPrimaryUpdate = 10

	confirmed := make([]bool, len(allKeyIDs))
	allPrimaryRegionsConfirmed := func() bool {
		for _, c := range confirmed {
			if !c {
				return false
			}
		}
		return true
	}

	client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> waitForReplicaRegionInAllMRKeys] polling %d keys for primary region update", len(allKeyIDs)))

	// Wait poll loop - read every key every iteration, even ones already confirmed.
	for loop := 0; loop < maxLoopsForPrimaryUpdate; loop++ {
		for i, keyID := range allKeyIDs {
			keyJSON, getErr := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
			if getErr != nil {
				client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] loop: %d, transient error reading key: %s, error: %s",
					loop, keyID, getErr.Error()))
				continue
			}
			primaryRegion := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
			keyType := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String()
			region := gjson.Get(keyJSON, "region").String()

			client.Log.Debug(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] loop: %d, region: %s, PrimaryKey.Region: %s, KeyType: %s, key: %s,",
				loop, region, primaryRegion, keyType, keyID))

			keyState := gjson.Get(keyJSON, "aws_param.KeyState").String()
			regionOK := primaryRegion == newPrimaryRegion
			// Both the old and new primary keys enter a transient Updating/Creating state
			// briefly after update-primary-region. Require KeyState == "Enabled" for both
			// to ensure we don't exit the wait while they are still transitioning.
			wasConfirmed := confirmed[i]
			switch keyID {
			case newPrimaryKeyID:
				confirmed[i] = regionOK && keyType == "PRIMARY" && keyState == "Enabled"
			case primaryKeyID:
				confirmed[i] = regionOK && keyType == "REPLICA" && keyState == "Enabled"
			default:
				confirmed[i] = regionOK
			}
			if !wasConfirmed && confirmed[i] {
				client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] loop: %d found primary region: %s PrimaryKey.Region: %s KeyType: %s KeyState: %s key: %s",
					loop, region, primaryRegion, keyType, keyState, keyID))
			}
		}

		if allPrimaryRegionsConfirmed() {
			client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] loop: %d All keys have new primary region %s",
				loop, newPrimaryRegion))
			return
		}
		time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
	}

	// Wait loop exhausted - call /refresh on each unconfirmed key and re-check.
	// CCKM saves the refreshed key synchronously before returning, so the GET after
	// each refresh call reflects current AWS state. Sleep between attempts gives AWS
	// additional time if the primary-region transition is still in progress.
	//
	// Individual key refresh (POST .../refresh) is only supported on CM >= 2.22.
	// On older CM and on CDSPaaS the endpoint returns 404, so skip the refresh
	// loop entirely and accept whatever state the inner poll loop produced.
	if client.CMVersion < 222 || client.IsCDSPaaS {
		client.Log.Info("[aws_multiregion.go -> waitForPrimaryRegionUpdated] individual key refresh not supported (CM < 2.22 or CDSPaaS), skipping refresh loop")
		for i, keyID := range allKeyIDs {
			if !confirmed[i] {
				client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] key %s not confirmed after poll loop (refresh unavailable)", keyID))
			}
		}
		return
	}
	client.Log.Info("[aws_multiregion.go -> waitForPrimaryRegionUpdated] wait loop exhausted - refreshing unconfirmed keys")
	const refreshAttemptsPrimary = 15
	refreshSleepPrimary := 5
	for loop := 0; loop < refreshAttemptsPrimary; loop++ {
		for i, keyID := range allKeyIDs {
			if confirmed[i] {
				continue
			}
			_, refreshErr := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/refresh", []byte("{}"))
			if refreshErr != nil {
				client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] refresh loop %d: error refreshing key %s: %s",
					loop, keyID, refreshErr.Error()))
			}
			keyJSON, getErr := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
			if getErr != nil {
				client.Log.Warn(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] refresh loop %d: error reading key %s: %s",
					loop, keyID, getErr.Error()))
				continue
			}
			primaryRegion := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
			keyType := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String()
			keyState := gjson.Get(keyJSON, "aws_param.KeyState").String()
			region := gjson.Get(keyJSON, "region").String()
			regionOK := primaryRegion == newPrimaryRegion
			switch keyID {
			case newPrimaryKeyID:
				confirmed[i] = regionOK && keyType == "PRIMARY" && keyState == "Enabled"
			case primaryKeyID:
				confirmed[i] = regionOK && keyType == "REPLICA" && keyState == "Enabled"
			default:
				confirmed[i] = regionOK
			}
			if confirmed[i] {
				client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] refresh loop %d: key %s (region %s) confirmed PrimaryKey.Region=%s KeyType=%s KeyState=%s",
					loop, keyID, region, primaryRegion, keyType, keyState))
			}
		}
		if allPrimaryRegionsConfirmed() {
			client.Log.Info(fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdated] refresh loop: %d All keys confirmed to contain new primary region %s", loop, newPrimaryRegion))
			return
		}
		if loop < refreshAttemptsPrimary-1 {
			time.Sleep(time.Duration(refreshSleepPrimary) * time.Second)
		}
	}

	for i, keyID := range allKeyIDs {
		if !confirmed[i] {
			msg := "Error updating primary region. Timed out confirming primary region change. Please refresh."
			details := utils.ApiError(msg, map[string]interface{}{
				"key_id":                    keyID,
				"configured primary region": newPrimaryRegion,
			})
			client.Log.Error("Error updating primary region. TIMED OUT confirming primary region change on primary key and all replicas.")
			diags.AddWarning(details, "")
		}
	}
}
