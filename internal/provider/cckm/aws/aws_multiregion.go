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
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

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
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_multiregion.go -> replicateKeyCommon]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_multiregion.go -> replicateKeyCommon]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("replicateKeyCommon: region: %s", replicaRegion))

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
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Info(ctx, fmt.Sprintf("Replicating AWS key %s to region %s", primaryKeyID, replicaRegion))
	replicaKeyResponse, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/replicate-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to replicate key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}

	// Don't return errors after this

	replicaKeyID := gjson.Get(replicaKeyResponse, "id").String()
	tflog.Info(ctx, fmt.Sprintf("Replica key created, id: %s, region: %s", replicaKeyID, replicaRegion))
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
		msg := "Error replicated AWS key, failed to read primary key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          errMsg,
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddWarning(details, "")
		return initialReplicaKeyResponse
	}

	waitForKeyEnabledDiags := diag.Diagnostics{}
	var enabledDiags diag.Diagnostics
	waitForReplicatedKeyIsEnabled(ctx, id, client, replicaKeyID, &enabledDiags)
	for _, d := range waitForKeyEnabledDiags {
		diags.AddWarning(d.Summary(), d.Detail())
	}

	sourceKeyID := gjson.Get(primaryKeyJSON, "local_key_id").String()
	sourceKeyTier := gjson.Get(primaryKeyJSON, "source_key_tier").String()
	if sourceKeyID != "" {
		// Make sure record is written
		var historDiags diag.Diagnostics
		waitForRotationHistoryRecord(ctx, id, client, replicaKeyID, sourceKeyID, sourceKeyTier, &historDiags)
		if enabledDiags.WarningsCount() > 0 {
			// And key really is enabled
			waitForReplicatedKeyIsEnabled(ctx, id, client, replicaKeyID, diags)
		}
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
		tflog.Error(ctx, details)
		diags.AddWarning(details, "")
		return initialReplicaKeyResponse
	}

	if replicateKeyPlan.MakePrimary.ValueBool() {
		tflog.Info(ctx, fmt.Sprintf("make_primary is true, promoting replica in region %s to primary", replicaRegion))
		enabled := gjson.Get(replicaKeyResponse, "aws_param.Enabled").Bool()
		if enabled {
			// Let the newly created replica settle before making it primary
			time.Sleep(time.Duration(10) * time.Second)
			tflog.Debug(ctx, fmt.Sprintf("replicateKeyCommon: replica key is enabled, proceeding with update-primary-region"))
			makePrimaryDiags := diag.Diagnostics{}
			updatePrimaryRegion(ctx, id, client, primaryKeyID, replicaRegion, replicaKeyID, &makePrimaryDiags)
			diags.Append(makePrimaryDiags...)
			for _, d := range makePrimaryDiags {
				diags.AddWarning(d.Summary(), d.Detail())
			}
		} else {
			msg := "Error updating AWS key. Unabled to primary region. Replica key is not enabled."
			details := utils.ApiError(msg, map[string]interface{}{
				"configured primary region": replicaRegion,
			})
			tflog.Warn(ctx, details)
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
		tflog.Error(ctx, details)
		diags.AddWarning(details, "")
		return finalFallback
	}
	tflog.Debug(ctx, "[aws_multiregion.go -> replicateKeyCommon][response:"+redactAWSResponse(replicaKeyResponse))
	return replicaKeyResponse
}

// waitForReplication polls the replica key until its state leaves the "Creating" phase or a timeout is reached.
func waitForReplication(ctx context.Context, id string, client *common.Client, replicaKeyID string, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_multiregion.go -> waitForReplication]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_multiregion.go -> waitForReplication]["+id+"]")
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
			tflog.Error(ctx, details)
			diags.AddWarning(details, "")
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
		tflog.Debug(ctx, fmt.Sprintf("Key state: %s", keyState))
		if keyState != "Creating" {
			tflog.Debug(ctx, "[aws_multiregion.go -> waitForReplication][response:"+redactAWSResponse(response))
			return response
		}
	}
	msg := fmt.Sprintf("Error replicating AWS key, key state is still '%s'.", keyState)
	details := utils.ApiError(msg, map[string]interface{}{"key_id": replicaKeyID})
	tflog.Warn(ctx, details)
	diags.AddWarning(details, "")
	tflog.Debug(ctx, "[aws_multiregion.go -> waitForReplication][response:"+redactAWSResponse(response))
	return response
}

// waitForReplicatedKeyIsEnabled polls the replica key until its state reaches "Enabled" or a timeout is
// reached. An EXTERNAL/BYOK replica key requires AWS to enable it after key material has been imported;
// this function also covers the window between a native replica leaving "Creating" state and reaching "Enabled".
func waitForReplicatedKeyIsEnabled(ctx context.Context, id string, client *common.Client, replicaKeyID string, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_multiregion.go -> waitForReplicatedKeyIsEnabled]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_multiregion.go -> waitForReplicatedKeyIsEnabled]["+id+"]")
	var (
		err      error
		response string
		keyState string
	)

	// Give AWS/CCKM a head start before the first poll.
	time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
	ticker := time.NewTicker(time.Duration(shortAwsKeyOpSleep) * time.Second)
	defer ticker.Stop()
	deadline := time.Now().Add(time.Duration(60) * time.Second)
	loop := 1
	for range ticker.C {
		if time.Now().After(deadline) {
			break
		}
		loop += 1
		response, err = client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error creating AWS key. Error reading replicated key."
			details := utils.ApiError(msg, map[string]interface{}{
				"error":          err.Error(),
				"replica_key_id": replicaKeyID,
			})
			tflog.Error(ctx, details)
			diags.AddWarning(details, "")
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
		tflog.Debug(ctx, fmt.Sprintf("waitForReplicatedKeyIsEnabled: loop: %d Key state: %s", loop, keyState))
		if keyState == "Enabled" {
			tflog.Info(ctx, "waitForReplicatedKeyIsEnabled: Key is enabled. response:"+redactAWSResponse(response))
			return response
		}
	}
	msg := fmt.Sprintf("Error replicating AWS key, keystate is '%s' instead of 'Enabled'.", keyState)
	details := utils.ApiError(msg, map[string]interface{}{"key_id": replicaKeyID})
	tflog.Warn(ctx, details)
	diags.AddWarning(details, "")
	tflog.Debug(ctx, "[aws_multiregion.go -> waitForReplicatedKeyIsEnabled][response:"+redactAWSResponse(response))
	return response
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
	tflog.Debug(ctx, common.MSG_METHOD_START+"[aws_multiregion.go -> updatePrimaryRegion]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[aws_multiregion.go -> updatePrimaryRegion]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("updatePrimaryRegion: newPrimaryRegion: %s newPrimaryKeyID: %s", newPrimaryRegion, newPrimaryKeyID))

	// Step 1: read the current primary to discover all keys in the MR set.
	// awsMrkKeyID is the shared mrk-xxx key ID present on all keys in the set (aws_param.KeyId).
	// Each entry in ReplicaKeys has a Region field we use to look up the replica's CCKM UUID.
	primaryKeyJSON, readErr := client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
	if readErr != nil {
		msg := "Error updating primary region, failed to read primary key."
		details := utils.ApiError(msg, map[string]interface{}{"error": readErr.Error(), "key_id": primaryKeyID})
		tflog.Error(ctx, details)
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
			tflog.Warn(ctx, fmt.Sprintf("updatePrimaryRegion: could not find replica key in CCKM for region %s - skipping from poll set", replicaRegion))
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

	tflog.Debug(ctx, fmt.Sprintf("updatePrimaryRegion: polling %d keys: %v", len(allKeyIDs), allKeyIDs))

	// Step 2: call update-primary-region.
	payload := UpdatePrimaryRegionPayloadJSON{
		PrimaryRegion: &newPrimaryRegion,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating primary region, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "primary key_id": primaryKeyID, "configured primary region": newPrimaryRegion})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Info(ctx, fmt.Sprintf("Updating primary region of key %s to %s", primaryKeyID, newPrimaryRegion))
	_, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/update-primary-region", payloadJSON)
	if err != nil {
		if strings.Contains(err.Error(), notMultiRegionPrimaryException) {
			tflog.Info(ctx, fmt.Sprintf("updatePrimaryRegion: notMultiRegionPrimaryException - retrying"))
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
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
	}
	tflog.Info(ctx, fmt.Sprintf("Primary region update API call succeeded for key %s", primaryKeyID))

	// Step 3: give CCKM/AWS a head start, then wait for all keys to confirm the primary region change.
	time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
	waitForPrimaryRegionUpdateConfirmed(ctx, id, client, primaryKeyID, newPrimaryKeyID, newPrimaryRegion, allKeyIDs, diags)
}

// waitForPrimaryRegionUpdateConfirmed polls all keys in the MR set until every one confirms the
// new primary region, using at most 2 refresh calls on the primary key to nudge CCKM/AWS.
//
// Outer loop (up to 2 refreshes):
//
//	Inner loop (up to 200 polls): read every key (even ones already confirmed) and check.
//	  Log loop counters and current updatedAt for each key. Return immediately when all confirmed.
//	If not all confirmed: call /refresh on the primary key, then wait until every key's updatedAt
//	  has changed from the value last seen in the inner loop before proceeding to the next outer iteration.
func waitForPrimaryRegionUpdateConfirmed(
	ctx context.Context,
	id string,
	client *common.Client,
	primaryKeyID string,
	newPrimaryKeyID string,
	newPrimaryRegion string,
	allKeyIDs []string,
	diags *diag.Diagnostics,
) {
	const maxInnerForPrimaryUpdate = 30
	const maxWaitForRefresh = 30

	// Snapshot updatedAt for every key before we start.
	lastUpdatedAt := make(map[string]string, len(allKeyIDs))
	for _, keyID := range allKeyIDs {
		keyJSON, err := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
		if err == nil {
			lastUpdatedAt[keyID] = gjson.Get(keyJSON, "updatedAt").String()
		}
	}

	done := make([]bool, len(allKeyIDs))
	allDone := func() bool {
		for _, d := range done {
			if !d {
				return false
			}
		}
		return true
	}

	for refresh := 0; refresh < 2; refresh++ {
		// Inner poll loop - read every key every iteration, even ones already done.
		for inner := 0; inner < maxInnerForPrimaryUpdate; inner++ {
			for i, keyID := range allKeyIDs {
				keyJSON, getErr := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
				if getErr != nil {
					tflog.Warn(ctx, fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdateConfirmed] refresh_loop: %d, wait_loop: %d, transient error reading key: %s, error: %s",
						refresh, inner, keyID, getErr.Error()))
					continue
				}
				updatedAt := gjson.Get(keyJSON, "updatedAt").String()
				primaryRegion := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
				keyType := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String()
				region := gjson.Get(keyJSON, "region").String()

				tflog.Debug(ctx, fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdateConfirmed] refresh_loop: %d, wait_loop: %d, key: %s, region: %s, PrimaryKey.Region: %s, KeyType: %s, updatedAt: %s",
					refresh, inner, keyID, region, primaryRegion, keyType, updatedAt))

				lastUpdatedAt[keyID] = updatedAt

				regionOK := primaryRegion == newPrimaryRegion
				switch keyID {
				case newPrimaryKeyID:
					done[i] = regionOK && keyType == "PRIMARY"
				case primaryKeyID:
					done[i] = regionOK && keyType == "REPLICA"
				default:
					done[i] = regionOK
				}
			}

			if allDone() {
				tflog.Info(ctx, fmt.Sprintf("All keys in MR set confirmed new primary region %s (refresh_loop: %d, wait_loop: %d)",
					newPrimaryRegion, refresh, inner))
				return
			}
			time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
		}

		// Inner loop exhausted without full confirmation - call /refresh on primary only.
		tflog.Info(ctx, fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdateConfirmed] refresh_loop: %d, inner loop exhausted - calling refresh on primary: %s",
			refresh, primaryKeyID))
		_, refreshErr := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/refresh", []byte("{}"))
		if refreshErr != nil {
			msg := "waitForPrimaryRegionUpdateConfirmed: error calling refresh on primary key."
			details := utils.ApiError(msg, map[string]interface{}{"error": refreshErr.Error(), "key_id": primaryKeyID})
			tflog.Warn(ctx, details)
		}

		time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)

		// Wait until every key's updatedAt has changed from what was last observed in the inner loop.
		baseUpdatedAt := make(map[string]string, len(allKeyIDs))
		for k, v := range lastUpdatedAt {
			baseUpdatedAt[k] = v
		}
		waitDone := make([]bool, len(allKeyIDs))
		allWaitDone := func() bool {
			for _, d := range waitDone {
				if !d {
					return false
				}
			}
			return true
		}

		for waitLoop := 0; waitLoop < maxWaitForRefresh; waitLoop++ {
			for i, keyID := range allKeyIDs {
				if waitDone[i] {
					continue
				}
				keyJSON, getErr := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
				if getErr != nil {
					tflog.Warn(ctx, fmt.Sprintf("[aws_multiregion.go -> waitForPrimaryRegionUpdateConfirmed] refresh_loop: %d, waitLoop: %d, transient error reading key: %s, error: %s",
						refresh, waitLoop, keyID, getErr.Error()))
					continue
				}
				newUpdatedAt := gjson.Get(keyJSON, "updatedAt").String()
				if newUpdatedAt != baseUpdatedAt[keyID] {
					tflog.Info(ctx, fmt.Sprintf("waitForPrimaryRegionUpdateConfirmed refresh_loop: %d, waitLoop: %d, key: %s, updatedAt changed, old: %s, new: %s",
						refresh, waitLoop, keyID, baseUpdatedAt[keyID], newUpdatedAt))
					lastUpdatedAt[keyID] = newUpdatedAt
					waitDone[i] = true
				}
			}

			if allWaitDone() {
				tflog.Debug(ctx, fmt.Sprintf("waitForPrimaryRegionUpdateConfirmed[aws_multiregion.go -> waitForPrimaryRegionUpdateConfirmed] refresh_loop: %d, all keys updated after refresh, waitLoop: %d",
					refresh, waitLoop))
				break
			}
			time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
		}
	}

	// Still not confirmed after 2 refresh cycles - warn for each unconfirmed key.
	for i, keyID := range allKeyIDs {
		if !done[i] {
			msg := "Error updating primary region. Timed out confirming primary region change. Please refresh."
			details := utils.ApiError(msg, map[string]interface{}{
				"key_id":                    keyID,
				"configured primary region": newPrimaryRegion,
			})
			tflog.Error(ctx, "Error updating primary region. TIMED OUT confirming primary region change.")
			diags.AddWarning(details, "")
		}
	}
}
