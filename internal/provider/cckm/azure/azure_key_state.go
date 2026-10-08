package cckm

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

func azureKeyOptString(value string) types.String {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

func azureKeyOptInt64(value int64) types.Int64 {
	if value == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(value)
}

// azureKeyDate converts Unix epoch seconds from the API to a UTC RFC3339 string. 0 is null.
func azureKeyDate(epoch int64) types.String {
	if epoch == 0 {
		return types.StringNull()
	}
	return types.StringValue(time.Unix(epoch, 0).UTC().Format(time.RFC3339))
}

// azureKeyKeyOps returns key_ops from the response, keeping the current value
// when the same operations are returned in any order.
func azureKeyKeyOps(ctx context.Context, response string, current types.List, diags *diag.Diagnostics) types.List {
	respOps := make([]string, 0)
	for _, op := range gjson.Get(response, "azure_param.key.key_ops").Array() {
		respOps = append(respOps, op.String())
	}
	if !current.IsNull() && !current.IsUnknown() {
		a := azureKeyListToStrings(current)
		b := append([]string{}, respOps...)
		sort.Strings(a)
		sort.Strings(b)
		if reflect.DeepEqual(a, b) {
			return current
		}
	}
	if len(respOps) == 0 {
		return types.ListNull(types.StringType)
	}
	ops, d := types.ListValueFrom(ctx, types.StringType, respOps)
	diags.Append(d...)
	return ops
}

// azureKeyTags returns tags from the response. No tags is null, unless the current value is an
// empty map (tags = {}), which is kept so the result matches the plan.
func azureKeyTags(ctx context.Context, response string, current types.Map, diags *diag.Diagnostics) types.Map {
	tags := make(map[string]string)
	for k, val := range gjson.Get(response, "azure_param.tags").Map() {
		tags[k] = val.String()
	}
	if len(tags) == 0 {
		if !current.IsNull() && !current.IsUnknown() && len(current.Elements()) == 0 {
			return current
		}
		return types.MapNull(types.StringType)
	}
	tagMap, d := types.MapValueFrom(ctx, types.StringType, tags)
	diags.Append(d...)
	return tagMap
}

// azureKeySetParams builds azure_params from the response. Configured values are kept
// when they are equivalent to what the API returned.
func azureKeySetParams(ctx context.Context, response string, state *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	prior := newAzureParamsView(state.AzureParams)

	kty := types.StringValue(gjson.Get(response, "azure_param.key.kty").String())
	keyObj, d := types.ObjectValue(models.AzureParamsKeyAttrTypes, map[string]attr.Value{
		"kty":     kty,
		"curve":   azureKeyOptString(gjson.Get(response, "azure_param.key.crv").String()),
		"key_ops": azureKeyKeyOps(ctx, response, prior.KeyOps, diags),
		"kid":     types.StringValue(gjson.Get(response, "azure_param.key.kid").String()),
		"n":       azureKeyOptString(gjson.Get(response, "azure_param.key.n").String()),
		"e":       azureKeyOptString(gjson.Get(response, "azure_param.key.e").String()),
	})
	diags.Append(d...)

	attrsObj, d := types.ObjectValue(models.AzureParamsAttributesAttrTypes, map[string]attr.Value{
		"enabled":         types.BoolValue(gjson.Get(response, "azure_param.attributes.enabled").Bool()),
		"expiration_date": azureKeyDate(gjson.Get(response, "azure_param.attributes.exp").Int()),
		"activation_date": azureKeyDate(gjson.Get(response, "azure_param.attributes.nbf").Int()),
		"recovery_level":  types.StringValue(gjson.Get(response, "azure_param.attributes.recoveryLevel").String()),
		"created":         azureKeyOptInt64(gjson.Get(response, "azure_param.attributes.created").Int()),
		"updated":         azureKeyOptInt64(gjson.Get(response, "azure_param.attributes.updated").Int()),
	})
	diags.Append(d...)

	params, d := types.ObjectValue(models.AzureParamsAttrTypes, map[string]attr.Value{
		"key":        keyObj,
		"attributes": attrsObj,
		"key_size":   azureKeyOptInt64(gjson.Get(response, "key_size").Int()),
		"tags":       azureKeyTags(ctx, response, prior.Tags, diags),
	})
	diags.Append(d...)
	state.AzureParams = params
}

// azureKeySetState maps a CipherTrust Manager Azure key response into the Terraform model.
// vault_id is set from key_vault_id. restore_key and vault_name are retained
// from the model. After an import, Read rebuilds vault_name from the vault.
func azureKeySetState(ctx context.Context, response string, state *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.Backup = types.StringValue(gjson.Get(response, "backup").String())
	state.BackupAt = azureKeyTimeString(gjson.Get(response, "backup_at").String())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = azureKeyTimeString(gjson.Get(response, "createdAt").String())
	state.Deleted = types.BoolValue(gjson.Get(response, "deleted").Bool())
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	state.KeySoftDeletedInAzure = types.BoolValue(gjson.Get(response, "key_soft_deleted_in_azure").Bool())
	state.Region = types.StringValue(gjson.Get(response, "region").String())
	state.SoftDeleteEnabled = types.BoolValue(gjson.Get(response, "soft_delete_enabled").Bool())
	state.Status = types.StringValue(gjson.Get(response, "status").String())
	state.SyncedAt = azureKeyTimeString(gjson.Get(response, "syncedAt").String())
	state.Tenant = types.StringValue(gjson.Get(response, "tenant").String())
	state.UpdatedAt = azureKeyTimeString(gjson.Get(response, "updatedAt").String())
	state.Version = types.StringValue(gjson.Get(response, "version").String())
	state.VersionCount = types.Int64Value(gjson.Get(response, "version_count").Int())
	state.Name = types.StringValue(gjson.Get(response, "key_name").String())
	state.Exportable = types.BoolValue(gjson.Get(response, "azure_param.attributes.exportable").Bool())
	// vault_id is the CipherTrust Manager vault ID. It is kept from the model only if the response has none.
	if vaultID := gjson.Get(response, "key_vault_id").String(); vaultID != "" {
		state.VaultID = types.StringValue(vaultID)
	}

	azureKeySetParams(ctx, response, state, diags)
	azureKeySetPolicyAndLabels(ctx, response, state, diags)
	azureKeySetUploadKey(response, state)

	// enable_auto_rotation is rebuilt from the labels only when state has none. This covers import and
	// rotation that was enabled outside Terraform.
	if state.EnableAutoRotation == nil {
		state.EnableAutoRotation = azureKeyRotationFromLabels(response)
	}

	// backup_config is set from the response like labels. enable_auto_backup is rebuilt from it only when
	// state has none. This covers import and backup that was enabled outside Terraform.
	state.BackupConfig = azureKeyBackupConfigMap(ctx, response, diags)
	if state.EnableAutoBackup == nil {
		state.EnableAutoBackup = azureKeyBackupFromConfig(response)
	}
}

// azureKeySetUploadKey sets the computed local_key_name of upload_key from the response. It is the name of
// the CipherTrust Manager key that was uploaded, so it is only set when source_key_tier is local and is
// null otherwise. The configured attributes (source_key_tier, source_key_id, pfx, pfx_password, kek_kid
// and hsm) are never changed. Nothing is set when upload_key is not configured (native and restored keys,
// import).
func azureKeySetUploadKey(response string, state *models.AzureKeyTFSDK) {
	if state.UploadKey == nil {
		return
	}
	if state.UploadKey.SourceKeyTier.ValueString() == "local" {
		state.UploadKey.LocalKeyName = azureKeyOptString(gjson.Get(response, "local_key_name").String())
		return
	}
	state.UploadKey.LocalKeyName = types.StringNull()
}

// azureKeyListToStrings converts a list of strings to a Go slice, ignoring null and unknown elements.
func azureKeyListToStrings(list types.List) []string {
	out := make([]string, 0, len(list.Elements()))
	for _, e := range list.Elements() {
		if sv, ok := e.(types.String); ok && !sv.IsNull() && !sv.IsUnknown() {
			out = append(out, sv.ValueString())
		}
	}
	return out
}

// azureKeyTimeString returns a null string for an empty or zero-value time, otherwise the
// time formatted as RFC3339 without fractional seconds. A value that cannot be parsed is
// returned unchanged.
func azureKeyTimeString(value string) types.String {
	if value == "" || strings.HasPrefix(value, "0001-01-01") {
		return types.StringNull()
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return types.StringValue(value)
	}
	return types.StringValue(t.Format(time.RFC3339))
}

// azureKeySetPolicyAndLabels sets release_policy and labels from the response.
// A configured release_policy is kept when it is JSON-equivalent to the returned one.
func azureKeySetPolicyAndLabels(ctx context.Context, response string, state *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	policy := gjson.Get(response, "release_policy")
	if !policy.Exists() || policy.Type == gjson.Null || policy.Raw == "{}" || policy.Raw == "" {
		state.ReleasePolicy = types.StringNull()
	} else {
		keepPolicy := false
		if !state.ReleasePolicy.IsNull() && !state.ReleasePolicy.IsUnknown() {
			var cur, got interface{}
			if json.Unmarshal([]byte(state.ReleasePolicy.ValueString()), &cur) == nil &&
				json.Unmarshal([]byte(policy.Raw), &got) == nil {
				keepPolicy = reflect.DeepEqual(cur, got)
			}
		}
		if !keepPolicy {
			state.ReleasePolicy = types.StringValue(policy.Raw)
		}
	}

	labels := make(map[string]string)
	for k, v := range gjson.Get(response, "labels").Map() {
		labels[k] = v.String()
	}
	labelMap, d := types.MapValueFrom(ctx, types.StringType, labels)
	diags.Append(d...)
	state.Labels = labelMap
}
