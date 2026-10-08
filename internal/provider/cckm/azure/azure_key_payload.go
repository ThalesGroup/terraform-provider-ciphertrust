package cckm

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

// azureKeyBuildUpdatePayload builds the PATCH /azure/keys/:id request body by comparing the plan
// with the key as it was just read from CipherTrust Manager (keyResponse), not with state.
// Only values that differ are included, so omitted fields are left untouched by the API.
// Dates cannot be cleared in Azure, so a date that is null in the plan is never sent.
// An empty tags map is sent when the plan has no tags and the key has some, which clears them.
// It returns nil when nothing differs, or when a date is not valid RFC3339 (an error is added to diags).
func azureKeyBuildUpdatePayload(id string, client *common.Client, plan *models.AzureKeyTFSDK, keyResponse string, diags *diag.Diagnostics) map[string]interface{} {
	v := newAzureParamsView(plan.AzureParams)
	payload := map[string]interface{}{}

	// Tags: send the full planned map when it differs from the key's tags.
	if !v.Tags.IsNull() && !v.Tags.IsUnknown() {
		planTags := make(map[string]string, len(v.Tags.Elements()))
		for k, e := range v.Tags.Elements() {
			if sv, ok := e.(types.String); ok {
				planTags[k] = sv.ValueString()
			}
		}
		keyTags := make(map[string]string)
		for k, val := range gjson.Get(keyResponse, "azure_param.tags").Map() {
			keyTags[k] = val.String()
		}
		var added, removed, changed []string
		for k, val := range planTags {
			keyVal, exists := keyTags[k]
			if !exists {
				added = append(added, k)
			} else if keyVal != val {
				changed = append(changed, k)
			}
		}
		for k := range keyTags {
			if _, exists := planTags[k]; !exists {
				removed = append(removed, k)
			}
		}
		if len(added) > 0 || len(removed) > 0 || len(changed) > 0 {
			sort.Strings(added)
			sort.Strings(removed)
			sort.Strings(changed)
			client.Log.Info(fmt.Sprintf("[azure_key_payload.go -> azureKeyBuildUpdatePayload][%s] Tags added: %v, removed: %v, changed: %v",
				id, added, removed, changed))
			payload["tags"] = planTags
		}
	}

	// Key operations are compared as sets.
	if !v.KeyOps.IsNull() && !v.KeyOps.IsUnknown() {
		planOps := azureKeyListToStrings(v.KeyOps)
		keyOps := make([]string, 0)
		for _, op := range gjson.Get(keyResponse, "azure_param.key.key_ops").Array() {
			keyOps = append(keyOps, op.String())
		}
		a := append([]string{}, planOps...)
		b := append([]string{}, keyOps...)
		sort.Strings(a)
		sort.Strings(b)
		if !reflect.DeepEqual(a, b) {
			payload["key_ops"] = planOps
		}
	}

	attrs := map[string]interface{}{}
	if !v.Enabled.IsNull() && !v.Enabled.IsUnknown() &&
		v.Enabled.ValueBool() != gjson.Get(keyResponse, "azure_param.attributes.enabled").Bool() {
		attrs["enabled"] = v.Enabled.ValueBool()
	}
	if !v.ActivationDate.IsNull() && !v.ActivationDate.IsUnknown() {
		t, err := time.Parse(time.RFC3339, v.ActivationDate.ValueString())
		if err != nil {
			diags.AddAttributeError(azureParamsPath("attributes", "activation_date"), "Invalid date",
				"activation_date must be in RFC3339 format, for example 2026-07-03T14:24:00Z.")
			return nil
		}
		if t.Unix() != gjson.Get(keyResponse, "azure_param.attributes.nbf").Int() {
			attrs["nbf"] = t.Unix()
		}
	}
	if !v.ExpirationDate.IsNull() && !v.ExpirationDate.IsUnknown() {
		t, err := time.Parse(time.RFC3339, v.ExpirationDate.ValueString())
		if err != nil {
			diags.AddAttributeError(azureParamsPath("attributes", "expiration_date"), "Invalid date",
				"expiration_date must be in RFC3339 format, for example 2030-07-03T14:24:00Z.")
			return nil
		}
		if t.Unix() != gjson.Get(keyResponse, "azure_param.attributes.exp").Int() {
			attrs["exp"] = t.Unix()
		}
	}
	if len(attrs) > 0 {
		payload["attributes"] = attrs
	}

	if len(payload) == 0 {
		return nil
	}
	return payload
}

// azureKeyBuildParam builds the azure_param object of a create or upload request from azure_params.
// It returns false and adds an error diagnostic if a date is not valid.
func azureKeyBuildParam(v azureParamsView, diags *diag.Diagnostics) (models.AzureKeyParamJSON, bool) {
	param := models.AzureKeyParamJSON{
		KeyType: v.Kty.ValueString(),
	}
	if !v.Curve.IsNull() && !v.Curve.IsUnknown() {
		param.Curve = v.Curve.ValueString()
	}
	if !v.KeySize.IsNull() && !v.KeySize.IsUnknown() {
		param.KeySize = v.KeySize.ValueInt64()
	}
	if !v.KeyOps.IsNull() && !v.KeyOps.IsUnknown() {
		param.KeyOps = azureKeyListToStrings(v.KeyOps)
	}
	if !v.Tags.IsNull() && !v.Tags.IsUnknown() {
		tags := make(map[string]string, len(v.Tags.Elements()))
		for k, e := range v.Tags.Elements() {
			if sv, ok := e.(types.String); ok {
				tags[k] = sv.ValueString()
			}
		}
		param.Tags = tags
	}

	attrs := models.AzureKeyAttributesJSON{}
	hasAttrs := false
	if !v.Enabled.IsNull() && !v.Enabled.IsUnknown() {
		b := v.Enabled.ValueBool()
		attrs.Enabled = &b
		hasAttrs = true
	}
	if !v.ActivationDate.IsNull() && !v.ActivationDate.IsUnknown() {
		t, err := time.Parse(time.RFC3339, v.ActivationDate.ValueString())
		if err != nil {
			diags.AddAttributeError(azureParamsPath("attributes", "activation_date"), "Invalid date",
				"activation_date must be in RFC3339 format, for example 2026-07-03T14:24:00Z.")
			return param, false
		}
		n := t.Unix()
		attrs.NotBefore = &n
		hasAttrs = true
	}
	if !v.ExpirationDate.IsNull() && !v.ExpirationDate.IsUnknown() {
		t, err := time.Parse(time.RFC3339, v.ExpirationDate.ValueString())
		if err != nil {
			diags.AddAttributeError(azureParamsPath("attributes", "expiration_date"), "Invalid date",
				"expiration_date must be in RFC3339 format, for example 2030-07-03T14:24:00Z.")
			return param, false
		}
		n := t.Unix()
		attrs.Expires = &n
		hasAttrs = true
	}
	if hasAttrs {
		param.Attributes = &attrs
	}
	return param, true
}

// azureKeyBuildCreateNativePayload builds the POST /azure/keys request body from the plan.
// It returns false and adds an error diagnostic if the plan is not valid for the vault type.
func azureKeyBuildCreateNativePayload(plan *models.AzureKeyTFSDK, vaultType string, diags *diag.Diagnostics) (models.AzureCreateKeyPayloadJSON, bool) {
	param, ok := azureKeyBuildParam(newAzureParamsView(plan.AzureParams), diags)
	payload := models.AzureCreateKeyPayloadJSON{
		KeyName:    plan.Name.ValueString(),
		KeyVault:   plan.VaultID.ValueString(),
		AzureParam: param,
	}
	if !ok {
		return payload, false
	}
	if vaultType == azureManagedHSMVaultType && !strings.HasSuffix(payload.AzureParam.KeyType, "-HSM") {
		diags.AddAttributeError(azureParamsPath("key", "kty"), "Invalid key type for vault",
			"Keys in a managed HSM vault must have a kty of EC-HSM or RSA-HSM.")
		return payload, false
	}

	if !plan.Exportable.IsNull() && !plan.Exportable.IsUnknown() {
		b := plan.Exportable.ValueBool()
		payload.Exportable = &b
	}
	if !plan.ReleasePolicy.IsNull() && !plan.ReleasePolicy.IsUnknown() {
		var policy map[string]interface{}
		if err := json.Unmarshal([]byte(plan.ReleasePolicy.ValueString()), &policy); err != nil {
			diags.AddAttributeError(path.Root("release_policy"), "Invalid release policy",
				"release_policy must be a valid JSON object.")
			return payload, false
		}
		payload.ReleasePolicy = policy
	}
	return payload, true
}
