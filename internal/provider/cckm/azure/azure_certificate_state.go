package cckm

import (
	"encoding/json"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func azureCertificateIssuerObject(param models.AzureCertificateParamResponseJSON) types.Object {
	if param.IssuerName == "" && param.CertificateType == "" && !param.CertTransparency {
		return types.ObjectNull(azureCertIssuerAttrTypes)
	}
	return types.ObjectValueMust(azureCertIssuerAttrTypes, map[string]attr.Value{
		"name":              azureCertificateStringOrNull(param.IssuerName),
		"certificate_type":  azureCertificateStringOrNull(param.CertificateType),
		"cert_transparency": types.BoolValue(param.CertTransparency),
	})
}

func azureCertificateKeyPropsObject(param models.AzureCertificateParamResponseJSON) types.Object {
	if param.Kty == "" {
		return types.ObjectNull(azureCertKeyPropsAttrTypes)
	}
	return types.ObjectValueMust(azureCertKeyPropsAttrTypes, map[string]attr.Value{
		"kty":        azureCertificateStringOrNull(param.Kty),
		"curve":      azureCertificateStringOrNull(param.Crv),
		"exportable": types.BoolValue(param.Exportable),
		"key_size":   azureCertificateInt64OrNull(param.KeySize),
		"reuse_key":  types.BoolValue(param.ReuseKey),
	})
}

func azureCertificateX509Object(prior map[string]attr.Value, param models.AzureCertificateParamResponseJSON) types.Object {
	sans := azureCertificateSansObject(objectAttrs(prior["sans"]), param.Sans)
	if param.Subject == "" && param.ValidityMonths == 0 && len(param.EnhancedKeyUsage) == 0 && len(param.KeyUsage) == 0 && sans.IsNull() {
		return types.ObjectNull(azureCertX509PropsAttrTypes)
	}
	// UseStateForUnknown cannot keep a null sans, so store an object with null lists when Azure returns none.
	if sans.IsNull() {
		sans = types.ObjectValueMust(azureCertSansAttrTypes, map[string]attr.Value{
			"dns_names":            types.ListValueMust(types.StringType, []attr.Value{}),
			"emails":               types.ListValueMust(types.StringType, []attr.Value{}),
			"user_principal_names": types.ListValueMust(types.StringType, []attr.Value{}),
		})
	}
	return types.ObjectValueMust(azureCertX509PropsAttrTypes, map[string]attr.Value{
		"subject":            azureCertificateStringOrNull(param.Subject),
		"enhanced_key_usage": azureCertificateStringList(prior["enhanced_key_usage"], param.EnhancedKeyUsage),
		"key_usage":          azureCertificateStringList(prior["key_usage"], param.KeyUsage),
		"validity_months":    azureCertificateInt64OrNull(param.ValidityMonths),
		"sans":               sans,
	})
}

// azureCertificateAttributesObject builds the attributes. The dates are optional inputs, so they are carried
// over from the prior attributes (null when there are none) and the returned nbf and exp are not written.
func azureCertificateAttributesObject(prior map[string]attr.Value, param models.AzureCertificateParamResponseJSON) types.Object {
	attrs := param.Attributes
	if attrs.Enabled == nil && attrs.Nbf == 0 && attrs.Exp == 0 {
		return types.ObjectNull(azureCertAttributesAttrTypes)
	}
	// The API omits enabled when it is false, so a missing value means false.
	enabled := types.BoolValue(false)
	if attrs.Enabled != nil {
		enabled = types.BoolValue(*attrs.Enabled)
	}
	return types.ObjectValueMust(azureCertAttributesAttrTypes, map[string]attr.Value{
		"enabled":         enabled,
		"activation_date": azureSecretKeptDate(prior, "activation_date"),
		"expiration_date": azureSecretKeptDate(prior, "expiration_date"),
	})
}

func azureCertificateSecretPropsObject(param models.AzureCertificateParamResponseJSON) types.Object {
	if param.ContentType == "" {
		return types.ObjectNull(azureCertSecretPropsAttrTypes)
	}
	return types.ObjectValueMust(azureCertSecretPropsAttrTypes, map[string]attr.Value{
		"content_type": types.StringValue(param.ContentType),
	})
}

func azureCertificatePolicyObject(prior map[string]attr.Value, param models.AzureCertificateParamResponseJSON) types.Object {
	return types.ObjectValueMust(azureCertPolicyAttrTypes, map[string]attr.Value{
		"issuer":           azureCertificateIssuerObject(param),
		"key_props":        azureCertificateKeyPropsObject(param),
		"x509_props":       azureCertificateX509Object(objectAttrs(prior["x509_props"]), param),
		"attributes":       azureCertificateAttributesObject(objectAttrs(prior["attributes"]), param),
		"lifetime_actions": azureCertificateLifetimeActionsList(param.LifetimeActions),
		"secret_props":     azureCertificateSecretPropsObject(param),
	})
}

// azureCertificateSetParams sets state.AzureParams from every value the GET response returns, including
// for uploaded and imported certificates. The prior azure_params is only used to keep list ordering.
func azureCertificateSetParams(param models.AzureCertificateParamResponseJSON, state *AzureCertificateTFSDK) {
	prior := objectAttrs(state.AzureParams)
	state.AzureParams = types.ObjectValueMust(azureCertParamsAttrTypes, map[string]attr.Value{
		"tags":   azureCertificateTags(param.Tags, attrMap(prior, "tags")),
		"policy": azureCertificatePolicyObject(objectAttrs(prior["policy"]), param),
	})
}

// ---------------------------------------------------------------------------
// Value helpers
// ---------------------------------------------------------------------------

// azureCertificateBoolPtr returns nil for a null or unknown value so that omitempty drops it.
func azureCertificateBoolPtr(value types.Bool) *bool {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueBool()
	return &result
}

// azureCertificateInt64Ptr returns nil for a null or unknown value so that omitempty drops it.
func azureCertificateInt64Ptr(value types.Int64) *int64 {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	result := value.ValueInt64()
	return &result
}

// azureCertificateListStrings returns the strings of a list, or nil for a null or unknown list.
func azureCertificateListStrings(value attr.Value) []string {
	list, ok := value.(types.List)
	if !ok || list.IsNull() || list.IsUnknown() {
		return nil
	}
	var result []string
	for _, element := range list.Elements() {
		if str, ok := element.(types.String); ok {
			result = append(result, str.ValueString())
		}
	}
	return result
}

// azureCertificateTagsPayload returns the tags as a plain map, or nil when there are none.
func azureCertificateTagsPayload(tags types.Map) map[string]string {
	if tags.IsNull() || tags.IsUnknown() {
		return nil
	}
	result := make(map[string]string)
	for key, value := range tags.Elements() {
		if str, ok := value.(types.String); ok {
			result[key] = str.ValueString()
		}
	}
	return result
}

// azureCertificateSameStrings reports whether a list holds the same strings as values, in any order.
func azureCertificateSameStrings(list types.List, values []string) bool {
	elements := list.Elements()
	if len(elements) != len(values) {
		return false
	}
	counts := make(map[string]int)
	for _, value := range values {
		counts[value]++
	}
	for _, element := range elements {
		str, ok := element.(types.String)
		if !ok {
			return false
		}
		counts[str.ValueString()]--
		if counts[str.ValueString()] < 0 {
			return false
		}
	}
	return true
}

// azureCertificateStringList builds a list from a response. The prior (planned) list is kept when it holds
// the same values in any order, because Azure may return list values in a different order.
func azureCertificateStringList(prior attr.Value, values []string) types.List {
	priorList, _ := prior.(types.List)
	known := !priorList.IsNull() && !priorList.IsUnknown()
	if len(values) == 0 {
		if known {
			return priorList
		}
		return types.ListNull(types.StringType)
	}
	if known && azureCertificateSameStrings(priorList, values) {
		return priorList
	}
	elements := make([]attr.Value, 0, len(values))
	for _, value := range values {
		elements = append(elements, types.StringValue(value))
	}
	return types.ListValueMust(types.StringType, elements)
}

// azureCertificateListOrEmpty turns a null list into an empty list. UseStateForUnknown cannot keep a null state
// value, so a null list under sans would be planned as unknown after every apply.
func azureCertificateListOrEmpty(list types.List) types.List {
	if list.IsNull() {
		return types.ListValueMust(types.StringType, []attr.Value{})
	}
	return list
}

func azureCertificateLifetimeActionsList(raw json.RawMessage) types.List {
	objType := types.ObjectType{AttrTypes: azureCertLifetimeActionAttrTypes}
	var items []models.AzureCertificateLifetimeActionJSON
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &items)
	}
	if len(items) == 0 {
		return types.ListNull(objType)
	}
	elements := make([]attr.Value, 0, len(items))
	for _, item := range items {
		trigger := types.ObjectNull(azureCertTriggerAttrTypes)
		if item.Trigger != nil {
			var percentage, days int64
			if item.Trigger.LifetimePercentage != nil {
				percentage = *item.Trigger.LifetimePercentage
			}
			if item.Trigger.DaysBeforeExpiry != nil {
				days = *item.Trigger.DaysBeforeExpiry
			}
			trigger = types.ObjectValueMust(azureCertTriggerAttrTypes, map[string]attr.Value{
				"lifetime_percentage": azureCertificateInt64OrNull(percentage),
				"days_before_expiry":  azureCertificateInt64OrNull(days),
			})
		}
		action := types.ObjectNull(azureCertActionAttrTypes)
		if item.Action != nil {
			action = types.ObjectValueMust(azureCertActionAttrTypes, map[string]attr.Value{
				"action_type": azureCertificateStringOrNull(item.Action.ActionType),
			})
		}
		elements = append(elements, types.ObjectValueMust(azureCertLifetimeActionAttrTypes, map[string]attr.Value{
			"trigger": trigger,
			"action":  action,
		}))
	}
	return types.ListValueMust(objType, elements)
}

func azureCertificateSansObject(prior map[string]attr.Value, raw json.RawMessage) types.Object {
	var sans models.AzureCertificateSansJSON
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &sans)
	}
	if len(sans.DNSNames) == 0 && len(sans.Emails) == 0 && len(sans.Upns) == 0 {
		return types.ObjectNull(azureCertSansAttrTypes)
	}
	return types.ObjectValueMust(azureCertSansAttrTypes, map[string]attr.Value{
		"dns_names":            azureCertificateListOrEmpty(azureCertificateStringList(prior["dns_names"], sans.DNSNames)),
		"emails":               azureCertificateListOrEmpty(azureCertificateStringList(prior["emails"], sans.Emails)),
		"user_principal_names": azureCertificateListOrEmpty(azureCertificateStringList(prior["user_principal_names"], sans.Upns)),
	})
}

// azureCertificateStringOrNull converts a string to a types.String. An empty string becomes null.
func azureCertificateStringOrNull(value string) types.String {
	if value == "" {
		return types.StringNull()
	}
	return types.StringValue(value)
}

// azureCertificateKeepIfEmpty returns value, or current when value is empty.
func azureCertificateKeepIfEmpty(value string, current types.String) types.String {
	if value == "" {
		return current
	}
	return types.StringValue(value)
}

// azureCertificateInt64OrNull returns null for zero, which the API uses for "not set".
func azureCertificateInt64OrNull(value int64) types.Int64 {
	if value == 0 {
		return types.Int64Null()
	}
	return types.Int64Value(value)
}

// azureCertificateTags returns the tags from the response. No tags is null, unless the current value is a
// known empty map (tags = {}), which is kept so the result matches the plan.
func azureCertificateTags(values map[string]string, current types.Map) types.Map {
	if len(values) == 0 && !current.IsNull() && !current.IsUnknown() && len(current.Elements()) == 0 {
		return current
	}
	return azureCertificateMapOrNull(values)
}

func azureCertificateMapOrNull(values map[string]string) types.Map {
	if len(values) == 0 {
		return types.MapNull(types.StringType)
	}
	elements := make(map[string]attr.Value, len(values))
	for key, value := range values {
		elements[key] = types.StringValue(value)
	}
	return types.MapValueMust(types.StringType, elements)
}

// azureCertificateSetState copies every value of a certificate response (AzureCertificateDetailed) into state.
// name and vault_id keep their current value when the response does not carry them. azure_params is
// read back from azure_param (see azureCertificateSetParams). upload_certificate is never returned and
// is left as it is.
func azureCertificateSetState(response string, state *AzureCertificateTFSDK) error {
	var cert models.AzureCertificateJSON
	if err := json.Unmarshal([]byte(response), &cert); err != nil {
		return err
	}
	state.ID = types.StringValue(cert.ID)
	state.Name = azureCertificateKeepIfEmpty(cert.CertName, state.Name)
	state.VaultID = azureCertificateKeepIfEmpty(cert.KeyVaultID, state.VaultID)

	state.CreatedAt = azureCertificateStringOrNull(cert.CreatedAt)
	state.UpdatedAt = azureCertificateStringOrNull(cert.UpdatedAt)
	state.SyncedAt = azureCertificateStringOrNull(cert.SyncedAt)
	state.RotatedAt = azureCertificateStringOrNull(cert.RotatedAt)
	state.Status = azureCertificateStringOrNull(cert.Status)
	state.Version = azureCertificateStringOrNull(cert.Version)
	state.VersionCount = types.Int64Value(cert.VersionCount)
	state.Operation = azureCertificateStringOrNull(cert.Operation)
	state.OperationError = azureCertificateStringOrNull(cert.OperationError)
	state.Error = azureCertificateStringOrNull(cert.Error)
	state.Deleted = types.BoolValue(cert.Deleted)
	state.Gone = types.BoolValue(cert.Gone)
	state.CertSoftDeletedInAzure = types.BoolValue(cert.CertSoftDeletedInAzure)
	state.CertMaterialOrigin = azureCertificateStringOrNull(cert.CertMaterialOrigin)
	state.CertSource = azureCertificateStringOrNull(cert.CertSource)
	if state.UploadCertificate != nil {
		// The response carries nothing for upload_certificate. A configured source_cert_id is kept
		// and an unknown one becomes null.
		if state.UploadCertificate.SourceCertID.IsUnknown() {
			state.UploadCertificate.SourceCertID = types.StringNull()
		}
	}
	state.BackupAt = azureCertificateStringOrNull(cert.BackupAt)
	state.Backup = types.StringNull()
	if cert.Backup != nil {
		state.Backup = azureCertificateStringOrNull(*cert.Backup)
	}

	state.CloudName = azureCertificateStringOrNull(cert.CloudName)
	state.Region = azureCertificateStringOrNull(cert.Region)
	state.Tenant = azureCertificateStringOrNull(cert.Tenant)
	state.VaultName = azureCertificateStringOrNull(cert.KeyVault)
	state.SoftDeleteEnabled = types.BoolValue(cert.SoftDeleteEnabled)
	state.AzureCreatedAt = azureCertificateStringOrNull(cert.AzureCreatedAt)
	state.AzureUpdatedAt = azureCertificateStringOrNull(cert.AzureUpdatedAt)
	state.AzureExpireAt = azureCertificateStringOrNull(cert.AzureExpireAt)

	param := cert.AzureParam
	state.Cert = azureCertificateStringOrNull(param.Cert)
	state.Cid = azureCertificateStringOrNull(param.Cid)
	state.Kid = azureCertificateStringOrNull(param.Kid)
	state.Sid = azureCertificateStringOrNull(param.Sid)
	state.Thumbprint = azureCertificateStringOrNull(param.X5t)
	state.RecoveryLevel = azureCertificateStringOrNull(param.Attributes.RecoveryLevel)
	state.RecoverableDays = azureCertificateInt64OrNull(param.Attributes.RecoverableDays)

	azureCertificateSetParams(param, state)
	return nil
}
