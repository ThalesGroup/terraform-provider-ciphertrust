package cckm

import (
	"fmt"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// Request bodies
// ---------------------------------------------------------------------------

// azureCertificateCreatePayload builds the body of a native certificate create.
func azureCertificateCreatePayload(plan *AzureCertificateTFSDK) models.AzureCertificateCreateJSON {
	return models.AzureCertificateCreateJSON{
		CertName:   plan.Name.ValueString(),
		KeyVault:   plan.VaultID.ValueString(),
		AzureParam: azureCertificateParamPayload(plan.AzureParams),
	}
}

// azureCertificateImportPayload builds the body of a certificate upload. Only azure_params.tags is sent,
// and only when the configuration set it; unknown computed values are dropped.
// certificate may be PEM content, the path to a PEM or PFX file, or a base64 encoded PFX.
// private_key_pem may be PEM content or the path to a PEM file.
func azureCertificateImportPayload(plan *AzureCertificateTFSDK) (models.AzureCertificateImportJSON, error) {
	upload := plan.UploadCertificate
	certificate, err := azureCertificateContent(upload.Certificate.ValueString())
	if err != nil {
		return models.AzureCertificateImportJSON{}, fmt.Errorf("unable to read certificate file: %w", err)
	}
	privateKey, err := azureFileOrContent(upload.PrivateKeyPem.ValueString())
	if err != nil {
		return models.AzureCertificateImportJSON{}, fmt.Errorf("unable to read private_key_pem file: %w", err)
	}
	payload := models.AzureCertificateImportJSON{
		CertName:      plan.Name.ValueString(),
		KeyVault:      plan.VaultID.ValueString(),
		CaID:          upload.CaID.ValueString(),
		SourceCertID:  upload.SourceCertID.ValueString(),
		Certificate:   certificate,
		PrivateKeyPem: privateKey,
		Password:      upload.PrivateKeyPassword.ValueString(),
	}
	// Only tags are accepted with an upload. policy is rejected by validation.
	if params := objectAttrs(plan.AzureParams); params != nil {
		if tags := azureCertificateTagsPayload(attrMap(params, "tags")); len(tags) > 0 {
			payload.AzureParam = &models.AzureCertificateParamJSON{Tags: tags}
		}
	}
	return payload, nil
}

// ---------------------------------------------------------------------------
// azure_param and policy
// ---------------------------------------------------------------------------

// azureCertificateParamPayload builds the azure_param body. Null and unknown values are left out.
func azureCertificateParamPayload(params types.Object) models.AzureCertificateParamJSON {
	m := objectAttrs(params)
	if m == nil {
		return models.AzureCertificateParamJSON{}
	}
	return models.AzureCertificateParamJSON{
		Policy: azureCertificatePolicyPayload(objectAttrs(m["policy"])),
		Tags:   azureCertificateTagsPayload(attrMap(m, "tags")),
	}
}

func azureCertificatePolicyPayload(policy map[string]attr.Value) *models.AzureCertificatePolicyJSON {
	if policy == nil {
		return nil
	}
	payload := &models.AzureCertificatePolicyJSON{}
	if issuer := objectAttrs(policy["issuer"]); issuer != nil {
		payload.Issuer = &models.AzureCertificateIssuerJSON{
			Name:             attrString(issuer, "name").ValueString(),
			CertificateType:  attrString(issuer, "certificate_type").ValueString(),
			CertTransparency: azureCertificateBoolPtr(attrBool(issuer, "cert_transparency")),
		}
	}
	if key := objectAttrs(policy["key_props"]); key != nil {
		payload.KeyProps = &models.AzureCertificateKeyPropsJSON{
			Kty:        attrString(key, "kty").ValueString(),
			Crv:        attrString(key, "curve").ValueString(),
			Exportable: azureCertificateBoolPtr(attrBool(key, "exportable")),
			KeySize:    azureCertificateInt64Ptr(attrInt64(key, "key_size")),
			ReuseKey:   azureCertificateBoolPtr(attrBool(key, "reuse_key")),
		}
	}
	if x509 := objectAttrs(policy["x509_props"]); x509 != nil {
		payload.X509Props = azureCertificateX509Payload(x509)
	}
	if attributes := objectAttrs(policy["attributes"]); attributes != nil {
		payload.Attributes = &models.AzureCertificateAttributesJSON{
			Enabled: azureCertificateBoolPtr(attrBool(attributes, "enabled")),
		}
	}
	if actions, ok := policy["lifetime_actions"].(types.List); ok && !actions.IsNull() && !actions.IsUnknown() {
		for _, element := range actions.Elements() {
			payload.LifetimeActions = append(payload.LifetimeActions, azureCertificateLifetimeActionPayload(objectAttrs(element)))
		}
	}
	if secret := objectAttrs(policy["secret_props"]); secret != nil {
		payload.SecretProps = &models.AzureCertificateSecretPropsJSON{
			ContentType: attrString(secret, "content_type").ValueString(),
		}
	}
	return payload
}

func azureCertificateX509Payload(x509 map[string]attr.Value) *models.AzureCertificateX509PropsJSON {
	payload := &models.AzureCertificateX509PropsJSON{
		Subject:          attrString(x509, "subject").ValueString(),
		EnhancedKeyUsage: azureCertificateListStrings(x509["enhanced_key_usage"]),
		KeyUsage:         azureCertificateListStrings(x509["key_usage"]),
		ValidityMonths:   azureCertificateInt64Ptr(attrInt64(x509, "validity_months")),
	}
	if sans := objectAttrs(x509["sans"]); sans != nil {
		payload.Sans = &models.AzureCertificateSansJSON{
			DNSNames: azureCertificateListStrings(sans["dns_names"]),
			Emails:   azureCertificateListStrings(sans["emails"]),
			Upns:     azureCertificateListStrings(sans["user_principal_names"]),
		}
	}
	return payload
}

func azureCertificateLifetimeActionPayload(action map[string]attr.Value) models.AzureCertificateLifetimeActionJSON {
	payload := models.AzureCertificateLifetimeActionJSON{}
	if trigger := objectAttrs(action["trigger"]); trigger != nil {
		payload.Trigger = &models.AzureCertificateTriggerJSON{
			LifetimePercentage: azureCertificateInt64Ptr(attrInt64(trigger, "lifetime_percentage")),
			DaysBeforeExpiry:   azureCertificateInt64Ptr(attrInt64(trigger, "days_before_expiry")),
		}
	}
	if act := objectAttrs(action["action"]); act != nil {
		payload.Action = &models.AzureCertificateActionJSON{
			ActionType: attrString(act, "action_type").ValueString(),
		}
	}
	return payload
}
