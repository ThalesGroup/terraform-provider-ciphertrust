package cckm

import (
	"fmt"
	"reflect"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/hashicorp/terraform-plugin-framework/attr"
)

// azureSecretCreatePayload builds the body of a secret create. Null and unknown values are left out.
func azureSecretCreatePayload(plan *AzureSecretTFSDK) (models.AzureSecretCreateJSON, error) {
	params := objectAttrs(plan.AzureParams)
	attributes, err := azureSecretAttributesPayload(objectAttrs(params["attributes"]))
	if err != nil {
		return models.AzureSecretCreateJSON{}, err
	}
	return models.AzureSecretCreateJSON{
		SecretName: plan.Name.ValueString(),
		KeyVault:   plan.VaultID.ValueString(),
		AzureParam: models.AzureSecretParamJSON{
			Value:       attrString(params, "value").ValueString(),
			ContentType: attrString(params, "content_type").ValueString(),
			Tags:        azureCertificateTagsPayload(attrMap(params, "tags")),
			Attributes:  attributes,
		},
	}, nil
}

// azureSecretUpdatePayload builds the PATCH body from the differences between plan and state. The bool is
// false when nothing needs updating.
func azureSecretUpdatePayload(plan, state *AzureSecretTFSDK) (models.AzureSecretUpdateJSON, bool, error) {
	var payload models.AzureSecretUpdateJSON
	planParams := objectAttrs(plan.AzureParams)
	stateParams := objectAttrs(state.AzureParams)

	if contentType := attrString(planParams, "content_type"); !contentType.IsNull() && !contentType.IsUnknown() &&
		!contentType.Equal(attrString(stateParams, "content_type")) {
		value := contentType.ValueString()
		payload.ContentType = &value
	}

	if tags := attrMap(planParams, "tags"); !tags.IsNull() && !tags.IsUnknown() && !tags.Equal(attrMap(stateParams, "tags")) {
		values := azureCertificateTagsPayload(tags)
		if values == nil {
			values = map[string]string{}
		}
		payload.Tags = &values
	}

	planAttrs := objectAttrs(planParams["attributes"])
	stateAttrs := objectAttrs(stateParams["attributes"])
	attributes := &models.AzureSecretAttributesJSON{}
	changed := false
	if enabled := attrBool(planAttrs, "enabled"); !enabled.IsNull() && !enabled.IsUnknown() &&
		!enabled.Equal(attrBool(stateAttrs, "enabled")) {
		value := enabled.ValueBool()
		attributes.Enabled = &value
		changed = true
	}
	for _, name := range []string{"activation_date", "expiration_date"} {
		planDate := attrString(planAttrs, name)
		if planDate.IsNull() || planDate.IsUnknown() || planDate.Equal(attrString(stateAttrs, name)) {
			continue
		}
		epoch, err := azureSecretEpoch(planDate.ValueString())
		if err != nil {
			return payload, false, fmt.Errorf("%s: %w", name, err)
		}
		if name == "activation_date" {
			attributes.Nbf = &epoch
		} else {
			attributes.Exp = &epoch
		}
		changed = true
	}
	if changed {
		payload.Attributes = attributes
	}
	return payload, !reflect.DeepEqual(payload, models.AzureSecretUpdateJSON{}), nil
}

// azureSecretAttributesPayload converts the attributes object to a create request body, or nil when none
// are set. The dates are sent as Unix epoch seconds.
func azureSecretAttributesPayload(attributes map[string]attr.Value) (*models.AzureSecretAttributesJSON, error) {
	if attributes == nil {
		return nil, nil
	}
	payload := &models.AzureSecretAttributesJSON{Enabled: azureCertificateBoolPtr(attrBool(attributes, "enabled"))}
	if date := attrString(attributes, "activation_date"); !date.IsNull() && !date.IsUnknown() {
		epoch, err := azureSecretEpoch(date.ValueString())
		if err != nil {
			return nil, fmt.Errorf("activation_date: %w", err)
		}
		payload.Nbf = &epoch
	}
	if date := attrString(attributes, "expiration_date"); !date.IsNull() && !date.IsUnknown() {
		epoch, err := azureSecretEpoch(date.ValueString())
		if err != nil {
			return nil, fmt.Errorf("expiration_date: %w", err)
		}
		payload.Exp = &epoch
	}
	if payload.Enabled == nil && payload.Nbf == nil && payload.Exp == nil {
		return nil, nil
	}
	return payload, nil
}

// azureSecretEpoch converts an RFC3339 date to Unix epoch seconds, which is what the create and update APIs take.
func azureSecretEpoch(value string) (int64, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return 0, fmt.Errorf("must be an RFC3339 date: %w", err)
	}
	return t.Unix(), nil
}
