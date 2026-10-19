package cckm

import (
	"context"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// azureCertificateUseStateWhenUnchanged returns state when the plan has no known difference from it,
// otherwise it returns the plan. It is called from ModifyPlan after validation, on update only.
//
// WORKAROUND: avoid a non-empty plan after apply (or refresh) when nothing has changed.
//
// Symptom: with an unchanged config, terraform reports "Detected value change" for azure_params
// and the acceptance test fails with a non-empty plan after apply.
//
// What is known: azure_params.policy contains Optional+Computed attributes that the user does not
// configure (attributes, lifetime_actions, secret_props, key_usage, enhanced_key_usage, sans, key_props.curve,
// and so on). The framework marks Optional+Computed attributes whose config is null as unknown
// when it builds the proposed plan, and terraform core then sees unknown != state value. Plan
// modifiers cannot suppress this. UseStateForUnknown was rejected because computed values such
// as updated_at can legitimately change on any real update.
//
// What is not known: why only this resource is affected, since other CCKM resources with
// Optional+Computed nested attributes plan cleanly. The root cause has not been found, so this is
// a workaround rather than a fix.
//
// Approach: compare the plan with state ignoring values that are unknown in the plan. If no known
// value differs, use state as the plan. State has already been refreshed from the API before
// planning, so out-of-band drift is still a known difference and still produces a diff. A genuine
// config change is a known difference too, so the proposed plan is kept and computed values stay
// unknown. Lists are compared by position, so a reordering is treated as a change. An error
// comparing the values is also treated as a change.
func azureCertificateUseStateWhenUnchanged(plan tftypes.Value, state tftypes.Value) tftypes.Value {
	diffs, err := plan.Diff(state)
	if err != nil {
		return plan
	}
	for _, diff := range diffs {
		if diff.Value1 != nil && !diff.Value1.IsKnown() {
			continue
		}
		return plan
	}
	return state
}

// azureVaultsEndpoint is the CipherTrust Manager endpoint for Azure vaults.
const azureVaultsEndpoint = common.URL_AZURE + "/vaults"

// azureVaultChangeAllowed implements the conditional immutability of vault_id. It must be called from
// ModifyPlan on update. A change is allowed only when the previously configured vault no longer exists
// in CipherTrust Manager, in which case a warning is added. Otherwise an error is added.
// Unknown or null plan values and an unchanged vault_id are always allowed.
func azureVaultChangeAllowed(ctx context.Context, id string, client *common.Client, oldVaultID types.String, newVaultID types.String, diags *diag.Diagnostics) bool {
	if newVaultID.IsNull() || newVaultID.IsUnknown() || oldVaultID.IsNull() || oldVaultID.IsUnknown() {
		return true
	}
	if oldVaultID.ValueString() == newVaultID.ValueString() {
		return true
	}
	_, err := client.GetById(ctx, id, oldVaultID.ValueString(), azureVaultsEndpoint)
	if err == nil {
		diags.AddAttributeError(path.Root("vault_id"), "Attribute is immutable",
			"vault_id can only be changed if the previously configured vault no longer exists in CipherTrust Manager. "+
				"The vault "+oldVaultID.ValueString()+" still exists. To use a different vault, destroy and recreate the resource.")
		return false
	}
	if strings.Contains(err.Error(), notFoundError) {
		diags.AddAttributeWarning(path.Root("vault_id"), "Previous vault was not found, allowing update",
			"The previously configured vault "+oldVaultID.ValueString()+" no longer exists in CipherTrust Manager.")
		return true
	}
	details := utils.ApiError("Error checking the previously configured Azure vault.",
		map[string]interface{}{"error": err.Error(), "vault_id": oldVaultID.ValueString()})
	client.Log.Error(details)
	diags.AddAttributeError(path.Root("vault_id"), "Attribute is immutable", details)
	return false
}

// azureCertificatePolicyChanged reports whether azure_params.policy differs between state and plan in
// anything other than policy.attributes.enabled, which is updated in place. It must be called from
// ModifyPlan, after the attribute plan modifiers have resolved unknown computed values.
func azureCertificatePolicyChanged(plan types.Object, state types.Object) bool {
	if plan.IsNull() || plan.IsUnknown() || state.IsNull() || state.IsUnknown() {
		return false
	}
	return !azureCertificatePolicyMaskEnabled(plan).Equal(azureCertificatePolicyMaskEnabled(state))
}

// azureCertificatePolicyMaskEnabled returns the policy with attributes.enabled set to null.
func azureCertificatePolicyMaskEnabled(policy types.Object) types.Object {
	elements := policy.Attributes()
	attributes, ok := elements["attributes"].(types.Object)
	if !ok || attributes.IsNull() || attributes.IsUnknown() {
		return policy
	}
	masked := make(map[string]attr.Value, len(attributes.Attributes()))
	for key, value := range attributes.Attributes() {
		masked[key] = value
	}
	masked["enabled"] = types.BoolNull()
	maskedAttributes, diags := types.ObjectValue(azureCertAttributesAttrTypes, masked)
	if diags.HasError() {
		return policy
	}
	result := make(map[string]attr.Value, len(elements))
	for key, value := range elements {
		result[key] = value
	}
	result["attributes"] = maskedAttributes
	maskedPolicy, diags := types.ObjectValue(azureCertPolicyAttrTypes, result)
	if diags.HasError() {
		return policy
	}
	return maskedPolicy
}

// azureCertificateHasPolicy reports whether azure_params.policy is set in the configuration.
func azureCertificateHasPolicy(cfg *AzureCertificateTFSDK) bool {
	policy, ok := objectAttrs(cfg.AzureParams)["policy"].(types.Object)
	return ok && !policy.IsNull()
}

// azureCertificateModeCheck returns the attributes that are required but not configured, and the attributes
// that are configured but not allowed, for the mode selected by the configuration. It must be called with
// the configuration, because name and azure_params are computed and are never null in the plan.
// It returns the path of the mode block (or azure_params when creating natively) to attach the error to,
// and the name of the mode for the error message.
// hasState is true when the resource is already in state (a plan after create or import). A native certificate
// that has state does not need azure_params.policy in the configuration, because the policy comes from state.
func azureCertificateModeCheck(cfg *AzureCertificateTFSDK, hasState bool) (blockPath path.Path, mode string, missing []string, notAllowed []string) {
	switch {
	case cfg.RestoreCertificate != nil:
		blockPath, mode = path.Root("restore_certificate"), "restore_certificate"
		if cfg.RestoreCertificate.CertificateID.IsNull() {
			missing = append(missing, "restore_certificate.certificate_id")
		}
		if !cfg.Name.IsNull() {
			notAllowed = append(notAllowed, "name")
		}
		if !cfg.AzureParams.IsNull() {
			notAllowed = append(notAllowed, "azure_params")
		}
	case cfg.UploadCertificate != nil:
		blockPath, mode = path.Root("upload_certificate"), "upload_certificate"
		upload := cfg.UploadCertificate
		if cfg.Name.IsNull() {
			missing = append(missing, "name")
		}
		if upload.Certificate.IsNull() {
			// A certificate signed by a CipherTrust Manager CA needs all three of these.
			signed := []struct {
				name string
				null bool
			}{
				{"upload_certificate.source_cert_id", upload.SourceCertID.IsNull()},
				{"upload_certificate.ca_id", upload.CaID.IsNull()},
				{"upload_certificate.private_key_pem", upload.PrivateKeyPem.IsNull()},
			}
			var absent []string
			for _, s := range signed {
				if s.null {
					absent = append(absent, s.name)
				}
			}
			if len(absent) == len(signed) {
				missing = append(missing, "upload_certificate.certificate, or upload_certificate.source_cert_id, ca_id and private_key_pem")
			} else {
				missing = append(missing, absent...)
			}
		} else {
			// An external certificate is not signed by a CipherTrust Manager CA.
			if !upload.SourceCertID.IsNull() {
				notAllowed = append(notAllowed, "upload_certificate.source_cert_id")
			}
			if !upload.CaID.IsNull() {
				notAllowed = append(notAllowed, "upload_certificate.ca_id")
			}
		}
		if azureCertificateHasPolicy(cfg) {
			notAllowed = append(notAllowed, "azure_params.policy")
		}
	default:
		blockPath, mode = path.Root("azure_params"), "a native certificate"
		if cfg.Name.IsNull() {
			missing = append(missing, "name")
		}
		if !hasState && !azureCertificateHasPolicy(cfg) {
			missing = append(missing, "azure_params.policy")
		}
	}
	return blockPath, mode, missing, notAllowed
}

// addAzureCertificateModeError adds a single error that lists every missing and every not allowed attribute.
// It returns true when an error was added.
func addAzureCertificateModeError(diags *diag.Diagnostics, blockPath path.Path, mode string, missing []string, notAllowed []string) bool {
	if len(missing) == 0 && len(notAllowed) == 0 {
		return false
	}
	var detail []string
	if len(missing) > 0 {
		detail = append(detail, "Missing required attributes: "+strings.Join(missing, ", ")+".")
	}
	if len(notAllowed) > 0 {
		detail = append(detail, "Attributes not allowed: "+strings.Join(notAllowed, ", ")+".")
	}
	diags.AddAttributeError(blockPath, "Invalid configuration for "+mode, strings.Join(detail, "\n"))
	return true
}
