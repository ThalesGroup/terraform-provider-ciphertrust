package cckm

import (
	"context"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// azureKeyValidateRotationCreate errors if enable_auto_rotation is configured when a key is created or restored.
func azureKeyValidateRotationCreate(cfg *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	if cfg.EnableAutoRotation != nil {
		diags.AddAttributeError(path.Root("enable_auto_rotation"), "Attribute not allowed when creating a key",
			"enable_auto_rotation cannot be set when a key is created. Add it after the key has been created.")
	}
}

// azureKeyValidateBackupCreate errors if enable_auto_backup is configured when a key is created or restored.
func azureKeyValidateBackupCreate(cfg *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	if cfg.EnableAutoBackup != nil {
		diags.AddAttributeError(path.Root("enable_auto_backup"), "Attribute not allowed when creating a key",
			"enable_auto_backup cannot be set when a key is created. Add it after the key has been created.")
	}
}

// azureKeyValidateRotationPlan checks that key_size is set for key_type RSA and RSA-HSM, and ec_name for
// key_type EC and EC-HSM. EC and EC-HSM also require key_source native. Unknown values are skipped.
func azureKeyValidateRotationPlan(plan *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	rot := plan.EnableAutoRotation
	if rot == nil || rot.KeyType.IsNull() || rot.KeyType.IsUnknown() {
		return
	}
	switch rot.KeyType.ValueString() {
	case "RSA", "RSA-HSM":
		if rot.KeySize.IsNull() {
			diags.AddAttributeError(path.Root("enable_auto_rotation").AtName("key_size"), "Missing required attribute",
				"enable_auto_rotation.key_size is required when key_type is RSA or RSA-HSM.")
		}
	case "EC", "EC-HSM":
		if !rot.KeySource.IsNull() && !rot.KeySource.IsUnknown() && rot.KeySource.ValueString() != "native" {
			diags.AddAttributeError(path.Root("enable_auto_rotation").AtName("key_source"), "Invalid attribute combination",
				"enable_auto_rotation.key_source must be native when key_type is EC or EC-HSM.")
		}
		if rot.ECName.IsNull() {
			diags.AddAttributeError(path.Root("enable_auto_rotation").AtName("ec_name"), "Missing required attribute",
				"enable_auto_rotation.ec_name is required when key_type is EC or EC-HSM.")
		}
	}
}

// azureKeyValidateCreateConfig validates the configuration of a key that is being created. The mode is
// chosen by the configuration: restore_key restores a key, upload_key uploads key material, otherwise a
// native key is created. Exactly one mode may be used. Unknown values are skipped.
func azureKeyValidateCreateConfig(_ context.Context, cfg *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	restore := cfg.RestoreKey != nil
	upload := cfg.UploadKey != nil

	if restore {
		if upload {
			diags.AddAttributeError(path.Root("upload_key"), "Conflicting attributes",
				"upload_key cannot be set when restore_key is set. Set one of them or neither.")
		}
		configured := []struct {
			name string
			set  bool
		}{
			{"name", !cfg.Name.IsNull()},
			{"azure_params", !cfg.AzureParams.IsNull()},
			{"exportable", !cfg.Exportable.IsNull()},
			{"release_policy", !cfg.ReleasePolicy.IsNull()},
		}
		for _, c := range configured {
			if c.set {
				diags.AddAttributeError(path.Root(c.name), "Attribute not allowed when restoring a key",
					c.name+" cannot be set when restore_key is set. "+
						"The key is restored with the attributes it had when it was backed up.")
			}
		}
		return
	}

	if cfg.Name.IsNull() {
		diags.AddAttributeError(path.Root("name"), "Missing required attribute",
			"name is required when restore_key is not set.")
	}
	if upload {
		azureKeyValidateUploadKey(cfg.UploadKey, diags)
	}
	if cfg.AzureParams.IsUnknown() {
		return
	}
	if cfg.AzureParams.IsNull() && !upload {
		diags.AddAttributeError(path.Root("azure_params"), "Missing required attribute",
			"azure_params is required when neither restore_key nor upload_key is set.")
		return
	}

	v := newAzureParamsView(cfg.AzureParams)
	if upload {
		// The type, curve and size of an uploaded key come from the key material.
		notAllowed := []struct {
			path path.Path
			name string
			set  bool
		}{
			{azureParamsPath("key", "kty"), "azure_params.key.kty", !v.Kty.IsNull()},
			{azureParamsPath("key", "curve"), "azure_params.key.curve", !v.Curve.IsNull()},
			{azureParamsPath("key_size"), "azure_params.key_size", !v.KeySize.IsNull()},
		}
		for _, n := range notAllowed {
			if n.set {
				diags.AddAttributeError(n.path, "Attribute not allowed when uploading a key",
					n.name+" cannot be set when upload_key is set. It is taken from the uploaded key. Use upload_key.hsm to create an HSM key.")
			}
		}
	} else {
		azureKeyValidateNativeParams(v, diags)
	}

	if !cfg.Exportable.IsNull() && !cfg.Exportable.IsUnknown() && cfg.Exportable.ValueBool() &&
		cfg.ReleasePolicy.IsNull() {
		diags.AddAttributeError(path.Root("release_policy"), "Missing required attribute",
			"release_policy is required when exportable is true.")
	}
	if azureKeyDateNotAfter(v.ExpirationDate, v.ActivationDate) {
		diags.AddAttributeError(azureParamsPath("attributes", "expiration_date"), "Invalid date",
			"azure_params.attributes.expiration_date must be later than azure_params.attributes.activation_date.")
	}
}

// azureKeyValidateUploadKey checks that the attributes that supply the key material match source_key_tier.
// Nothing is checked while source_key_tier is not yet known.
func azureKeyValidateUploadKey(u *models.AzureUploadKeyTFSDK, diags *diag.Diagnostics) {
	if u.SourceKeyTier.IsUnknown() || u.SourceKeyTier.IsNull() {
		return
	}
	uploadPath := path.Root("upload_key")
	if u.SourceKeyTier.ValueString() == azureSourceKeyTierPfx {
		if u.Pfx.IsNull() {
			diags.AddAttributeError(uploadPath.AtName("pfx"), "Missing attribute",
				"upload_key.pfx is required when upload_key.source_key_tier is pfx.")
		}
		if !u.SourceKeyID.IsNull() {
			diags.AddAttributeError(uploadPath.AtName("source_key_id"), "Invalid attribute",
				"upload_key.source_key_id cannot be set when upload_key.source_key_tier is pfx.")
		}
		return
	}
	if u.SourceKeyID.IsNull() {
		diags.AddAttributeError(uploadPath.AtName("source_key_id"), "Missing attribute",
			"upload_key.source_key_id is required when upload_key.source_key_tier is not pfx.")
	}
	if !u.Pfx.IsNull() {
		diags.AddAttributeError(uploadPath.AtName("pfx"), "Invalid attribute",
			"upload_key.pfx can only be set when upload_key.source_key_tier is pfx.")
	}
	if !u.PfxPassword.IsNull() {
		diags.AddAttributeError(uploadPath.AtName("pfx_password"), "Invalid attribute",
			"upload_key.pfx_password can only be set when upload_key.source_key_tier is pfx.")
	}
}

// azureKeyValidateNativeParams checks the key parameters of a native key: kty is required, RSA needs
// key_size and rejects curve, EC needs curve and rejects key_size, and import is only valid for RSA-HSM.
func azureKeyValidateNativeParams(v azureParamsView, diags *diag.Diagnostics) {
	if v.Kty.IsNull() {
		diags.AddAttributeError(azureParamsPath("key", "kty"), "Missing required attribute",
			"azure_params.key.kty is required when neither restore_key nor upload_key is set.")
		return
	}
	if v.Kty.IsUnknown() {
		return
	}
	kty := v.Kty.ValueString()
	switch {
	case strings.HasPrefix(kty, "RSA"):
		if v.KeySize.IsNull() {
			diags.AddAttributeError(azureParamsPath("key_size"), "Missing required attribute",
				"azure_params.key_size is required for kty "+kty+".")
		}
		if !v.Curve.IsNull() {
			diags.AddAttributeError(azureParamsPath("key", "curve"), "Attribute not allowed",
				"azure_params.key.curve cannot be set for kty "+kty+".")
		}
	case strings.HasPrefix(kty, "EC"):
		if v.Curve.IsNull() {
			diags.AddAttributeError(azureParamsPath("key", "curve"), "Missing required attribute",
				"azure_params.key.curve is required for kty "+kty+".")
		}
		if !v.KeySize.IsNull() {
			diags.AddAttributeError(azureParamsPath("key_size"), "Attribute not allowed",
				"azure_params.key_size cannot be set for kty "+kty+".")
		}
	}
	if kty != "RSA-HSM" && !v.KeyOps.IsNull() && !v.KeyOps.IsUnknown() {
		for _, op := range azureKeyListToStrings(v.KeyOps) {
			if op == "import" {
				diags.AddAttributeError(azureParamsPath("key", "key_ops"), "Invalid key operation",
					"The import key operation is only valid for kty RSA-HSM.")
				break
			}
		}
	}
}

// azureKeyDateNotAfter returns true when both dates are known, valid RFC3339 values and
// expiration is not later than activation. A date that cannot be parsed is skipped here
// because the payload builder reports it.
func azureKeyDateNotAfter(expiration, activation types.String) bool {
	if expiration.IsNull() || expiration.IsUnknown() || activation.IsNull() || activation.IsUnknown() {
		return false
	}
	e, err := time.Parse(time.RFC3339, expiration.ValueString())
	if err != nil {
		return false
	}
	a, err := time.Parse(time.RFC3339, activation.ValueString())
	if err != nil {
		return false
	}
	return !e.After(a)
}

// azureKeyValidateUpdatePlan validates the planned values of an existing key. It uses the plan because
// omitted optional+computed values are resolved from state there. Unknown values are skipped.
func azureKeyValidateUpdatePlan(_ context.Context, plan *models.AzureKeyTFSDK, diags *diag.Diagnostics) {
	if plan.AzureParams.IsNull() || plan.AzureParams.IsUnknown() {
		return
	}
	v := newAzureParamsView(plan.AzureParams)
	if !v.Kty.IsNull() && !v.Kty.IsUnknown() && v.Kty.ValueString() != "RSA-HSM" && !v.KeyOps.IsNull() && !v.KeyOps.IsUnknown() {
		for _, op := range azureKeyListToStrings(v.KeyOps) {
			if op == "import" {
				diags.AddAttributeError(azureParamsPath("key", "key_ops"), "Invalid key operation",
					"The import key operation is only valid for kty RSA-HSM.")
				break
			}
		}
	}
	if azureKeyDateNotAfter(v.ExpirationDate, v.ActivationDate) {
		diags.AddAttributeError(azureParamsPath("attributes", "expiration_date"), "Invalid date",
			"azure_params.attributes.expiration_date must be later than azure_params.attributes.activation_date.")
	}
}
