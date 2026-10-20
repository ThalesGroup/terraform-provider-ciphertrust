package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/validators"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/objectvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMAzureSecret{}
	_ resource.ResourceWithConfigure   = &resourceCCKMAzureSecret{}
	_ resource.ResourceWithImportState = &resourceCCKMAzureSecret{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMAzureSecret{}
)

const (
	// azureSecretsEndpoint is the CipherTrust Manager endpoint for Azure secrets.
	azureSecretsEndpoint = common.URL_AZURE + "/secrets"

	azureSecretAvailable   = "AVAILABLE"
	azureSecretSoftDeleted = "SOFT-DELETED"
)

// NewResourceCCKMAzureSecret returns a new instance of the ciphertrust_azure_secret resource.
func NewResourceCCKMAzureSecret() resource.Resource {
	return &resourceCCKMAzureSecret{}
}

type resourceCCKMAzureSecret struct {
	client *common.Client
}

func (r *resourceCCKMAzureSecret) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_secret"
}

func (r *resourceCCKMAzureSecret) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	nonBlank := regexp.MustCompile(`\S`)
	secretName := regexp.MustCompile(`^[0-9a-zA-Z-]{1,127}$`)

	resp.Schema = schema.Schema{
		Description: "Use this resource to add a secret to a CipherTrust Manager Azure vault. " +
			"The mode is chosen by whether restore_secret is set.\n\n" +
			"- No block (default): creates a new secret in the vault from name and azure_params.\n" +
			"- restore_secret: restores a purged secret from its backup into the vault nominated by vault_id.\n\n" +
			"All inputs are immutable except `azure_params.content_type`, `azure_params.tags` and " +
			"`azure_params.attributes`, which are updated in place.\n\n" +
			"To create a new version of a secret, create another secret resource with the same name.\n\n" +
			"If a soft-deleted secret of the same name exists in the vault, creating the resource recovers it " +
			"instead of creating a new secret. This requires `recover_soft_deleted_secrets` to be true in the " +
			"provider settings, otherwise the create fails.\n\n" +
			"On destroy, the secret is soft-deleted and, if `purge_secrets_on_delete` is true in the provider " +
			"settings (the default), purged. If it is false, the secret is only soft-deleted.\n\n" +
			"The secret value is not read back after it is created. After an import `azure_params.value` is null " +
			"and can be set in the configuration without forcing a change.",
		Attributes: map[string]schema.Attribute{
			// Inputs
			"name": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "(Immutable) Name of the secret. May contain only alphanumeric characters and hyphens. " +
					"Required unless restore_secret is set, in which case it cannot be set.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(secretName, "must be 1 to 127 alphanumeric characters or hyphens"),
					stringvalidator.ConflictsWith(path.MatchRoot("restore_secret")),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					modifiers.ImmutableString(),
				},
			},
			"vault_id": schema.StringAttribute{
				Required: true,
				Description: "(Conditionally immutable) CipherTrust Manager resource ID of the Azure vault that contains the secret. " +
					"Can only be changed if the previously configured vault no longer exists in CipherTrust Manager. " +
					"When restore_secret is set this is the vault the secret is restored to; it can be any vault. " +
					"A vault name is not accepted.",
				Validators: []validator.String{stringvalidator.RegexMatches(nonBlank, "must contain at least one non-whitespace character")},
			},
			"restore_secret": schema.SingleNestedAttribute{
				Optional: true,
				Description: "(Immutable) Restores a purged secret into `vault_id` instead of creating a new one. " +
					"Cannot be combined with `name` or `azure_params`.",
				Validators: []validator.Object{
					objectvalidator.ConflictsWith(path.MatchRoot("azure_params")),
				},
				PlanModifiers: []planmodifier.Object{
					modifiers.ImmutableObject(),
				},
				Attributes: map[string]schema.Attribute{
					"secret_id": schema.StringAttribute{
						Required: true,
						Description: "CipherTrust Manager resource ID of the purged secret to restore. " +
							"It is no longer in Terraform state.",
						Validators: []validator.String{stringvalidator.RegexMatches(nonBlank, "must contain at least one non-whitespace character")},
					},
				},
			},
			"azure_params": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				Description: "Azure secret parameters. `value` is required unless `restore_secret` is set. " +
					"Cannot be set when `restore_secret` is set.",
				PlanModifiers: []planmodifier.Object{
					objectplanmodifier.UseStateForUnknown(),
				},
				Attributes: map[string]schema.Attribute{
					"value": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "(Immutable) Value of the secret.",
						PlanModifiers: []planmodifier.String{
							modifiers.ImmutableSensitiveString(),
						},
					},
					"content_type": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Type of the secret value, for example password.",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"tags": schema.MapAttribute{
						Optional:    true,
						Computed:    true,
						ElementType: types.StringType,
						Description: "Application specific metadata in the form of key-value pairs. " +
							"Removing the attribute from the configuration does not clear " +
							"the tags, set it to an empty map (`tags = {}`) to remove all tags.",
						PlanModifiers: []planmodifier.Map{
							mapplanmodifier.UseStateForUnknown(),
						},
					},
					"attributes": schema.SingleNestedAttribute{
						Optional:      true,
						Computed:      true,
						Description:   "Attributes of the secret.",
						PlanModifiers: []planmodifier.Object{objectplanmodifier.UseStateForUnknown()},
						Attributes: map[string]schema.Attribute{
							"enabled": schema.BoolAttribute{
								Optional:    true,
								Computed:    true,
								Description: "Whether the secret is enabled.",
								PlanModifiers: []planmodifier.Bool{
									boolplanmodifier.UseStateForUnknown(),
								},
							},
							"activation_date": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "Date of secret activation in UTC time in RFC3339 format. For example, 2026-07-03T14:24:00Z. " +
									"Before this time the secret cannot be used. A date cannot be cleared once it is set.",
								Validators:    []validator.String{validators.RFC3339()},
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
							"expiration_date": schema.StringAttribute{
								Optional: true,
								Computed: true,
								Description: "Date of secret expiry in UTC time in RFC3339 format. For example, 2030-07-03T14:24:00Z. " +
									"Must be later than activation_date. A date cannot be cleared once it is set.",
								Validators:    []validator.String{validators.RFC3339()},
								PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
							},
						},
					},
					"secret_id": schema.StringAttribute{
						Computed:    true,
						Description: "Azure identifier of the secret.",
					},
					"recoverable_days": schema.Int64Attribute{
						Computed:    true,
						Description: "Number of days a soft-deleted secret can be recovered.",
					},
					"recovery_level": schema.StringAttribute{
						Computed:    true,
						Description: "Azure recovery level of the secret.",
					},
				},
			},

			// Computed attributes.
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager resource ID of the secret.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager URI of the secret.",
			},
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager account that owns the secret.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the secret was created in CipherTrust Manager.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the secret was last updated in CipherTrust Manager.",
			},
			"synced_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the secret was last synchronized with Azure.",
			},
			"created_by": schema.StringAttribute{
				Computed:    true,
				Description: "Identity that created the secret.",
			},
			"modified_by": schema.StringAttribute{
				Computed:    true,
				Description: "Identity that last modified the secret.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Status of the secret.",
			},
			"version": schema.StringAttribute{
				Computed:      true,
				Description:   "Azure version of the secret.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"version_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of versions of the secret.",
			},
			"deleted": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the secret is deleted.",
			},
			"gone": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the secret no longer exists in Azure.",
			},
			"secret_soft_deleted_in_azure": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the secret is soft-deleted in Azure.",
			},
			"backup": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager resource ID of the Azure secret backup.",
			},
			"backup_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the secret was last backed up.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "Azure cloud of the vault.",
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "Azure region of the vault.",
			},
			"tenant": schema.StringAttribute{
				Computed:    true,
				Description: "Azure tenant of the vault.",
			},
			"vault_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the Azure vault that contains the secret.",
			},
			"soft_delete_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether soft delete is enabled on the vault.",
			},
			"azure_created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the secret was created in Azure.",
			},
			"azure_updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time the secret was last updated in Azure.",
			},
		},
	}
}

func (r *resourceCCKMAzureSecret) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Error in fetching client from provider",
			fmt.Sprintf("Expected *provider.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	r.client = client
}

// Create restores, recovers or creates the secret, then builds state from a read of it.
func (r *resourceCCKMAzureSecret) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> Create][" + id + "]")

	var plan AzureSecretTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := plan.VaultID.ValueString()
	vaultResp := getAzureVault(ctx, id, r.client, vaultID, "creating secret in", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if gjson.Get(vaultResp, "id").String() != vaultID {
		details := utils.ApiError(
			"Error creating Azure secret: vault_id must be the CipherTrust Manager resource ID of an Azure vault.",
			map[string]interface{}{"vault_id": vaultID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	mutexKey := fmt.Sprintf("azure-secret-%s", vaultID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	var response string
	if plan.RestoreSecret != nil {
		response = restoreAzureSecret(ctx, id, r.client, plan.RestoreSecret.SecretID.ValueString(), vaultID, &resp.Diagnostics)
	} else {
		response = createNativeAzureSecret(ctx, id, r.client, &plan, &resp.Diagnostics)
	}
	if response == "" || resp.Diagnostics.HasError() {
		return
	}

	// Read the secret back so that state is built from the same response as Read.
	response = getAzureSecret(ctx, id, r.client, gjson.Get(response, "id").String(), "creating", &resp.Diagnostics)
	if response == "" || resp.Diagnostics.HasError() {
		return
	}

	r.client.Log.Info(fmt.Sprintf("SARAH create response: %s", response))

	if err := azureSecretSetState(response, &plan); err != nil {
		details := utils.ApiError("Error creating Azure secret, failed to parse the response.",
			map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the secret state from CipherTrust Manager. A 404 is a hard error.
func (r *resourceCCKMAzureSecret) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> Read][" + id + "]")

	var state AzureSecretTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response := getAzureSecret(ctx, id, r.client, state.ID.ValueString(), "reading", &resp.Diagnostics)
	if response == "" || resp.Diagnostics.HasError() {
		return
	}
	if err := azureSecretSetState(response, &state); err != nil {
		details := utils.ApiError("Error reading Azure secret, failed to parse the response.",
			map[string]interface{}{"error": err.Error(), "secret_id": state.ID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// ImportState imports a secret using its CipherTrust Manager resource ID. Read populates the rest. A
// soft-deleted secret is recovered first when recover_soft_deleted_secrets is true, otherwise the import
// fails, because a soft-deleted secret cannot be used.
func (r *resourceCCKMAzureSecret) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> ImportState][" + id + "]")

	existing := getAzureSecret(ctx, id, r.client, req.ID, "importing", &resp.Diagnostics)
	if existing == "" || resp.Diagnostics.HasError() {
		return
	}
	if gjson.Get(existing, "status").String() == azureSecretSoftDeleted {
		if !r.client.CCKMConfig.AzureCCKMSettings.RecoverSoftDeletedSecrets {
			details := utils.ApiError(
				"Error importing Azure secret. The secret is soft-deleted and cannot be imported as is. "+
					"Set the provider option of recover_soft_deleted_secrets to true in the provider settings and import again.",
				map[string]interface{}{"name": gjson.Get(existing, "secret_name").String(), "secret_id": req.ID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		mutexKey := fmt.Sprintf("azure-secret-%s", gjson.Get(existing, "key_vault_id").String())
		mutex.CckmMutex.Lock(mutexKey)
		defer mutex.CckmMutex.Unlock(mutexKey)

		if recovered := recoverAzureSecret(ctx, id, r.client, req.ID, &resp.Diagnostics); recovered == "" || resp.Diagnostics.HasError() {
			return
		}
	}
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// Update changes content_type, tags and attributes with a single PATCH. Every other input is immutable and is
// rejected at plan time.
func (r *resourceCCKMAzureSecret) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> Update][" + id + "]")

	var plan, state AzureSecretTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	mutexKey := fmt.Sprintf("azure-secret-%s", state.VaultID.ValueString())
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	secretID := state.ID.ValueString()
	response := getAzureSecret(ctx, id, r.client, secretID, "updating", &resp.Diagnostics)
	if response == "" || resp.Diagnostics.HasError() {
		return
	}

	body, changed, err := azureSecretUpdatePayload(&plan, &state)
	b, _ := json.Marshal(body)
	r.client.Log.Info(fmt.Sprintf("SARAH update body: %s\n", string(b)))
	if err != nil {
		details := utils.ApiError("Error updating Azure secret, invalid configuration.",
			map[string]interface{}{"error": err.Error(), "secret_id": secretID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	if changed {
		payload, err := json.Marshal(body)
		if err != nil {
			details := utils.ApiError("Error updating Azure secret, failed to build the request.",
				map[string]interface{}{"error": err.Error(), "secret_id": secretID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		patchResponse, err := azureUpdateDataV2WithRetry(ctx, id, r.client, azureSecretsEndpoint, secretID, payload)
		if err != nil {
			details := utils.ApiError("Error updating Azure secret.",
				map[string]interface{}{"error": err.Error(), "secret_id": secretID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		r.client.Log.Debug("[resource_azure_secret.go -> Update][" + id + "][patch response:" + redactAzureSecretResponse(patchResponse) + "]")
		// The response read before the PATCH is stale, so read the secret again to get the new values.
		response = getAzureSecret(ctx, id, r.client, secretID, "updating", &resp.Diagnostics)
		if response == "" || resp.Diagnostics.HasError() {
			return
		}
		r.client.Log.Info(fmt.Sprintf("SARAH update response: %s", response))
	}

	// vault_id is conditionally immutable. When it was repointed because the old vault no longer exists,
	// the response may still carry the old vault, so the planned value is kept.
	plannedVaultID := plan.VaultID
	if err := azureSecretSetState(response, &plan); err != nil {
		details := utils.ApiError("Error updating Azure secret, failed to parse the response.",
			map[string]interface{}{"error": err.Error(), "secret_id": secretID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	plan.VaultID = plannedVaultID
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete soft-deletes a secret and, when purge_secrets_on_delete is true and the secret is purgeable, purges it.
// A purge straight after a soft-delete can return 409, so the POSTs are retried. Each step is done only if it is
// still needed, so a destroy that failed part way can be run again.
func (r *resourceCCKMAzureSecret) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> Delete][" + id + "]")

	var state AzureSecretTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	secretID := state.ID.ValueString()
	response := getAzureSecret(ctx, id, r.client, secretID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() || response == "" {
		return
	}

	mutexKey := fmt.Sprintf("azure-secret-%s", gjson.Get(response, "key_vault_id").String())
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	name := gjson.Get(response, "secret_name").String()
	r.client.Log.Debug("[resource_azure_secret.go -> Delete][" + id + "] Secret before delete: status=" +
		gjson.Get(response, "status").String() +
		" deleted=" + gjson.Get(response, "deleted").String() +
		" secret_soft_deleted_in_azure=" + gjson.Get(response, "secret_soft_deleted_in_azure").String() +
		" recovery_level=" + gjson.Get(response, "azure_param.attributes.recovery_level").String())

	if gjson.Get(response, "deleted").Bool() {
		return
	}
	if gjson.Get(response, "status").String() == azureSecretAvailable {
		softDelResponse, err := azurePostNoDataWithRetry(ctx, id, r.client, azureSecretsEndpoint+"/"+secretID+"/soft-delete")
		if err != nil {
			details := utils.ApiError("Error soft deleting Azure secret.",
				map[string]interface{}{"error": err.Error(), "secret_id": secretID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		r.client.Log.Info("[resource_azure_secret.go -> Delete][" + id + "] Soft deleted Azure secret " + name)
		r.client.Log.Debug("[resource_azure_secret.go -> Soft-Delete][" + id + "][response:" + redactAzureSecretResponse(softDelResponse) + "]")
	}

	recoveryLevel := gjson.Get(response, "azure_param.attributes.recovery_level").String()
	if !strings.Contains(recoveryLevel, "Purgeable") {
		r.client.Log.Info("[resource_azure_secret.go -> Delete][" + id + "] Not purging " + name + " as the secret is not purgeable")
		return
	}
	if !r.client.CCKMConfig.AzureCCKMSettings.PurgeSecretsOnDelete {
		r.client.Log.Info("[resource_azure_secret.go -> Delete][" + id + "] Not purging " + name + " as purge_secrets_on_delete is false")
		return
	}
	purgeResponse, err := azurePostNoDataWithRetry(ctx, id, r.client, azureSecretsEndpoint+"/"+secretID+"/hard-delete")
	if err != nil {
		details := utils.ApiError("Error purging Azure secret.",
			map[string]interface{}{"error": err.Error(), "secret_id": secretID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Info("[resource_azure_secret.go -> Delete][" + id + "] Purged Azure secret " + name)
	r.client.Log.Debug("[resource_azure_secret.go -> Hard-Delete][" + id + "][response:" + redactAzureSecretResponse(purgeResponse) + "]")
}

// ModifyPlan checks the configuration for the mode selected, and that the expiration date is later than the
// activation date. name and azure_params are computed, so the configuration is used to see what the user set.
func (r *resourceCCKMAzureSecret) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> ModifyPlan]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> ModifyPlan]")

	// destroy - nothing to validate
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan AzureSecretTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hasState := !req.State.Raw.IsNull()
	if hasState {
		var state AzureSecretTFSDK
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !azureVaultChangeAllowed(ctx, uuid.New().String(), r.client, state.VaultID, plan.VaultID, &resp.Diagnostics) {
			return
		}
		if plan.RestoreSecret == nil && state.RestoreSecret != nil {
			resp.Diagnostics.AddAttributeError(path.Root("restore_secret"), "Attribute is immutable",
				"restore_secret cannot be removed after creation. "+
					"To change this attribute, destroy and recreate the resource.")
			return
		}
	}

	var cfg AzureSecretTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Mode check: restore_secret selects the restore mode, otherwise the secret is a native secret. A secret
	// that has state does not need azure_params.value in the configuration, because it is not read back and
	// is null after an import.
	var missing, notAllowed []string
	blockPath, mode := path.Root("azure_params"), "a native secret"
	if cfg.RestoreSecret != nil {
		blockPath, mode = path.Root("restore_secret"), "restore_secret"
		if cfg.RestoreSecret.SecretID.IsNull() {
			missing = append(missing, "restore_secret.secret_id")
		}
		if !cfg.Name.IsNull() {
			notAllowed = append(notAllowed, "name")
		}
		if !cfg.AzureParams.IsNull() {
			notAllowed = append(notAllowed, "azure_params")
		}
	} else {
		if cfg.Name.IsNull() {
			missing = append(missing, "name")
		}
		if !hasState && attrString(objectAttrs(cfg.AzureParams), "value").IsNull() {
			missing = append(missing, "azure_params.value")
		}
	}
	if addAzureCertificateModeError(&resp.Diagnostics, blockPath, mode, missing, notAllowed) {
		return
	}
	if cfg.RestoreSecret != nil {
		return
	}

	attributes := objectAttrs(objectAttrs(cfg.AzureParams)["attributes"])
	if azureKeyDateNotAfter(attrString(attributes, "expiration_date"), attrString(attributes, "activation_date")) {
		resp.Diagnostics.AddAttributeError(
			path.Root("azure_params").AtName("attributes").AtName("expiration_date"),
			"Invalid expiration date",
			"azure_params.attributes.expiration_date must be later than azure_params.attributes.activation_date.")
	}
}

// createNativeAzureSecret creates a secret, or recovers a soft-deleted secret of the same name when
// recover_soft_deleted_secrets is true. It returns the response, or "" with an error in diags.
func createNativeAzureSecret(ctx context.Context, id string, client *common.Client, plan *AzureSecretTFSDK, diags *diag.Diagnostics) string {
	name := plan.Name.ValueString()
	if client.CCKMConfig.AzureCCKMSettings.RecoverSoftDeletedSecrets {
		existing := findSoftDeletedAzureSecret(ctx, id, client, plan.VaultID.ValueString(), name, diags)
		if diags.HasError() {
			return ""
		}
		if existing != "" {
			// Recover only makes the soft-deleted secret available again. Nothing is created, so its ID and
			// version are unchanged. When recover_soft_deleted_secrets is false the create below goes ahead
			// and fails because the name is still held by the soft-deleted secret.
			return recoverAzureSecret(ctx, id, client, gjson.Get(existing, "id").String(), diags)
		}
	}
	body, err := azureSecretCreatePayload(plan)
	b, _ := json.Marshal(body)
	client.Log.Info(fmt.Sprintf("SARAH create body: %s\n", string(b)))
	if err != nil {
		details := utils.ApiError("Error creating Azure secret, invalid configuration.",
			map[string]interface{}{"error": err.Error(), "name": name})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	payloadJSON, err := json.Marshal(body)
	if err != nil {
		details := utils.ApiError("Error creating Azure secret, invalid request.",
			map[string]interface{}{"error": err.Error(), "name": name})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := azurePostDataV2WithRetry(ctx, id, client, azureSecretsEndpoint, payloadJSON)
	if err != nil {
		details := utils.ApiError("Error creating Azure secret.",
			map[string]interface{}{"error": err.Error(), "name": name})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Debug("[resource_azure_secret.go -> Create][response:" + redactAzureSecretResponse(response) + "]")
	if gjson.Get(response, "id").String() == "" {
		details := utils.ApiError("Error creating Azure secret, the response did not contain a secret ID.",
			map[string]interface{}{"name": name})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// restoreAzureSecret restores a secret from its backup into the vault. restoreID is the CipherTrust Manager ID of
// the secret to restore. CipherTrust Manager rejects the request if the secret cannot be restored. On failure an
// error diagnostic is added and "" is returned.
func restoreAzureSecret(ctx context.Context, id string, client *common.Client, restoreID string, vaultID string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> restoreAzureSecret][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> restoreAzureSecret][" + id + "]")

	payloadJSON, err := json.Marshal(models.AzureRestoreSecretPayloadJSON{KeyVault: vaultID})
	if err != nil {
		details := utils.ApiError("Error restoring Azure secret, invalid request.",
			map[string]interface{}{"error": err.Error(), "restore_secret.secret_id": restoreID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := azurePostDataV2WithRetry(ctx, id, client, azureSecretsEndpoint+"/"+restoreID+"/restore", payloadJSON)
	if err != nil {
		details := utils.ApiError("Error restoring Azure secret.",
			map[string]interface{}{"error": err.Error(), "restore_secret.secret_id": restoreID, "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Debug("[resource_azure_secret.go -> Restore][response:" + redactAzureSecretResponse(response) + "]")
	if gjson.Get(response, "id").String() == "" {
		details := utils.ApiError("Error restoring Azure secret, the response did not contain a secret ID.",
			map[string]interface{}{"restore_secret.secret_id": restoreID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// recoverAzureSecret recovers a soft-deleted secret. The callers check that recover_soft_deleted_secrets is true
// before calling it. It returns a JSON object that contains the secret ID, or "" with an error in diags.
func recoverAzureSecret(ctx context.Context, id string, client *common.Client, secretID string, diags *diag.Diagnostics) string {
	endpoint := azureSecretsEndpoint + "/" + secretID + "/recover"
	client.Log.Debug("[resource_azure_secret.go -> recoverAzureSecret][" + id + "][request: POST " + endpoint + ", payload: {}]")
	response, err := azurePostDataV2WithRetry(ctx, id, client, endpoint, []byte("{}"))
	if err != nil {
		details := utils.ApiError("Error recovering soft-deleted Azure secret.",
			map[string]interface{}{"error": err.Error(), "secret_id": secretID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	client.Log.Debug("[resource_azure_secret.go -> recoverAzureSecret][" + id + "][response:" + redactAzureSecretResponse(response) + "]")
	// The ID of the secret is known, so the recover response is not relied on for it.
	return `{"id":"` + secretID + `"}`
}

// findSoftDeletedAzureSecret returns the JSON of a soft-deleted secret of the given name in a vault, or "" when
// there is none.
func findSoftDeletedAzureSecret(ctx context.Context, id string, client *common.Client, vaultID string, name string, diags *diag.Diagnostics) string {
	filters := url.Values{}
	filters.Set("secret_name", name)
	filters.Set("key_vault_id", vaultID)
	response, err := client.ListWithFilters(ctx, id, azureSecretsEndpoint, filters)
	if err != nil {
		details := utils.ApiError("Error creating Azure secret, failed to list secrets.",
			map[string]interface{}{"error": err.Error(), "name": name, "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	for _, secret := range gjson.Get(response, "resources").Array() {
		if secret.Get("status").String() == azureSecretSoftDeleted {
			return secret.Raw
		}
	}
	return ""
}

// getAzureSecret fetches an Azure secret by its CipherTrust Manager ID.
// If the secret is not found (404):
//   - opLabel "deleting": warning added, "" returned - resource will be removed from state.
//   - any other opLabel: error added, "" returned - state is preserved.
//
// A non-404 error is always a hard error. "" is returned.
func getAzureSecret(ctx context.Context, id string, client *common.Client, secretID string, opLabel string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_secret.go -> getAzureSecret][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_secret.go -> getAzureSecret][" + id + "]")

	response, err := client.GetById(ctx, id, secretID, azureSecretsEndpoint)
	if err == nil {
		client.Log.Trace("[resource_azure_secret.go -> Get][response:" + redactAzureSecretResponse(response) + "]")
		return response
	}
	if strings.Contains(err.Error(), notFoundError) {
		if opLabel == "deleting" {
			details := utils.ApiError("Azure secret was not found. It will be removed from state.",
				map[string]interface{}{"secret_id": secretID})
			client.Log.Warn(details)
			diags.AddWarning(details, "")
			return ""
		}
		details := utils.ApiError(fmt.Sprintf(utils.NotFoundRetainedFmt, "Azure secret"),
			map[string]interface{}{"secret_id": secretID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	details := utils.ApiError("Error "+opLabel+" Azure secret, failed to read Azure secret.",
		map[string]interface{}{"error": err.Error(), "secret_id": secretID})
	client.Log.Error(details)
	diags.AddError(details, "")
	return ""
}

// redactAzureSecretResponse returns a safe-to-log version of an Azure secret API response. The secret value is
// returned in plain text by a GET, so it is always redacted. key_vault has the form <vault name>::<subscription
// id>, only the subscription id is redacted.
func redactAzureSecretResponse(response string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		return response
	}
	if keyVault, ok := data["key_vault"].(string); ok {
		if name, _, found := strings.Cut(keyVault, "::"); found {
			data["key_vault"] = name + "::redacted"
		}
	}
	for _, field := range []string{"azure_vault_id", "subscription_id", "tenant"} {
		if _, ok := data[field]; ok {
			data[field] = "redacted"
		}
	}
	if azureParam, ok := data["azure_param"].(map[string]interface{}); ok {
		for _, field := range []string{"value", "tags"} {
			if _, ok := azureParam[field]; ok {
				azureParam[field] = "redacted"
			}
		}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return response
	}
	return string(b)
}
