package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/tidwall/gjson"
)

const (
	notFoundError = "status: 404"
)

var (
	_ resource.Resource                = &resourceCCKMAzureVault{}
	_ resource.ResourceWithConfigure   = &resourceCCKMAzureVault{}
	_ resource.ResourceWithImportState = &resourceCCKMAzureVault{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMAzureVault{}
)

// NewResourceCCKMAzureVault returns a new instance of the ciphertrust_azure_vault resource.
func NewResourceCCKMAzureVault() resource.Resource {
	return &resourceCCKMAzureVault{}
}

type resourceCCKMAzureVault struct {
	client *common.Client
}

func (r *resourceCCKMAzureVault) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_vault"
}

func (r *resourceCCKMAzureVault) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMAzureVault) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to add and manage Azure Key Vaults in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			// Required user inputs
			"name": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Name of the Azure Key Vault to add to CipherTrust Manager.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "Resource ID of the CipherTrust Manager Azure connection used to access the vault.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"subscription_id": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) Azure subscription ID that contains the vault.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			// Optional user inputs
			"cloud_key_backup_limit": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Maximum number of key backups allowed for this vault. Must be greater than zero and at most 65535. Set to 0 (or omit) for no limit.",
				Validators: []validator.Int64{
					int64validator.AtLeast(1),
				},
			},
			"vault_details": schema.SingleNestedAttribute{
				Optional: true,
				Description: "(Immutable) Vault details returned by the ciphertrust_azure_vault_details data source. " +
					"When provided, vault details are taken from this block and the vault is not separately " +
					"fetched from Azure during creation. The name within vault_details must match name. " +
					"If omitted, vault details are fetched from Azure.",
				Attributes: map[string]schema.Attribute{
					"name": schema.StringAttribute{
						Optional:    true,
						Description: "Vault name. Must match name.",
					},
					"azure_vault_id": schema.StringAttribute{
						Optional:    true,
						Description: "Azure resource ID of the vault.",
					},
					"vault_type": schema.StringAttribute{
						Optional:    true,
						Description: "Azure resource type.",
					},
					"location": schema.StringAttribute{
						Optional:    true,
						Description: "Azure region where the vault is located.",
					},
					"tags": schema.MapAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Azure tags applied to the vault.",
					},
					"vault_properties": schema.SingleNestedAttribute{
						Optional:    true,
						Description: "Azure vault properties.",
						Attributes: map[string]schema.Attribute{
							"tenant_id": schema.StringAttribute{
								Optional:    true,
								Description: "Azure Active Directory tenant ID for the vault.",
							},
							"vault_uri": schema.StringAttribute{
								Optional:    true,
								Description: "URI for performing operations on keys and secrets in this vault.",
							},
							"enabled_for_deployment": schema.BoolAttribute{
								Optional:    true,
								Description: "Whether Azure Virtual Machines may retrieve certificates stored as secrets.",
							},
							"enabled_for_disk_encryption": schema.BoolAttribute{
								Optional:    true,
								Description: "Whether Azure Disk Encryption may retrieve secrets from the vault.",
							},
							"enabled_for_template_deployment": schema.BoolAttribute{
								Optional:    true,
								Description: "Whether Azure Resource Manager may retrieve secrets from the vault.",
							},
							"enable_soft_delete": schema.BoolAttribute{
								Optional:    true,
								Description: "Whether soft delete is enabled for the vault.",
							},
							"create_mode": schema.StringAttribute{
								Optional:    true,
								Description: "Vault create mode.",
							},
							"enable_purge_protection": schema.BoolAttribute{
								Optional:    true,
								Description: "Whether protection against purge is enabled.",
							},
							"soft_delete_retention_in_days": schema.Int64Attribute{
								Optional:    true,
								Description: "Soft delete data retention period in days.",
							},
							"enable_rbac_authorization": schema.BoolAttribute{
								Optional:    true,
								Description: "Whether RBAC is used for data action authorization.",
							},
							"sku": schema.SingleNestedAttribute{
								Optional:    true,
								Description: "SKU details for the vault.",
								Attributes: map[string]schema.Attribute{
									"family": schema.StringAttribute{
										Optional:    true,
										Description: "SKU family name.",
									},
									"name": schema.StringAttribute{
										Optional:    true,
										Description: "SKU name.",
									},
								},
							},
						},
					},
				},
			},
			// Computed
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "CipherTrust Manager resource ID of the vault.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "The account which owns this resource.",
			},
			"acls": schema.SetNestedAttribute{
				Computed:    true,
				Description: "List of ACLs that have been added to the vault.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"actions": schema.SetAttribute{
							Computed:    true,
							Description: "Permitted actions.",
							ElementType: types.StringType,
						},
						"group": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager group.",
						},
						"user_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager user ID.",
						},
					},
				},
			},
			"azure_vault_id": schema.StringAttribute{
				Computed:    true,
				Description: "Azure resource ID of the vault.",
			},
			"cckm_vault_name": schema.StringAttribute{
				Computed: true,
				Description: "CipherTrust Manager resource name for this vault in " +
					"`azure_name::subscription_id` format. Use this value as the `name` " +
					"filter in the `ciphertrust_azure_vault_list` data source.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "Cloud name as returned by CipherTrust Manager.",
			},
			"connection_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the Azure connection as returned by CipherTrust Manager.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the vault was added to CipherTrust Manager.",
			},
			"labels": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "CipherTrust Manager labels attached to the vault.",
			},
			"location": schema.StringAttribute{
				Computed:    true,
				Description: "Azure region where the vault is located.",
			},
			"subscription_name": schema.StringAttribute{
				Computed:    true,
				Description: "Display name of the Azure subscription.",
			},
			"synced_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the vault was last synced.",
			},
			"tags": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Azure tags applied to the vault.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the vault was last updated in CipherTrust Manager.",
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager unique identifier URI for the resource.",
			},
			"vault_properties": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Azure vault properties retrieved from CCKM.",
				Attributes: map[string]schema.Attribute{
					"tenant_id": schema.StringAttribute{
						Computed:    true,
						Description: "Azure Active Directory tenant ID for the vault.",
					},
					"vault_uri": schema.StringAttribute{
						Computed:    true,
						Description: "URI for performing operations on keys and secrets in this vault.",
					},
					"enabled_for_deployment": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether Azure Virtual Machines may retrieve certificates stored as secrets.",
					},
					"enabled_for_disk_encryption": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether Azure Disk Encryption may retrieve secrets from the vault.",
					},
					"enabled_for_template_deployment": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether Azure Resource Manager may retrieve secrets from the vault.",
					},
					"enable_soft_delete": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether soft delete is enabled for the vault.",
					},
					"create_mode": schema.StringAttribute{
						Computed:    true,
						Description: "Vault create mode",
					},
					"enable_purge_protection": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether protection against purge is enabled.",
					},
					"soft_delete_retention_in_days": schema.Int64Attribute{
						Computed:    true,
						Description: "Soft delete data retention period in days.",
					},
					"enable_rbac_authorization": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether RBAC is used for data action authorization.",
					},
					"sku": schema.SingleNestedAttribute{
						Computed:    true,
						Description: "SKU details for the vault.",
						Attributes: map[string]schema.Attribute{
							"family": schema.StringAttribute{
								Computed:    true,
								Description: "SKU family name.",
							},
							"name": schema.StringAttribute{
								Computed:    true,
								Description: "SKU name.",
							},
						},
					},
				},
			},
			"vault_type": schema.StringAttribute{
				Computed:    true,
				Description: "Azure resource type of the vault.",
			},
		},
	}
}

// Create adds an Azure vault to CipherTrust Manager.
// When vault_details is provided, its contents are used directly; otherwise the vault
// is fetched from Azure via the get-vaults endpoint. The vault is then added via
// add-vaults, and the CM vault ID is resolved by listing vaults after creation.
func (r *resourceCCKMAzureVault) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_vault.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_vault.go -> Create][" + id + "]")

	var plan models.AzureVaultTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Validate that connection_id is a real Azure connection resource ID.
	connResp, connErr := r.client.GetById(ctx, id, plan.ConnectionID.ValueString(), common.URL_AZURE_CONNECTION)
	if connErr != nil {
		msg := "Error adding Azure vault, failed to read Azure connection by 'connection_id'."
		details := utils.ApiError(msg, map[string]interface{}{"error": connErr.Error(), "connection_id": plan.ConnectionID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	if gjson.Get(connResp, "id").String() != plan.ConnectionID.ValueString() {
		msg := "Error adding Azure vault: connection_id must be a resource ID of an Azure connection."
		details := utils.ApiError(msg, map[string]interface{}{"connection_id": plan.ConnectionID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	connAccount := gjson.Get(connResp, "account").String()
	mutexKey := fmt.Sprintf("azure-vault-%s", connAccount)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	// Determine vault data: use user-supplied vault_details if provided, otherwise look up from Azure.
	var vaultData *models.AzureVaultDataJSON
	if plan.VaultDetails.IsNull() {
		// vault_details not provided - fetch from Azure.
		vaultData = r.lookupVaultByName(ctx, id, plan.ConnectionID.ValueString(), plan.SubscriptionID.ValueString(), plan.Name.ValueString(), &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	} else {
		// vault_details provided - extract and validate.
		// UnhandledNullAsEmpty allows null nested objects (e.g. vault_properties omitted by
		// the user) to become zero-value Go structs rather than causing a framework panic.
		// Validation below will catch any missing required fields with a clear error.
		var vd models.AzureVaultDetailTFSDK
		resp.Diagnostics.Append(plan.VaultDetails.As(ctx, &vd, basetypes.ObjectAsOptions{UnhandledNullAsEmpty: true, UnhandledUnknownAsEmpty: true})...)
		if resp.Diagnostics.HasError() {
			return
		}
		if vd.Name.ValueString() != plan.Name.ValueString() {
			resp.Diagnostics.AddError(
				"vault_details.name does not match name",
				fmt.Sprintf("vault_details.name (%q) must match name (%q).",
					vd.Name.ValueString(), plan.Name.ValueString()),
			)
			return
		}
		vaultData = vaultDetailToVaultData(vd)
	}

	// Validate tenant_id is present (required by CCKM).
	if vaultData.Properties.TenantID == "" {
		resp.Diagnostics.AddError(
			"Error adding Azure vault: missing tenant_id",
			"The vault must have a tenant_id. Ensure vault_details.vault_properties.tenant_id is set.",
		)
		return
	}

	// Build add-vaults payload.
	payload := models.AzureAddVaultPayloadJSON{
		SubscriptionID: plan.SubscriptionID.ValueString(),
		Vaults:         []models.AzureVaultDataJSON{*vaultData},
		Connection:     plan.ConnectionID.ValueString(),
	}
	if !plan.CloudKeyBackupLimit.IsNull() && !plan.CloudKeyBackupLimit.IsUnknown() {
		v := int(plan.CloudKeyBackupLimit.ValueInt64())
		payload.CloudKeyBackupLimit = &v
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error adding Azure vault, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_name": plan.Name.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	_, err = r.client.PostDataV2(ctx, id, common.URL_AZURE+"/add-vaults", payloadJSON)
	if err != nil {
		msg := "Error adding Azure vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_name": plan.Name.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	// Resolve the CM vault ID by listing vaults and matching by name.
	vaultID := r.findVaultIDByName(ctx, id, plan.Name.ValueString(), plan.SubscriptionID.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = types.StringValue(vaultID)

	// Fetch the full vault record from CCKM to populate state.
	vaultJSON := getAzureVault(ctx, id, r.client, vaultID, "creating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	r.setVaultState(ctx, id, vaultJSON, plan.ConnectionID.ValueString(), gjson.Get(connResp, "name").String(), &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state for an Azure vault.
// A 404 is treated as an error so state is preserved until the resource is explicitly removed.
func (r *resourceCCKMAzureVault) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_vault.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_vault.go -> Read][" + id + "]")

	var state models.AzureVaultTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultJSON := getAzureVault(ctx, id, r.client, state.ID.ValueString(), "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_azure_vault.go -> Read][response:" + redactAzureResponse(vaultJSON) + "]")

	r.setVaultState(ctx, id, vaultJSON, "", "", &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update applies mutable changes (connection, cloud_key_backup_limit) to an existing Azure vault.
// Changes are applied only if they differ from the current CCKM vault state, using the resolved
// connection ID (from GetById) to accurately detect connection changes regardless of how Azure
// stores the connection reference in the vault resource.
func (r *resourceCCKMAzureVault) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_vault.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_vault.go -> Update][" + id + "]")

	var plan, state models.AzureVaultTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.ID.ValueString()

	// Verify the vault still exists before attempting any changes.
	currentJSON := getAzureVault(ctx, id, r.client, vaultID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_azure_vault.go -> Update][current:" + redactAzureResponse(currentJSON) + "]")

	// Validate the plan's connection and resolve its ID + name.
	// GetById is always called so we can reliably compare the resolved ID against state.ConnectionID.
	connResp, connErr := r.client.GetById(ctx, id, plan.ConnectionID.ValueString(), common.URL_AZURE_CONNECTION)
	if connErr != nil {
		msg := "Error updating Azure vault, failed to read Azure connection by 'connection_id'."
		details := utils.ApiError(msg, map[string]interface{}{"error": connErr.Error(), "connection_id": plan.ConnectionID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	planConnID := gjson.Get(connResp, "id").String()
	planConnName := gjson.Get(connResp, "name").String()
	if planConnID == "" {
		msg := "Error updating Azure vault: connection_id must be a resource ID of an Azure connection."
		details := utils.ApiError(msg, map[string]interface{}{"connection_id": plan.ConnectionID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	// Determine whether anything actually needs to change.
	// Compare the resolved connection ID against the stored state ID (which is always a UUID).
	connectionChanged := planConnID != state.ConnectionID.ValueString()
	planBackupLimit := plan.CloudKeyBackupLimit.ValueInt64()
	currentBackupLimit := gjson.Get(currentJSON, "cloud_key_backup_limit").Int()
	backupLimitChanged := !plan.CloudKeyBackupLimit.IsNull() && !plan.CloudKeyBackupLimit.IsUnknown() && planBackupLimit != currentBackupLimit

	if connectionChanged || backupLimitChanged {
		updatePayload := models.AzureUpdateVaultPayloadJSON{
			// Connection is always required by the API even when unchanged.
			Connection: plan.ConnectionID.ValueString(),
		}
		if !plan.CloudKeyBackupLimit.IsNull() && !plan.CloudKeyBackupLimit.IsUnknown() {
			v := int(planBackupLimit)
			updatePayload.CloudKeyBackupLimit = &v
		}

		payloadJSON, err := json.Marshal(updatePayload)
		if err != nil {
			msg := "Error updating Azure vault, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		_, err = r.client.UpdateDataV2(ctx, vaultID, common.URL_AZURE+"/vaults", payloadJSON)
		if err != nil {
			msg := "Error updating Azure vault."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
	}

	// Always re-read from CCKM so state reflects all current values including out-of-band changes.
	updatedJSON := getAzureVault(ctx, id, r.client, vaultID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_azure_vault.go -> Update][response:" + redactAzureResponse(updatedJSON) + "]")

	r.setVaultState(ctx, id, updatedJSON, planConnID, planConnName, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete removes an Azure vault from CipherTrust Manager.
// Uses POST /azure/vaults/:id/remove-vault. A 404 during the pre-flight GET
// emits a warning and allows Terraform to remove the resource from state.
func (r *resourceCCKMAzureVault) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_vault.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_vault.go -> Delete][" + id + "]")

	var state models.AzureVaultTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.ID.ValueString()

	// Pre-flight: verify vault exists. On 404 a warning is added (resource removed from state).
	vaultJSON := getAzureVault(ctx, id, r.client, vaultID, "deleting", &resp.Diagnostics)
	if vaultJSON == "" {
		// Either 404 (warning added, state removed by Terraform) or non-404 error (hard error, state kept).
		return
	}

	_, err := r.client.PostNoData(ctx, id, common.URL_AZURE+"/vaults/"+vaultID+"/remove-vault")
	if err != nil {
		msg := "Error removing Azure vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
	}
}

// ModifyPlan enforces create-time restrictions: name and subscription_id are immutable.
func (r *resourceCCKMAzureVault) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state models.AzureVaultTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// vault_details identifies which Azure vault was added. Block any change to the
	// block once set. Removing vault_details entirely (setting to null) is allowed because
	// it is an input-only attribute with no effect after creation.
	// name and subscription_id are covered by ImmutableString plan modifiers.
	if !plan.VaultDetails.IsNull() && !state.VaultDetails.IsNull() {
		if !plan.VaultDetails.Equal(state.VaultDetails) {
			resp.Diagnostics.AddError(
				"Immutable attribute change detected",
				"vault_details cannot be modified after creation. "+
					"Delete and recreate the resource to apply this change.",
			)
		}
	}
}

// ImportState imports an existing Azure vault into Terraform state using its CM resource ID.
func (r *resourceCCKMAzureVault) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_vault.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_vault.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// vaultPropertiesAttrTypes returns the attr.Type map for the vault_properties object.
// The sku nested object type is defined inline to keep the mapping self-contained.
func vaultPropertiesAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"tenant_id": types.StringType,
		"sku": types.ObjectType{AttrTypes: map[string]attr.Type{
			"family": types.StringType,
			"name":   types.StringType,
		}},
		"vault_uri":                       types.StringType,
		"enabled_for_deployment":          types.BoolType,
		"enabled_for_disk_encryption":     types.BoolType,
		"enabled_for_template_deployment": types.BoolType,
		"enable_soft_delete":              types.BoolType,
		"create_mode":                     types.StringType,
		"enable_purge_protection":         types.BoolType,
		"soft_delete_retention_in_days":   types.Int64Type,
		"enable_rbac_authorization":       types.BoolType,
	}
}

// setVaultState populates the Terraform state for an Azure vault exclusively from the
// CCKM GET response JSON. No plan or prior state values are used, ensuring all
// out-of-band changes are picked up.
//
// connID and connName should be the already-resolved connection ID and name when the
// caller has already fetched the connection (Create, Update). Pass empty strings from
// Read to fall back to resolveConnectionByIDOrName using the connection field in the
// API response.
func (r *resourceCCKMAzureVault) setVaultState(ctx context.Context, reqID string, response string, connID string, connName string, state *models.AzureVaultTFSDK, diags *diag.Diagnostics) {
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	acls.SetAclsStateFromJSON(ctx, gjson.Get(response, "acls"), &state.Acls, diags)
	if diags.HasError() {
		return
	}
	state.AzureVaultID = types.StringValue(gjson.Get(response, "azure_vault_id").String())
	state.CckmVaultName = types.StringValue(gjson.Get(response, "name").String())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.Location = types.StringValue(gjson.Get(response, "location").String())
	state.Name = types.StringValue(gjson.Get(response, "azure_name").String())
	state.SubscriptionID = types.StringValue(gjson.Get(response, "subscription_id").String())
	state.SubscriptionName = types.StringValue(gjson.Get(response, "subscription_name").String())
	state.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.VaultType = types.StringValue(gjson.Get(response, "type").String())

	// cloud_key_backup_limit: use null when zero (user did not configure a limit).
	backupLimit := gjson.Get(response, "cloud_key_backup_limit").Int()
	if backupLimit == 0 {
		state.CloudKeyBackupLimit = types.Int64Null()
	} else {
		state.CloudKeyBackupLimit = types.Int64Value(backupLimit)
	}

	// tags: null when absent or empty.
	tagsResult := gjson.Get(response, "tags")
	if tagsResult.Exists() && len(tagsResult.Map()) > 0 {
		tagMap := make(map[string]string, len(tagsResult.Map()))
		for k, v := range tagsResult.Map() {
			tagMap[k] = v.String()
		}
		tv, d := types.MapValueFrom(ctx, types.StringType, tagMap)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		state.Tags = tv
	} else {
		state.Tags = types.MapNull(types.StringType)
	}

	// labels: null when absent or empty.
	labelsResult := gjson.Get(response, "labels")
	if labelsResult.Exists() && len(labelsResult.Map()) > 0 {
		labelMap := make(map[string]string, len(labelsResult.Map()))
		for k, v := range labelsResult.Map() {
			labelMap[k] = v.String()
		}
		lv, d := types.MapValueFrom(ctx, types.StringType, labelMap)
		diags.Append(d...)
		if diags.HasError() {
			return
		}
		state.Labels = lv
	} else {
		state.Labels = types.MapNull(types.StringType)
	}

	// vault_properties: build the sku object first, then the outer properties object.
	skuAttrTypes := map[string]attr.Type{
		"family": types.StringType,
		"name":   types.StringType,
	}
	skuObj, d := types.ObjectValue(skuAttrTypes, map[string]attr.Value{
		"family": types.StringValue(gjson.Get(response, "properties.sku.family").String()),
		"name":   types.StringValue(gjson.Get(response, "properties.sku.name").String()),
	})
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	vpObj, d := types.ObjectValue(vaultPropertiesAttrTypes(), map[string]attr.Value{
		"tenant_id":                       types.StringValue(gjson.Get(response, "properties.tenantId").String()),
		"sku":                             skuObj,
		"vault_uri":                       types.StringValue(gjson.Get(response, "properties.vaultUri").String()),
		"enabled_for_deployment":          types.BoolValue(gjson.Get(response, "properties.enabledForDeployment").Bool()),
		"enabled_for_disk_encryption":     types.BoolValue(gjson.Get(response, "properties.enabledForDiskEncryption").Bool()),
		"enabled_for_template_deployment": types.BoolValue(gjson.Get(response, "properties.enabledForTemplateDeployment").Bool()),
		"enable_soft_delete":              types.BoolValue(gjson.Get(response, "properties.enableSoftDelete").Bool()),
		"create_mode":                     types.StringValue(gjson.Get(response, "properties.createMode").String()),
		"enable_purge_protection":         types.BoolValue(gjson.Get(response, "properties.enablePurgeProtection").Bool()),
		"soft_delete_retention_in_days":   types.Int64Value(gjson.Get(response, "properties.softDeleteRetentionInDays").Int()),
		"enable_rbac_authorization":       types.BoolValue(gjson.Get(response, "properties.enableRbacAuthorization").Bool()),
	})
	diags.Append(d...)
	if diags.HasError() {
		return
	}
	state.VaultProperties = vpObj

	// Set connection fields: use caller-supplied IDs when available (Create/Update),
	// otherwise resolve from the connection field in the API response (Read).
	if connID != "" {
		state.ConnectionID = types.StringValue(connID)
		state.ConnectionName = types.StringValue(connName)
	} else {
		r.resolveConnectionByIDOrName(ctx, reqID, gjson.Get(response, "connection").String(), state, diags)
	}
}

// resolveConnectionByIDOrName resolves an Azure connection from the value stored in the
// API "connection" field, which may be a UUID or a human-readable name. It first attempts
// a GetById lookup; on 404 it falls back to a name-based list query. Both connection_id
// and connection_name are written into state.
func (r *resourceCCKMAzureVault) resolveConnectionByIDOrName(ctx context.Context, reqID string, connValue string, state *models.AzureVaultTFSDK, diags *diag.Diagnostics) {
	if connValue == "" {
		return
	}
	// Try lookup by ID first.
	connResp, err := r.client.GetById(ctx, reqID, connValue, common.URL_AZURE_CONNECTION)
	if err != nil && !strings.Contains(err.Error(), notFoundError) {
		msg := "Error resolving Azure connection by ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": connValue})
		diags.AddError(details, "")
		return
	}
	if err == nil {
		state.ConnectionID = types.StringValue(gjson.Get(connResp, "id").String())
		state.ConnectionName = types.StringValue(gjson.Get(connResp, "name").String())
		return
	}
	// 404 - fall back to lookup by name.
	listResp, err := r.client.GetAll(ctx, reqID, common.URL_AZURE_CONNECTION+"?name="+url.QueryEscape(connValue))
	if err != nil {
		msg := "Error resolving Azure connection by name."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": connValue})
		diags.AddError(details, "")
		return
	}
	resources := gjson.Get(listResp, "resources").Array()
	if len(resources) == 0 {
		msg := "Azure connection not found by ID or name."
		details := utils.ApiError(msg, map[string]interface{}{"connection": connValue})
		diags.AddError(details, "")
		return
	}
	connID := resources[0].Get("id").String()
	if connID == "" {
		msg := "Azure connection found by name but ID is empty."
		details := utils.ApiError(msg, map[string]interface{}{"connection": connValue})
		diags.AddError(details, "")
		return
	}
	state.ConnectionID = types.StringValue(connID)
	state.ConnectionName = types.StringValue(resources[0].Get("name").String())
}

// lookupVaultByName fetches vault details from Azure via the CCKM get-vaults endpoint,
// paginating until a vault with the matching name is found. Returns the VaultData or
// adds an error diagnostic if not found.
func (r *resourceCCKMAzureVault) lookupVaultByName(ctx context.Context, reqID string, connectionID string, subscriptionID string, vaultName string, diags *diag.Diagnostics) *models.AzureVaultDataJSON {
	payload := models.AzureVaultInputJSON{
		Connection:     connectionID,
		SubscriptionID: subscriptionID,
		Limit:          1000,
	}
	for {
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error looking up Azure vault details, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_name": vaultName})
			r.client.Log.Error(details)
			diags.AddError(details, "")
			return nil
		}
		response, err := r.client.PostDataV2(ctx, reqID, common.URL_AZURE+"/get-vaults", payloadJSON)
		if err != nil {
			msg := "Error looking up Azure vault details."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_name": vaultName})
			r.client.Log.Error(details)
			diags.AddError(details, "")
			return nil
		}
		var output models.AzureVaultOutputJSON
		if err = json.Unmarshal([]byte(response), &output); err != nil {
			msg := "Error looking up Azure vault details, invalid data output."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_name": vaultName})
			r.client.Log.Error(details)
			diags.AddError(details, "")
			return nil
		}
		for i := range output.Vaults {
			if output.Vaults[i].Name == vaultName {
				v := output.Vaults[i]
				return &v
			}
		}
		if output.NextLink == nil || *output.NextLink == "" {
			break
		}
		nl := *output.NextLink
		payload.NextLink = &nl
	}
	msg := "Azure vault not found in subscription."
	details := utils.ApiError(msg, map[string]interface{}{"vault_name": vaultName, "subscription_id": subscriptionID})
	r.client.Log.Error(details)
	diags.AddError(details, "")
	return nil
}

// findVaultIDByName lists CCKM Azure vaults filtered by azure_name and returns the CM resource ID
// of the first vault whose azure_name matches vaultName. An error is added if no match is found.
// Note: the CCKM "name" field is "{azure_name}::{subscription_id}", so we must match by "azure_name".
func (r *resourceCCKMAzureVault) findVaultIDByName(ctx context.Context, reqID string, vaultName string, subscriptionID string, diags *diag.Diagnostics) string {
	// The CCKM "name" field for an Azure vault is "{azure_name}::{subscription_id}".
	expectedCCKMName := vaultName + "::" + subscriptionID
	listURL := common.URL_AZURE + "/vaults?name=" + url.QueryEscape(expectedCCKMName)
	response, err := r.client.GetAll(ctx, reqID, listURL)
	if err != nil {
		msg := "Error resolving Azure vault ID after creation."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_name": vaultName})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	for _, item := range gjson.Parse(response).Array() {
		if item.Get("azure_name").String() == vaultName {
			return item.Get("id").String()
		}
	}
	msg := "Azure vault was not found in CipherTrust Manager after creation."
	details := utils.ApiError(msg, map[string]interface{}{"vault_name": expectedCCKMName, "subscription_id": subscriptionID})
	r.client.Log.Error(details)
	diags.AddError(details, "")
	return ""
}

// getAzureVault fetches an Azure vault by its CipherTrust Manager ID.
// On 404:
//   - opLabel "deleting": warning added (Terraform removes from state), "" returned.
//   - any other opLabel: error added (state retained via NotFoundRetainedFmt), "" returned.
//
// Any non-404 error adds a hard error diagnostic and returns "".
func getAzureVault(ctx context.Context, id string, client *common.Client, vaultID string, opLabel string, diags *diag.Diagnostics) string {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_azure_vault.go -> getAzureVault][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_azure_vault.go -> getAzureVault][" + id + "]")

	response, err := client.GetById(ctx, id, vaultID, common.URL_AZURE+"/vaults")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			var msg string
			if opLabel == "deleting" {
				msg = "Azure vault was not found. It will be removed from state."
			} else {
				msg = fmt.Sprintf(utils.NotFoundRetainedFmt, "Azure vault")
			}
			details := utils.ApiError(msg, map[string]interface{}{"vault_id": vaultID})
			if opLabel == "deleting" {
				client.Log.Warn(details)
				diags.AddWarning(details, "")
			} else {
				client.Log.Error(details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + opLabel + " Azure vault, failed to read Azure vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// vaultDetailToVaultData converts user-supplied vault_details (TFSDK) to the AzureVaultDataJSON
// model expected by the add-vaults API.
func vaultDetailToVaultData(vd models.AzureVaultDetailTFSDK) *models.AzureVaultDataJSON {
	data := &models.AzureVaultDataJSON{
		Name:         vd.Name.ValueString(),
		AzureVaultID: vd.AzureVaultID.ValueString(),
		Type:         vd.VaultType.ValueString(),
		Location:     vd.Location.ValueString(),
		Properties: models.AzureVaultPropertiesJSON{
			TenantID:                     vd.VaultProperties.TenantID.ValueString(),
			VaultURI:                     vd.VaultProperties.VaultURI.ValueString(),
			EnabledForDeployment:         vd.VaultProperties.EnabledForDeployment.ValueBool(),
			EnabledForDiskEncryption:     vd.VaultProperties.EnabledForDiskEncryption.ValueBool(),
			EnabledForTemplateDeployment: vd.VaultProperties.EnabledForTemplateDeployment.ValueBool(),
			EnableSoftDelete:             vd.VaultProperties.EnableSoftDelete.ValueBool(),
			CreateMode:                   vd.VaultProperties.CreateMode.ValueString(),
			EnablePurgeProtection:        vd.VaultProperties.EnablePurgeProtection.ValueBool(),
			SoftDeleteRetentionInDays:    int32(vd.VaultProperties.SoftDeleteRetentionInDays.ValueInt64()),
			EnableRbacAuthorization:      vd.VaultProperties.EnableRbacAuthorization.ValueBool(),
			Sku: models.AzureSkuJSON{
				Family: vd.VaultProperties.Sku.Family.ValueString(),
				Name:   vd.VaultProperties.Sku.Name.ValueString(),
			},
		},
	}
	if !vd.Tags.IsNull() {
		tags := make(map[string]string, len(vd.Tags.Elements()))
		for k, v := range vd.Tags.Elements() {
			if sv, ok := v.(types.String); ok {
				tags[k] = sv.ValueString()
			}
		}
		data.Tags = tags
	}
	return data
}

// redactAzureResponse returns a safe-to-log version of an Azure vault API response.
func redactAzureResponse(response string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		return response
	}
	for _, field := range []string{"azure_vault_id", "subscription_id"} {
		if _, ok := data[field]; ok {
			data[field] = "redacted"
		}
	}
	if props, ok := data["properties"].(map[string]interface{}); ok {
		if _, ok := props["tenantId"]; ok {
			props["tenantId"] = "redacted"
		}
		if _, ok := props["vaultUri"]; ok {
			props["vaultUri"] = "redacted"
		}
	}
	b, err := json.Marshal(data)
	if err != nil {
		return response
	}
	return string(b)
}
