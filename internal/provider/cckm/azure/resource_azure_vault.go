package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

const notFoundError = "status: 404"

var (
	_ resource.Resource                = &resourceAzureVault{}
	_ resource.ResourceWithConfigure   = &resourceAzureVault{}
	_ resource.ResourceWithImportState = &resourceAzureVault{}
)

// NewResourceAzureVault returns a new ciphertrust_azure_vault resource.
func NewResourceAzureVault() resource.Resource {
	return &resourceAzureVault{}
}

type resourceAzureVault struct {
	client *common.Client
}

func (r *resourceAzureVault) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_vault"
}

func (r *resourceAzureVault) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAzureVault) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage Azure Key Vaults in CipherTrust Manager CCKM.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "CipherTrust Manager resource ID (UUID) for this vault.",
			},
			"uri": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "URI of the vault in CipherTrust Manager.",
			},
			"name": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Name of the vault in CipherTrust CCKM.",
			},
			"connection_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
				Description:   "(Immutable) ID of the Azure connection in CipherTrust Manager.",
			},
			"connection_name": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Name or UUID of the Azure connection as returned by CM.",
			},
			"managed_hsm": schema.BoolAttribute{
				Optional:      true,
				PlanModifiers: []planmodifier.Bool{modifiers.ImmutableBool()},
				Description:   "(Immutable) Set to true to register an Azure Managed HSM vault.",
			},
			"subscription_id": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
				Description:   "(Immutable) Azure subscription ID.",
			},
			"azure": schema.StringAttribute{
				Required:      true,
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
				Description:   "(Immutable) JSON array string of vault descriptors from the discovery step.",
			},
			"azure_vault_id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Azure resource ID of the vault.",
			},
			"azure_name": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Azure name of the vault.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Cloud name (e.g. AzureCloud).",
			},
			"location": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Azure region where the vault is located.",
			},
			"type": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Azure resource type.",
			},
			"subscription_name": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Azure subscription name.",
			},
			"account": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "CipherTrust account URI.",
			},
			"application": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "CipherTrust application URI.",
			},
			"dev_account": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "CipherTrust dev account URI.",
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Timestamp when the vault was registered in CM.",
			},
			// updated_at must NOT have UseStateForUnknown — it changes on every PATCH.
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the vault record was last updated in CM.",
			},
			"tags": schema.MapAttribute{
				Computed:      true,
				ElementType:   types.StringType,
				PlanModifiers: []planmodifier.Map{mapplanmodifier.UseStateForUnknown()},
				Description:   "Azure resource tags.",
			},
			"labels": schema.MapAttribute{
				Computed:      true,
				ElementType:   types.StringType,
				PlanModifiers: []planmodifier.Map{mapplanmodifier.UseStateForUnknown()},
				Description:   "CipherTrust labels.",
			},
			"tenant_id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Azure tenant ID from vault properties.",
			},
			"vault_uri": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Vault URI from Azure properties.",
			},
			"enabled_for_deployment": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				Description:   "Whether vault is enabled for deployment.",
			},
			"enabled_for_disk_encryption": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				Description:   "Whether vault is enabled for disk encryption.",
			},
			"enabled_for_template_deployment": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				Description:   "Whether vault is enabled for template deployment.",
			},
			"enable_soft_delete": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				Description:   "Whether soft delete is enabled.",
			},
			"create_mode": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
				Description:   "Vault create mode from Azure properties.",
			},
			"enable_purge_protection": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				Description:   "Whether purge protection is enabled.",
			},
			"soft_delete_retention_in_days": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
				Description:   "Soft delete retention period in days.",
			},
			"enable_rbac_authorization": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
				Description:   "Whether RBAC authorization is enabled.",
			},
			"sku": schema.SingleNestedAttribute{
				Computed: true,
				Attributes: map[string]schema.Attribute{
					"family": schema.StringAttribute{
						Computed:      true,
						PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
					"name": schema.StringAttribute{
						Computed:      true,
						PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
					},
				},
				Description: "SKU details of the vault.",
			},
			"cloud_key_backup_limit": schema.Int64Attribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
				Description:   "Cloud key backup limit.",
			},
			// acls is Optional+Computed so that removing the block (null plan) does not
			// produce perpetual drift against the empty Set that Read() writes to state.
			"acls": schema.SetNestedAttribute{
				Optional: true,
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"group": schema.StringAttribute{
							Required:    true,
							Description: "CipherTrust Manager group name.",
						},
						"allow_list": schema.ListAttribute{
							Required:    true,
							ElementType: types.StringType,
							Description: "List of operations to allow.",
						},
					},
				},
				Description: "Access control list entries for the vault.",
			},
			"enable_rotation": schema.BoolAttribute{
				Optional:    true,
				Description: "Set to true to enable key rotation; false to disable.",
			},
			"rotation_job_params": schema.StringAttribute{
				Optional:    true,
				Description: "JSON string of rotation job parameters. Required when enable_rotation is true.",
			},
		},
	}
}

func (r *resourceAzureVault) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_vault.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_vault.go -> Create]["+id+"]")

	var plan AzureVaultTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 1: get-subscriptions — pre-flight to validate connection; response discarded.
	getSubsPayload, _ := json.Marshal(map[string]interface{}{
		"connection": plan.ConnectionID.ValueString(),
	})
	if _, err := r.client.PostDataV2(ctx, id, URL_AZURE_GET_SUBSCRIPTIONS, getSubsPayload); err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
			"Could not validate Azure subscription, connection_id="+plan.ConnectionID.ValueString()+": "+err.Error())
		return
	}

	// Step 2: get-vaults or get-managed-hsms — pre-flight; response discarded.
	discoverURL := URL_AZURE_GET_VAULTS
	if !plan.ManagedHsm.IsNull() && plan.ManagedHsm.ValueBool() {
		discoverURL = URL_AZURE_GET_MANAGED_HSMS
	}
	discoverPayload, _ := json.Marshal(map[string]interface{}{
		"subscription_id": plan.SubscriptionID.ValueString(),
		"connection":      plan.ConnectionID.ValueString(),
	})
	if _, err := r.client.PostDataV2(ctx, id, discoverURL, discoverPayload); err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
			"Could not discover Azure vaults: "+err.Error())
		return
	}

	// Step 3: add-vaults — parse the `azure` JSON array field.
	var azureList json.RawMessage
	if err := json.Unmarshal([]byte(plan.Azure.ValueString()), &azureList); err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
			"The 'azure' field must be a valid JSON array: "+err.Error())
		return
	}
	addPayload, _ := json.Marshal(map[string]interface{}{
		"subscription_id": plan.SubscriptionID.ValueString(),
		"connection":      plan.ConnectionID.ValueString(),
		"azure":           azureList,
	})
	addResp, err := r.client.PostDataV2(ctx, id, URL_AZURE_ADD_VAULTS, addPayload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
			"Could not add Azure vault: "+err.Error())
		return
	}

	// Extract vault ID from add-vaults response. Path follows the OCI pattern.
	vaultID := gjson.Get(addResp, "resources.0.id").String()
	if vaultID == "" {
		tflog.Debug(ctx, common.ERR_METHOD_END+"no vault ID in add-vaults response[resource_azure_vault.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
			"No vault ID returned from add-vaults response. Raw response: "+addResp)
		return
	}

	// Step 4: GET by ID to hydrate all Computed fields.
	getResp, err := r.client.GetById(ctx, id, vaultID, URL_AZURE_VAULTS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
			"Could not read vault after create, vault_id="+vaultID+": "+err.Error())
		return
	}
	hydrateAzureVaultState(ctx, getResp, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 5: Optional ACL update.
	if !plan.Acls.IsNull() && !plan.Acls.IsUnknown() {
		var aclList []AzureVaultAclTFSDK
		resp.Diagnostics.Append(plan.Acls.ElementsAs(ctx, &aclList, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
		wireAcls := buildAzureVaultAclsJSON(aclList)
		aclPayload, _ := json.Marshal(map[string]interface{}{"acls": wireAcls})
		if _, err = r.client.PostDataV2(ctx, id, URL_AZURE_VAULTS+"/"+vaultID+"/update-acls", aclPayload); err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
			resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
				"Could not set ACLs on vault, vault_id="+vaultID+": "+err.Error())
			return
		}
		// Re-read to pick up ACL state.
		getResp2, err2 := r.client.GetById(ctx, id, vaultID, URL_AZURE_VAULTS)
		if err2 != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err2.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
			resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
				"Could not read vault after ACL update, vault_id="+vaultID+": "+err2.Error())
			return
		}
		hydrateAzureVaultState(ctx, getResp2, &plan, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Step 6: Optional rotation enable.
	if !plan.EnableRotation.IsNull() && plan.EnableRotation.ValueBool() {
		rotParams := []byte("{}")
		if !plan.RotationJobParams.IsNull() {
			rotParams = []byte(plan.RotationJobParams.ValueString())
		}
		if _, err = r.client.PostDataV2(ctx, id, URL_AZURE_VAULTS+"/"+vaultID+"/enable-rotation-job", rotParams); err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Create]["+id+"]")
			resp.Diagnostics.AddError("Error Creating CipherTrust Azure Vault",
				"Could not enable rotation on vault, vault_id="+vaultID+": "+err.Error())
			return
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceAzureVault) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_vault.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_vault.go -> Read]["+id+"]")

	var state AzureVaultTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	getResp, err := r.client.GetById(ctx, id, state.ID.ValueString(), URL_AZURE_VAULTS)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Debug(ctx, "[resource_azure_vault.go -> Read] vault not found, removing from state ["+id+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Read]["+id+"]")
		resp.Diagnostics.AddError("Error Reading CipherTrust Azure Vault",
			"Could not read vault, id="+state.ID.ValueString()+": "+err.Error())
		return
	}

	// hydrateAzureVaultState sets all Computed (Saved=Yes) fields.
	// Write-only fields are not touched — they retain their prior values.
	hydrateAzureVaultState(ctx, getResp, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceAzureVault) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_vault.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_vault.go -> Update]["+id+"]")

	var plan, state AzureVaultTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.ID.ValueString()
	payload := map[string]interface{}{}

	if !plan.Name.IsNull() && !plan.Name.Equal(state.Name) {
		payload["name"] = plan.Name.ValueString()
	}

	if len(payload) > 0 {
		patchBytes, _ := json.Marshal(payload)
		if _, err := r.client.UpdateData(ctx, vaultID, URL_AZURE_VAULTS, patchBytes, "id"); err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Update]["+id+"]")
			resp.Diagnostics.AddError("Error Updating CipherTrust Azure Vault",
				"Could not update vault, id="+vaultID+": "+err.Error())
			return
		}
	}

	// ACL diff — plan.Acls may be null (user removed block) or populated.
	if !plan.Acls.Equal(state.Acls) {
		var aclList []AzureVaultAclTFSDK
		if !plan.Acls.IsNull() && !plan.Acls.IsUnknown() {
			resp.Diagnostics.Append(plan.Acls.ElementsAs(ctx, &aclList, false)...)
		}
		// aclList is empty slice when plan.Acls is null — sends {"acls":[]} to clear.
		if !resp.Diagnostics.HasError() {
			wireAcls := buildAzureVaultAclsJSON(aclList)
			aclPayload, _ := json.Marshal(map[string]interface{}{"acls": wireAcls})
			if _, err := r.client.PostDataV2(ctx, id, URL_AZURE_VAULTS+"/"+vaultID+"/update-acls", aclPayload); err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Update]["+id+"]")
				resp.Diagnostics.AddError("Error Updating CipherTrust Azure Vault",
					"Could not update ACLs on vault, id="+vaultID+": "+err.Error())
				return
			}
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Rotation toggle.
	planRotation  := !plan.EnableRotation.IsNull() && plan.EnableRotation.ValueBool()
	stateRotation := !state.EnableRotation.IsNull() && state.EnableRotation.ValueBool()
	if planRotation && !stateRotation {
		rotParams := []byte("{}")
		if !plan.RotationJobParams.IsNull() {
			rotParams = []byte(plan.RotationJobParams.ValueString())
		}
		if _, err := r.client.PostDataV2(ctx, id, URL_AZURE_VAULTS+"/"+vaultID+"/enable-rotation-job", rotParams); err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Update]["+id+"]")
			resp.Diagnostics.AddError("Error Updating CipherTrust Azure Vault",
				"Could not enable rotation on vault, id="+vaultID+": "+err.Error())
			return
		}
	} else if !planRotation && stateRotation {
		if _, err := r.client.PostDataV2(ctx, id, URL_AZURE_VAULTS+"/"+vaultID+"/disable-rotation-job", []byte("{}")); err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Update]["+id+"]")
			resp.Diagnostics.AddError("Error Updating CipherTrust Azure Vault",
				"Could not disable rotation on vault, id="+vaultID+": "+err.Error())
			return
		}
	}

	// Read back updated state.
	getResp, err := r.client.GetById(ctx, id, vaultID, URL_AZURE_VAULTS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Update]["+id+"]")
		resp.Diagnostics.AddError("Error Updating CipherTrust Azure Vault",
			"Could not read vault after update, id="+vaultID+": "+err.Error())
		return
	}
	hydrateAzureVaultState(ctx, getResp, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Explicitly preserve all write-only (Saved=No) fields from prior state into plan.
	if plan.ConnectionID.IsNull() {
		plan.ConnectionID = state.ConnectionID
	}
	if plan.ManagedHsm.IsNull() {
		plan.ManagedHsm = state.ManagedHsm
	}
	if plan.Azure.IsNull() {
		plan.Azure = state.Azure
	}
	if plan.SubscriptionID.IsNull() {
		plan.SubscriptionID = state.SubscriptionID
	}
	if plan.EnableRotation.IsNull() {
		plan.EnableRotation = state.EnableRotation
	}
	if plan.RotationJobParams.IsNull() {
		plan.RotationJobParams = state.RotationJobParams
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceAzureVault) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_vault.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_vault.go -> Delete]["+id+"]")

	var state AzureVaultTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.ID.ValueString()
	_, err := r.client.PostDataV2(ctx, id, URL_AZURE_VAULTS+"/"+vaultID+"/remove-vault", []byte("{}"))
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			// Vault already gone — treat as successful deletion.
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+"[resource_azure_vault.go -> Delete]["+id+"]")
		resp.Diagnostics.AddError("Error Deleting CipherTrust Azure Vault",
			"Could not delete vault, id="+vaultID+": "+err.Error())
		return
	}
}

func (r *resourceAzureVault) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// buildAzureVaultAclsJSON converts Terraform ACL structs to the wire format for the update-acls API.
func buildAzureVaultAclsJSON(aclList []AzureVaultAclTFSDK) []azureVaultAclJSON {
	var wireAcls []azureVaultAclJSON
	for _, acl := range aclList {
		var allowList []string
		for _, v := range acl.AllowList.Elements() {
			if sv, ok := v.(types.String); ok {
				allowList = append(allowList, sv.ValueString())
			}
		}
		wireAcls = append(wireAcls, azureVaultAclJSON{
			Group:     acl.Group.ValueString(),
			AllowList: allowList,
		})
	}
	if wireAcls == nil {
		wireAcls = []azureVaultAclJSON{}
	}
	return wireAcls
}
