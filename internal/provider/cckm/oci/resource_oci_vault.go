package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
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
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIVault{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIVault{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIVault{}
)

func NewResourceCCKMOCIVault() resource.Resource {
	return &resourceCCKMOCIVault{}
}

type resourceCCKMOCIVault struct {
	client *common.Client
}

func (r *resourceCCKMOCIVault) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_vault"
}

func (r *resourceCCKMOCIVault) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMOCIVault) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage OCI vault resources in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "The unique identifier of the resource.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"uri": schema.StringAttribute{
				Description: "A human-readable unique identifier of the resource.",
				Computed:    true,
			},
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
			},
			"created_at": schema.StringAttribute{
				Description: "Date/time the application was created",
				Computed:    true,
			},
			"refreshed_at": schema.StringAttribute{
				Description: "Date/time the application was refreshed.",
				Computed:    true,
			},
			"updated_at": schema.StringAttribute{
				Description: "Date/time the application was updated.",
				Computed:    true,
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "Cloud name.",
			},
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI connection ID or connection name. When importing an existing vault use connection name.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "OCI region.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"tenancy": schema.StringAttribute{
				Computed:    true,
				Description: "Tenancy name.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Vault name.",
			},
			"acls": schema.SetNestedAttribute{
				Computed:    true,
				Description: "List of ACLs that have been added to the vault.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"user_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager user ID.",
						},
						"group": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager group.",
						},
						"actions": schema.SetAttribute{
							Computed:    true,
							Description: "Permitted actions.",
							ElementType: types.StringType,
						},
					},
				},
			},
			"compartment_id": schema.StringAttribute{
				Computed:    true,
				Description: "Compartment OCID.",
			},
			"compartment_name": schema.StringAttribute{
				Computed:    true,
				Description: "Compartment name.",
			},
			"lifecycle_state": schema.StringAttribute{
				Computed:    true,
				Description: "Current state of the vault.",
			},
			"vault_type": schema.StringAttribute{
				Computed:    true,
				Description: "OCI Vault type.",
			},
			"time_created": schema.StringAttribute{
				Computed:    true,
				Description: "OCI Vault type.",
			},
			"freeform_tags": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Freeform tags for the key. A freeform tag is a simple key-value pair with no predefined name, type, or namespace.",
			},
			"defined_tags": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Defined tags for the key. A tag consists of namespace, key, and value.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"tag": schema.StringAttribute{
							Computed: true,
						},
						"values": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
						},
					},
				},
			},
			"restored_from_vault_id": schema.StringAttribute{
				Computed:    true,
				Description: "OCID of the vault this vault was restored from.",
			},
			"replication_id": schema.StringAttribute{
				Computed:    true,
				Description: "OCI replication ID.",
			},
			"is_primary": schema.BoolAttribute{
				Computed:    true,
				Description: "True if a primary vault.",
			},
			"vault_id": schema.StringAttribute{
				Required:    true,
				Description: "Vault OCID.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"bucket_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name of the OCI bucket for creating key backups of HSM-protected keys for Virtual Private Vaults (VPVs). The bucket should be in the same region as the vault. You must have appropriate read/write permissions on this bucket. Note: If bucket_name is not specified, the keys cannot be backed up while syncing vaults.",
			},
			"bucket_namespace": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Namespace of the OCI bucket, bucket_name. This parameter is required if bucket_name is specified. Note: If bucket_namespace is not specified, the keys cannot be backed up while syncing vaults.",
			},
		},
	}
}

func (r *resourceCCKMOCIVault) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_vault.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_vault.go -> Create]["+id+"]")

	var plan VaultTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := AddVaultsPayloadJSON{
		Connection: plan.Connection.ValueString(),
		Region:     plan.Region.ValueString(),
		VaultIDs:   []string{plan.VaultID.ValueString()},
	}
	if plan.BucketName.ValueString() != "" {
		payload.BucketName = plan.BucketName.ValueStringPointer()
	}
	if plan.BucketNamespace.ValueString() != "" {
		payload.BucketNamespace = plan.BucketNamespace.ValueStringPointer()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error adding OCI vault, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault": payload.VaultIDs[0]})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_OCI+"/add-vaults", payloadJSON)
	if err != nil {
		msg := "Error adding OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault": payload.VaultIDs[0]})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	if gjson.Get(response, "vaults").Exists() {
		vaultsJSON := gjson.Get(response, "vaults").Array()
		for _, vaultJSON := range vaultsJSON {
			plan.ID = types.StringValue(gjson.Get(vaultJSON.Raw, "id").String())
		}
	}
	response, err = r.client.GetById(ctx, id, plan.ID.ValueString(), common.URL_OCI+"/vaults")
	if err != nil {
		msg := "Error reading OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": plan.ID.ValueString()})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}

	var diags diag.Diagnostics
	r.setVaultState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Trace(ctx, "[resource_oci_vault.go -> Create][response:"+response)
}

func (r *resourceCCKMOCIVault) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_vault.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_vault.go -> Read]["+id+"]")
	var state VaultTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaultID := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		msg := "Error reading OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.setVaultState(ctx, response, &state, &resp.Diagnostics)
	if state.Connection.ValueString() == "" {
		// Don't overwrite what might be connection ID with connection name
		state.Connection = types.StringValue(gjson.Get(response, "connection").String())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *resourceCCKMOCIVault) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_vault.go -> Import]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_vault.go -> Import]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *resourceCCKMOCIVault) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_vault.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_vault.go -> Update]["+id+"]")

	var plan VaultTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state VaultTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
	if err != nil {
		msg := "Error reading OCI vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}
	if plan.Connection.ValueString() != gjson.Get(response, "connection").String() ||
		plan.BucketName.ValueString() != gjson.Get(response, "bucket_name").String() ||
		plan.BucketNamespace.ValueString() != gjson.Get(response, "bucket_namespace").String() {

		var payload UpdateVaultJSON
		if plan.Connection.ValueString() != gjson.Get(response, "connection").String() {
			payload.Connection = plan.Connection.ValueStringPointer()
		}
		if plan.BucketName.ValueString() != gjson.Get(response, "bucket_name").String() {
			payload.BucketName = plan.BucketName.ValueStringPointer()
		}
		if plan.BucketNamespace.ValueString() != gjson.Get(response, "bucket_namespace").String() {
			payload.BucketNamespace = plan.BucketNamespace.ValueStringPointer()
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error updating OCI Vault, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		_, err = r.client.UpdateDataV2(ctx, vaultID, common.URL_OCI+"/vaults", payloadJSON)
		if err != nil {
			msg := "Error updating OCI Vault."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		response, err = r.client.GetById(ctx, id, vaultID, common.URL_OCI+"/vaults")
		if err != nil {
			msg := "Error reading OCI Vault."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
	}
	r.setVaultState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating OCI Vault, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"vault id": vaultID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	state.Connection = plan.Connection
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *resourceCCKMOCIVault) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_oci_vault.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_oci_vault.go -> Delete]["+id+"]")

	var state VaultTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vaultID := state.ID.ValueString()
	_, err := r.client.DeleteByURL(ctx, id, common.URL_OCI+"/vaults/"+vaultID)
	if err != nil {
		msg := "Error deleting OCI Vault."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "vault_id": vaultID})
		tflog.Error(ctx, details)
		if strings.Contains(err.Error(), "NCERRResourceNotFound") {
			resp.Diagnostics.AddWarning(details, "")
		} else {
			resp.Diagnostics.AddError(details, "")
		}
	}
}

func (r *resourceCCKMOCIVault) setVaultState(ctx context.Context, response string, state *VaultTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, "[resource_oci_vault.go -> setVaultState][response:"+response)
	setCommonVaultState(ctx, response, &state.VaultCommonTFSDK, diags)
	state.BucketName = types.StringValue(gjson.Get(response, "bucket_name").String())
	state.BucketNamespace = types.StringValue(gjson.Get(response, "bucket_namespace").String())
	state.VaultID = types.StringValue(gjson.Get(response, "vault_id").String())
	setFreeformTagsStateFromJSON(ctx, gjson.Get(response, "freeform_tags"), &state.FreeformTags, diags)
	if diags.HasError() {
		return
	}
	setDefinedTagsStateFromJSON(ctx, gjson.Get(response, "defined_tags"), &state.DefinedTags, diags)
	if diags.HasError() {
		return
	}
}

func setCommonVaultState(ctx context.Context, response string, state *VaultCommonTFSDK, diags *diag.Diagnostics) {
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.CompartmentID = types.StringValue(gjson.Get(response, "compartment_id").String())
	state.DisplayName = types.StringValue(gjson.Get(response, "display_name").String())
	state.LifecycleState = types.StringValue(gjson.Get(response, "lifecycle_state").String())
	state.TimeCreated = types.StringValue(gjson.Get(response, "time_created").String())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.VaultType = types.StringValue(gjson.Get(response, "vault_type").String())
	state.RestoredFromVaultID = types.StringValue(gjson.Get(response, "restored_from_vault_id").String())
	state.ReplicationID = types.StringValue(gjson.Get(response, "replication_id").String())
	state.IsPrimary = types.BoolValue(gjson.Get(response, "is_primary").Bool())
	acls.SetAclsStateFromJSON(ctx, gjson.Get(response, "acls"), &state.Acls, diags)
	state.RefreshedAt = types.StringValue(gjson.Get(response, "refreshed_at").String())
	state.Tenancy = types.StringValue(gjson.Get(response, "tenancy").String())
	state.Region = types.StringValue(gjson.Get(response, "region").String())
	state.CompartmentName = types.StringValue(gjson.Get(response, "compartment_name").String())
}

func setFreeformTagsStateFromJSON(ctx context.Context, tagsJSON gjson.Result, state *types.Map, diags *diag.Diagnostics) {
	tags := make(map[string]string)
	if len(tagsJSON.String()) > 0 {
		err := json.Unmarshal([]byte(tagsJSON.Raw), &tags)
		if err != nil {
			msg := "Error parsing 'freeform_tags', invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "tags": tagsJSON.String()})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
	}
	setFreeformTagsStateFromMap(ctx, tags, state, diags)
}

func setFreeformTagsStateFromMap(ctx context.Context, tags map[string]string, state *types.Map, diags *diag.Diagnostics) {
	tfMapValue, dg := types.MapValueFrom(ctx, types.StringType, tags)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*state = tfMapValue
}

func setDefinedTagsStateFromJSON(ctx context.Context, tagsJSON gjson.Result, state *types.List, diags *diag.Diagnostics) {
	tags := make(map[string]map[string]string)
	if len(tagsJSON.String()) > 0 {
		err := json.Unmarshal([]byte(tagsJSON.Raw), &tags)
		if err != nil {
			msg := "Error parsing 'defined_tags', invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "tags": tagsJSON.String()})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
	}
	setDefinedTagsStateFromMap(ctx, tags, state, diags)
}

func setDefinedTagsStateFromMap(ctx context.Context, tags map[string]map[string]string, state *types.List, diags *diag.Diagnostics) {
	var definedTagsTFSDK []DefinedTagsTFSDK
	for namespace, valueMap := range tags {
		tfMapValue, dg := types.MapValueFrom(ctx, types.StringType, valueMap)
		if dg.HasError() {
			diags.Append(dg...)
			return
		}
		definedTagTFSDK := DefinedTagsTFSDK{
			Tag:    types.StringValue(namespace),
			Values: tfMapValue,
		}
		definedTagsTFSDK = append(definedTagsTFSDK, definedTagTFSDK)
	}
	tfListValue, dg := types.ListValueFrom(ctx,
		types.ObjectType{AttrTypes: map[string]attr.Type{
			"tag":    types.StringType,
			"values": types.MapType{ElemType: types.StringType},
		}}, definedTagsTFSDK)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*state, dg = tfListValue.ToListValue(ctx)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
}
