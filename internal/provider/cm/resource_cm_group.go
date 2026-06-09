package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const notFoundError = "not found"

var (
	_ resource.Resource              = &resourceCMGroup{}
	_ resource.ResourceWithConfigure = &resourceCMGroup{}
)

func NewResourceCMGroup() resource.Resource {
	return &resourceCMGroup{}
}

type resourceCMGroup struct {
	client *common.Client
}

func (r *resourceCMGroup) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_groups"
}

// Schema defines the schema for the resource.
func (r *resourceCMGroup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"app_metadata": schema.MapNestedAttribute{
				Optional: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"user_metadata": schema.MapNestedAttribute{
				Optional: true,
			},
			"id": schema.StringAttribute{
				Computed: true,
			},
			"connection": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"client_id": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"created_at": schema.StringAttribute{
				Computed: true,
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
			},
			"all_clients": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_user.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMGroupTFSDK
	var payload CMGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}
	if plan.Connection.ValueString() != "" && plan.Connection.ValueString() != types.StringNull().ValueString() {
		payload.Connection = plan.Connection.ValueString()
	}
	if plan.ClientId.ValueString() != "" && plan.ClientId.ValueString() != types.StringNull().ValueString() {
		payload.ClientId = plan.ClientId.ValueString()
	}
	if !plan.AllClients.IsNull() && !plan.AllClients.IsUnknown() {
		payload.AllClients = plan.AllClients.ValueBool()
	}

	appMetadataPayload := make(map[string]interface{})
	for k, v := range plan.AppMetadata.Elements() {
		appMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.AppMetadata = appMetadataPayload

	userMetadataPayload := make(map[string]interface{})
	for k, v := range plan.UserMetadata.Elements() {
		userMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.UserMetadata = userMetadataPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_CM_GROUPS, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating group on CipherTrust Manager: ",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = plan.Name

	tflog.Debug(ctx, "[resource_cm_user.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Read]["+id+"]")

	var state CMGroupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, groupID, common.URL_CM_GROUPS)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, utils.ApiError("CM group not found, removing from state.", map[string]interface{}{"id": groupID}))
			resp.State.RemoveResource(ctx)
			return
		}
		msg := "Error reading CM group."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": groupID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	r.setCMGroupState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		tflog.Error(ctx, utils.ApiError("Error reading CM group, failed to set resource state.", map[string]interface{}{"id": groupID}))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// setCMGroupState populates the Terraform state for a CM group from an API response JSON string.
func (r *resourceCMGroup) setCMGroupState(ctx context.Context, response string, state *CMGroupTFSDK, diags *diag.Diagnostics) {
	var groupJSON CMGroupJSON
	if err := json.Unmarshal([]byte(response), &groupJSON); err != nil {
		msg := "Error parsing CM group API response."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}

	state.ID = types.StringValue(groupJSON.ID)
	state.Name = types.StringValue(groupJSON.Name)
	state.Description = types.StringValue(groupJSON.Description)
	state.Connection = types.StringValue(groupJSON.Connection)
	state.ClientId = types.StringValue(groupJSON.ClientId)
	state.CreatedAt = types.StringValue(groupJSON.CreatedAt)
	state.UpdatedAt = types.StringValue(groupJSON.UpdatedAt)
	state.AllClients = types.BoolValue(groupJSON.AllClients)

	appMetadata := make(map[string]string, len(groupJSON.AppMetadata))
	for k, v := range groupJSON.AppMetadata {
		appMetadata[k] = fmt.Sprintf("%v", v)
	}
	appMetadataVal, d := types.MapValueFrom(ctx, types.StringType, appMetadata)
	diags.Append(d...)
	if !d.HasError() {
		state.AppMetadata = appMetadataVal
	}

	userMetadata := make(map[string]string, len(groupJSON.UserMetadata))
	for k, v := range groupJSON.UserMetadata {
		userMetadata[k] = fmt.Sprintf("%v", v)
	}
	userMetadataVal, d := types.MapValueFrom(ctx, types.StringType, userMetadata)
	diags.Append(d...)
	if !d.HasError() {
		state.UserMetadata = userMetadataVal
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan CMGroupTFSDK
	var payload CMGroupJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}
	if plan.Connection.ValueString() != "" && plan.Connection.ValueString() != types.StringNull().ValueString() {
		payload.Connection = plan.Connection.ValueString()
	}
	if plan.ClientId.ValueString() != "" && plan.ClientId.ValueString() != types.StringNull().ValueString() {
		payload.ClientId = plan.ClientId.ValueString()
	}
	if !plan.AllClients.IsNull() && !plan.AllClients.IsUnknown() {
		payload.AllClients = plan.AllClients.ValueBool()
	}

	appMetadataPayload := make(map[string]interface{})
	for k, v := range plan.AppMetadata.Elements() {
		appMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.AppMetadata = appMetadataPayload

	userMetadataPayload := make(map[string]interface{})
	for k, v := range plan.UserMetadata.Elements() {
		userMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.UserMetadata = userMetadataPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.Name.ValueString(), common.URL_CM_GROUPS, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_user.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating group on CipherTrust Manager: ",
			"Could not update group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.Name = types.StringValue(response)
	plan.ID = plan.Name
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMGroup) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMGroupTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_GROUPS, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Group",
			"Could not delete group, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMGroup) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	d.client = client
}
