package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

const notFoundError = "status: 404"

var (
	_ resource.Resource                = &resourceCMGroup{}
	_ resource.ResourceWithConfigure   = &resourceCMGroup{}
	_ resource.ResourceWithImportState = &resourceCMGroup{}
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
			"app_metadata": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"client_metadata": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"user_metadata": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"id": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

// setGroupState maps all API response fields into Terraform state for a CM group.
func setGroupState(_ context.Context, response string, state *CMGroupTFSDK, diags *diag.Diagnostics) {
	name := gjson.Get(response, "name").String()
	state.ID = types.StringValue(name)
	state.Name = types.StringValue(name)
	state.Description = types.StringValue(gjson.Get(response, "description").String())
	state.AppMetadata = gjsonToStringMap(gjson.Get(response, "app_metadata"), diags)
	state.ClientMetadata = gjsonToStringMap(gjson.Get(response, "client_metadata"), diags)
	state.UserMetadata = gjsonToStringMap(gjson.Get(response, "user_metadata"), diags)
}

// gjsonToStringMap converts a gjson map result to a types.Map of strings.
// Returns null map when the field is absent or null in the API response.
func gjsonToStringMap(result gjson.Result, diags *diag.Diagnostics) types.Map {
	if !result.Exists() || result.Type == gjson.Null {
		return types.MapNull(types.StringType)
	}
	m := make(map[string]attr.Value, len(result.Map()))
	result.ForEach(func(k, v gjson.Result) bool {
		m[k.String()] = types.StringValue(v.String())
		return true
	})
	mapVal, d := types.MapValue(types.StringType, m)
	diags.Append(d...)
	return mapVal
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Create]["+id+"]")

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

	appMetadataPayload := make(map[string]interface{})
	for k, v := range plan.AppMetadata.Elements() {
		appMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.AppMetadata = appMetadataPayload

	clientMetadataPayload := make(map[string]interface{})
	for k, v := range plan.ClientMetadata.Elements() {
		clientMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.ClientMetadata = clientMetadataPayload

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

	response, err := r.client.PostData(ctx, id, common.URL_GROUP, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating group on CipherTrust Manager: ",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = plan.Name

	tflog.Debug(ctx, "[resource_cm_group.go -> Create Output]["+response+"]")

	// Fetch full resource from API to populate computed fields.
	getResp, err := r.client.GetById(ctx, id, plan.Name.ValueString(), common.URL_GROUP)
	if err == nil {
		setGroupState(ctx, getResp, &plan, &resp.Diagnostics)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Create]["+id+"]")
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
	response, err := r.client.GetById(ctx, id, groupID, common.URL_GROUP)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			msg := "Group was not found, it will be removed from state."
			tflog.Warn(ctx, "[resource_cm_group.go -> Read]["+msg+"][id: "+groupID+"]")
			resp.Diagnostics.AddWarning(msg, "Group ID: "+groupID)
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Error(ctx, "[resource_cm_group.go -> Read][error reading group][id: "+groupID+"]["+err.Error()+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Group",
			"Could not read group ID "+groupID+": "+err.Error(),
		)
		return
	}

	setGroupState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
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

	appMetadataPayload := make(map[string]interface{})
	for k, v := range plan.AppMetadata.Elements() {
		appMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.AppMetadata = appMetadataPayload

	clientMetadataPayload := make(map[string]interface{})
	for k, v := range plan.ClientMetadata.Elements() {
		clientMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.ClientMetadata = clientMetadataPayload

	userMetadataPayload := make(map[string]interface{})
	for k, v := range plan.UserMetadata.Elements() {
		userMetadataPayload[k] = v.(types.String).ValueString()
	}
	payload.UserMetadata = userMetadataPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.Name.ValueString(), common.URL_GROUP, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating group on CipherTrust Manager: ",
			"Could not update group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.Name = types.StringValue(response)
	plan.ID = plan.Name

	// Fetch full resource from API to populate computed fields.
	getResp, err := r.client.GetById(ctx, id, plan.Name.ValueString(), common.URL_GROUP)
	if err == nil {
		setGroupState(ctx, getResp, &plan, &resp.Diagnostics)
	}

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
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_GROUP, state.Name.ValueString())
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

func (r *resourceCMGroup) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
