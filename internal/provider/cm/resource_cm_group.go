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

func (r *resourceCMGroup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"connection": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"all_domain_users": schema.BoolAttribute{
				Optional: true,
				Computed: true,
			},
			"app_metadata": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"client_metadata": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"user_metadata": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"users": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
			},
			"created_at": schema.StringAttribute{
				Computed: true,
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
			},
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *resourceCMGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Create]["+id+"]")

	var plan CMGroupTFSDK
	var payload CMGroupJSON

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Name.ValueString() != "" {
		payload.Name = plan.Name.ValueString()
	}
	if plan.Description.ValueString() != "" {
		payload.Description = plan.Description.ValueString()
	}
	if plan.Connection.ValueString() != "" {
		payload.Connection = plan.Connection.ValueString()
	}
	if !plan.AllDomainUsers.IsNull() && !plan.AllDomainUsers.IsUnknown() {
		v := plan.AllDomainUsers.ValueBool()
		payload.AllDomainUsers = &v
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

	usersPayload := make([]string, 0, len(plan.Users.Elements()))
	for _, u := range plan.Users.Elements() {
		usersPayload = append(usersPayload, u.(types.String).ValueString())
	}
	if len(usersPayload) > 0 {
		payload.Users = usersPayload
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_GROUP, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating group on CipherTrust Manager",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	setCMGroupState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Create]["+id+"]")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Read refreshes the Terraform state for a CM group by fetching it from CipherTrust Manager.
// If the group is no longer found (HTTP 404), it is removed from state so Terraform can plan recreation.
func (r *resourceCMGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Read]["+id+"]")

	var state CMGroupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, groupID, common.URL_GROUP)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, "[resource_cm_group.go -> Read][group not found, removing from state][group id: "+groupID+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading group on CipherTrust Manager",
			"Could not read group "+groupID+", unexpected error: "+err.Error(),
		)
		return
	}

	setCMGroupState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Read]["+id+"]")
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *resourceCMGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Update]["+id+"]")

	var plan CMGroupTFSDK
	var state CMGroupTFSDK
	var payload CMGroupJSON

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := state.ID.ValueString()

	if plan.Name.ValueString() != "" {
		payload.Name = plan.Name.ValueString()
	}
	if plan.Description.ValueString() != "" {
		payload.Description = plan.Description.ValueString()
	}
	if plan.Connection.ValueString() != "" {
		payload.Connection = plan.Connection.ValueString()
	}
	if !plan.AllDomainUsers.IsNull() && !plan.AllDomainUsers.IsUnknown() {
		v := plan.AllDomainUsers.ValueBool()
		payload.AllDomainUsers = &v
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

	usersPayload := make([]string, 0, len(plan.Users.Elements()))
	for _, u := range plan.Users.Elements() {
		usersPayload = append(usersPayload, u.(types.String).ValueString())
	}
	payload.Users = usersPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Update",
			err.Error(),
		)
		return
	}

	_, err = r.client.UpdateDataV2(ctx, groupID, common.URL_GROUP, payloadJSON)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, "[resource_cm_group.go -> Update][group not found, removing from state][group id: "+groupID+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+groupID+"]")
		resp.Diagnostics.AddError(
			"Error updating group on CipherTrust Manager",
			"Could not update group "+groupID+", unexpected error: "+err.Error(),
		)
		return
	}

	response, err := r.client.GetById(ctx, id, groupID, common.URL_GROUP)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error reading group after update on CipherTrust Manager",
			"Could not read group "+groupID+" after update, unexpected error: "+err.Error(),
		)
		return
	}

	setCMGroupState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Update]["+id+"]")
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *resourceCMGroup) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Delete]["+id+"]")

	var state CMGroupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupID := state.ID.ValueString()
	_, err := r.client.DeleteByURL(ctx, groupID, common.URL_GROUP+"/"+groupID)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, "[resource_cm_group.go -> Delete][group not found][group id: "+groupID+"]")
			resp.Diagnostics.AddWarning(
				"Group not found during delete",
				"Group "+groupID+" was not found on CipherTrust Manager; it may have been deleted out-of-band.",
			)
			return
		}
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Group",
			"Could not delete group "+groupID+", unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Delete]["+id+"]")
}

func (r *resourceCMGroup) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
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

// setCMGroupState maps the CM API JSON response into the Terraform state struct for a CM group.
func setCMGroupState(_ context.Context, response string, state *CMGroupTFSDK, diags *diag.Diagnostics) {
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Description = types.StringValue(gjson.Get(response, "description").String())
	state.Connection = types.StringValue(gjson.Get(response, "connection").String())
	state.AllDomainUsers = types.BoolValue(gjson.Get(response, "allDomainUsers").Bool())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	rawAppMetadata := gjson.Get(response, "appMetadata").Map()
	appMetadataAttrMap := make(map[string]attr.Value, len(rawAppMetadata))
	for k, v := range rawAppMetadata {
		appMetadataAttrMap[k] = types.StringValue(v.String())
	}
	var d diag.Diagnostics
	state.AppMetadata, d = types.MapValue(types.StringType, appMetadataAttrMap)
	diags.Append(d...)

	rawClientMetadata := gjson.Get(response, "clientMetadata").Map()
	clientMetadataAttrMap := make(map[string]attr.Value, len(rawClientMetadata))
	for k, v := range rawClientMetadata {
		clientMetadataAttrMap[k] = types.StringValue(v.String())
	}
	state.ClientMetadata, d = types.MapValue(types.StringType, clientMetadataAttrMap)
	diags.Append(d...)

	rawUserMetadata := gjson.Get(response, "userMetadata").Map()
	userMetadataAttrMap := make(map[string]attr.Value, len(rawUserMetadata))
	for k, v := range rawUserMetadata {
		userMetadataAttrMap[k] = types.StringValue(v.String())
	}
	state.UserMetadata, d = types.MapValue(types.StringType, userMetadataAttrMap)
	diags.Append(d...)

	rawUsers := gjson.Get(response, "users").Array()
	usersAttrSlice := make([]attr.Value, len(rawUsers))
	for i, u := range rawUsers {
		usersAttrSlice[i] = types.StringValue(u.String())
	}
	state.Users, d = types.ListValue(types.StringType, usersAttrSlice)
	diags.Append(d...)
}
