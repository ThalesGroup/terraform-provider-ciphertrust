package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

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

type cmGroupTFSDK struct {
	ID             types.String `tfsdk:"id"`
	Name           types.String `tfsdk:"name"`
	Description    types.String `tfsdk:"description"`
	Connection     types.String `tfsdk:"connection"`
	UserMetadata   types.Map    `tfsdk:"user_metadata"`
	ClientMetadata types.Map    `tfsdk:"client_metadata"`
}

type cmGroupJSON struct {
	Name           string                 `json:"name,omitempty"`
	Description    string                 `json:"description,omitempty"`
	Connection     string                 `json:"connection,omitempty"`
	UserMetadata   map[string]interface{} `json:"user_metadata,omitempty"`
	ClientMetadata map[string]interface{} `json:"client_metadata,omitempty"`
}

func NewResourceCMGroup() resource.Resource {
	return &resourceCMGroup{}
}

type resourceCMGroup struct {
	client *common.Client
}

func (r *resourceCMGroup) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_group"
}

func (r *resourceCMGroup) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"connection": schema.StringAttribute{
				Optional: true,
				Computed: true,
			},
			"user_metadata": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			"client_metadata": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (r *resourceCMGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Create]["+id+"]")

	var plan cmGroupTFSDK
	var payload cmGroupJSON

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if v := plan.Name.ValueString(); v != "" {
		payload.Name = v
	}
	if v := plan.Description.ValueString(); v != "" {
		payload.Description = v
	}
	if v := plan.Connection.ValueString(); v != "" {
		payload.Connection = v
	}
	if !plan.UserMetadata.IsNull() && !plan.UserMetadata.IsUnknown() {
		m := make(map[string]interface{})
		for k, v := range plan.UserMetadata.Elements() {
			m[k] = v.(types.String).ValueString()
		}
		payload.UserMetadata = m
	}
	if !plan.ClientMetadata.IsNull() && !plan.ClientMetadata.IsUnknown() {
		m := make(map[string]interface{})
		for k, v := range plan.ClientMetadata.Elements() {
			m[k] = v.(types.String).ValueString()
		}
		payload.ClientMetadata = m
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError("Invalid data input: Group Creation", err.Error())
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_CM_GROUPS, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating group on CipherTrust Manager",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = plan.Name
	tflog.Debug(ctx, "[resource_cm_group.go -> Create Output]["+response+"]")
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Create]["+id+"]")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCMGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Read]["+id+"]")

	var state cmGroupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupName := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, groupName, common.URL_CM_GROUPS)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, "[resource_cm_group.go -> Read] group not found, removing from state: "+groupName)
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError(
			"Error reading CipherTrust Group",
			"Could not read group, unexpected error: "+err.Error(),
		)
		return
	}

	setCMGroupState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Read]["+id+"]")
}

func (r *resourceCMGroup) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func setCMGroupState(_ context.Context, response string, state *cmGroupTFSDK, diags *diag.Diagnostics) {
	var group cmGroupJSON
	if err := json.Unmarshal([]byte(response), &group); err != nil {
		diags.AddError("Error parsing CipherTrust Group response", err.Error())
		return
	}
	state.Name = types.StringValue(group.Name)
	state.Description = types.StringValue(group.Description)
	state.Connection = types.StringValue(group.Connection)
	state.UserMetadata = cmGroupToStringMap(group.UserMetadata, diags)
	state.ClientMetadata = cmGroupToStringMap(group.ClientMetadata, diags)
}

func cmGroupToStringMap(m map[string]interface{}, diags *diag.Diagnostics) types.Map {
	if m == nil {
		return types.MapNull(types.StringType)
	}
	elems := make(map[string]attr.Value, len(m))
	for k, v := range m {
		elems[k] = types.StringValue(fmt.Sprintf("%v", v))
	}
	mapVal, d := types.MapValue(types.StringType, elems)
	diags.Append(d...)
	return mapVal
}

func (r *resourceCMGroup) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Update]["+id+"]")

	var plan cmGroupTFSDK
	var payload cmGroupJSON

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if v := plan.Name.ValueString(); v != "" {
		payload.Name = v
	}
	if v := plan.Description.ValueString(); v != "" {
		payload.Description = v
	}
	if v := plan.Connection.ValueString(); v != "" {
		payload.Connection = v
	}
	if !plan.UserMetadata.IsNull() && !plan.UserMetadata.IsUnknown() {
		m := make(map[string]interface{})
		for k, v := range plan.UserMetadata.Elements() {
			m[k] = v.(types.String).ValueString()
		}
		payload.UserMetadata = m
	}
	if !plan.ClientMetadata.IsNull() && !plan.ClientMetadata.IsUnknown() {
		m := make(map[string]interface{})
		for k, v := range plan.ClientMetadata.Elements() {
			m[k] = v.(types.String).ValueString()
		}
		payload.ClientMetadata = m
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+id+"]")
		resp.Diagnostics.AddError("Invalid data input: Group Update", err.Error())
		return
	}

	response, err := r.client.UpdateData(ctx, plan.Name.ValueString(), common.URL_CM_GROUPS, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating group on CipherTrust Manager",
			"Could not update group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.Name = types.StringValue(response)
	plan.ID = plan.Name
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceCMGroup) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state cmGroupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteURL := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_CM_GROUPS, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), deleteURL, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Group",
			"Could not delete group, unexpected error: "+err.Error(),
		)
		return
	}
}

func (r *resourceCMGroup) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
