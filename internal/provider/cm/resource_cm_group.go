package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

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
			"client_metadata": schema.MapNestedAttribute{
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

	tflog.Debug(ctx, "[resource_cm_user.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_user.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
//
// Groups are looked up by name (the resource id). On a 404 the group is removed
// from state so a subsequent plan recreates it; on success the description is
// reconciled so out-of-band edits are surfaced. The metadata maps are preserved
// from prior state (their schema does not declare an element type that can be
// safely round-tripped from the API response).
func (r *resourceCMGroup) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Read]["+id+"]")

	var state CMGroupTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.Name.ValueString(), common.URL_GROUP)
	if err != nil {
		if strings.Contains(err.Error(), "404") {
			tflog.Warn(ctx, "[resource_cm_group.go -> Read][group not found, removing from state][group name: "+state.Name.ValueString()+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Group",
			"Could not read CipherTrust group "+state.Name.ValueString()+": "+err.Error(),
		)
		return
	}

	var group CMGroupJSON
	if err := json.Unmarshal([]byte(response), &group); err != nil {
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Group",
			"Could not parse CipherTrust group response: "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(group.Name)
	state.ID = state.Name
	// Only refresh description if the user configured it, to avoid a perpetual
	// diff when the API returns an empty value for an unset attribute.
	if !state.Description.IsNull() && state.Description.ValueString() != "" {
		state.Description = types.StringValue(group.Description)
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
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Group Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.Name.ValueString(), common.URL_GROUP, payloadJSON, "name")
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
