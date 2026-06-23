package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

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
				Description: "Unique group name. Immutable after creation.",
				PlanModifiers: []planmodifier.String{
					NameImmutableModifier{},
				},
			},
			"app_metadata": schema.StringAttribute{
				Optional: true,
			},
			"client_metadata": schema.StringAttribute{
				Optional: true,
			},
			"description": schema.StringAttribute{
				Optional: true,
			},
			"user_metadata": schema.StringAttribute{
				Optional: true,
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

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMGroup) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cm_group.go -> Create]["+id+"]")

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

	if !plan.AppMetadata.IsNull() && !plan.AppMetadata.IsUnknown() && plan.AppMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.AppMetadata.ValueString()), &meta) == nil {
			payload.AppMetadata = meta
		}
	}

	if !plan.ClientMetadata.IsNull() && !plan.ClientMetadata.IsUnknown() && plan.ClientMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.ClientMetadata.ValueString()), &meta) == nil {
			payload.ClientMetadata = meta
		}
	}

	if !plan.UserMetadata.IsNull() && !plan.UserMetadata.IsUnknown() && plan.UserMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.UserMetadata.ValueString()), &meta) == nil {
			payload.UserMetadata = meta
		}
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

	response, err := r.client.PostData(ctx, id, common.URL_GROUP, payloadJSON, "name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error Creating CipherTrust Group",
			"Could not create group, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = plan.Name

	tflog.Debug(ctx, "[resource_cm_group.go -> Create Output]["+response+"]")

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

	resourceID := state.ID.ValueString()

	response, err := r.client.GetById(ctx, id, resourceID, common.URL_GROUP)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			tflog.Warn(ctx, "CipherTrust Group not found, removing from state [resource_cm_group.go -> Read]["+resourceID+"]")
			resp.Diagnostics.AddWarning(
				"CipherTrust Group Not Found",
				"Group "+resourceID+" was not found on CipherTrust Manager and will be removed from state. "+err.Error(),
			)
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cm_group.go -> Read]["+resourceID+"]")
		resp.Diagnostics.AddError(
			"Error Reading CipherTrust Group",
			"Could not read group "+resourceID+": "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.ID = state.Name

	if v := gjson.Get(response, "description"); v.Exists() && v.String() != "" {
		state.Description = types.StringValue(v.String())
	} else {
		state.Description = types.StringNull()
	}

	if v := gjson.Get(response, "app_metadata"); v.Exists() && v.Type != gjson.Null && v.Raw != "{}" {
		// Normalize to compact JSON so whitespace differences between CM and
		// CDSPaaS responses don't surface as phantom drift in subsequent plans.
		compacted := compactJSONString(v.Raw)
		state.AppMetadata = types.StringValue(compacted)
	} else {
		state.AppMetadata = types.StringNull()
	}

	if v := gjson.Get(response, "client_metadata"); v.Exists() && v.Type != gjson.Null && v.Raw != "{}" {
		state.ClientMetadata = types.StringValue(v.Raw)
	} else {
		state.ClientMetadata = types.StringNull()
	}

	if v := gjson.Get(response, "user_metadata"); v.Exists() && v.Type != gjson.Null && v.Raw != "{}" {
		state.UserMetadata = types.StringValue(v.Raw)
	} else {
		state.UserMetadata = types.StringNull()
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
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

	if !plan.AppMetadata.IsNull() && !plan.AppMetadata.IsUnknown() && plan.AppMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.AppMetadata.ValueString()), &meta) == nil {
			payload.AppMetadata = meta
		}
	}

	if !plan.ClientMetadata.IsNull() && !plan.ClientMetadata.IsUnknown() && plan.ClientMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.ClientMetadata.ValueString()), &meta) == nil {
			payload.ClientMetadata = meta
		}
	}

	if !plan.UserMetadata.IsNull() && !plan.UserMetadata.IsUnknown() && plan.UserMetadata.ValueString() != "" {
		var meta map[string]interface{}
		if json.Unmarshal([]byte(plan.UserMetadata.ValueString()), &meta) == nil {
			payload.UserMetadata = meta
		}
	}

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
			"Error Updating CipherTrust Group",
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

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_GROUP, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cm_group.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return
		}
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

// compactJSONString returns s compacted (no extra whitespace). If compaction
// fails it returns s unchanged — keeps JSON round-trips safe when the server
// returns pretty-printed JSON and the config stores compact JSON.
func compactJSONString(s string) string {
	var v interface{}
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, err := json.Marshal(v)
	if err != nil {
		return s
	}
	return string(b)
}
