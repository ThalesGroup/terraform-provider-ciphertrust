package cm

import (
	"context"
	"encoding/json"
	"fmt"

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
	_ resource.Resource              = &resourceCMProperty{}
	_ resource.ResourceWithConfigure = &resourceCMProperty{}
)

func NewResourceCMProperty() resource.Resource {
	return &resourceCMProperty{}
}

type resourceCMProperty struct {
	client *common.Client
}

func (r *resourceCMProperty) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_property"
}

// Schema defines the schema for the resource.
func (r *resourceCMProperty) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Optional: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Name of property",
			},
			"value": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Value to be set",
			},
			"description": schema.StringAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Description of the property and its value",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMProperty) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_property.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMPropertyTFSDK
	var payload CMPropertyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Value = plan.Value.ValueString()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_property.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Property Updation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataFullURL(
		ctx,
		plan.Name.ValueString(),
		common.URL_CM_PROPERTIES+"/"+plan.Name.ValueString(),
		payloadJSON,
		"name")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_property.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating property on CipherTrust Manager: ",
			"Could not update property "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	plan.Description = types.StringValue(gjson.Get(response, "description").String())

	tflog.Debug(ctx, "[resource_property.go -> Create Output -> Response]["+response+"]")
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_property.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMProperty) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMPropertyTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.Name.ValueString(), common.URL_CM_PROPERTIES)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_property.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM Property on CipherTrust Manager: ",
			"Could not read CM Property : ,"+state.Name.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.Value = types.StringValue(gjson.Get(response, "value").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Description = types.StringValue(gjson.Get(response, "description").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_property.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMProperty) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan CMPropertyTFSDK
	var payload CMPropertyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Value = plan.Value.ValueString()

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_property.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Property Updation",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataFullURL(
		ctx,
		plan.Name.ValueString(),
		common.URL_CM_PROPERTIES+"/"+plan.Name.ValueString(),
		payloadJSON,
		"name")
	tflog.Debug(ctx, "[resource_property.go -> Update -> Response]["+response+"]")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_property.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating property on CipherTrust Manager: ",
			"Could not update property "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMProperty) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMPropertyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var payload []byte

	response, err := r.client.PostDataV2(
		ctx,
		state.Name.ValueString(),
		common.URL_CM_PROPERTIES+"/"+state.Name.ValueString()+"/reset",
		payload)
	tflog.Debug(ctx, "[resource_property.go -> delete -> Response]["+response+"]")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_property.go -> delete]["+state.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error resetting property on CipherTrust Manager: ",
			"Could not reset property "+state.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMProperty) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
