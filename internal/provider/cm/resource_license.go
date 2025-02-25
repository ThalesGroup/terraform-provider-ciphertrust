package cm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCMLicense{}
	_ resource.ResourceWithConfigure = &resourceCMLicense{}
)

func NewResourceCMLicense() resource.Resource {
	return &resourceCMLicense{}
}

type resourceCMLicense struct {
	client *common.Client
}

func (r *resourceCMLicense) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_license"
}

// Schema defines the schema for the resource.
func (r *resourceCMLicense) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"license": schema.StringAttribute{
				Required:    true,
				Description: "License String",
			},
			"bind_type": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"instance",
						"cluster"}...),
				},
				Description: "Binding type for this license. Can be either 'instance' or 'cluster'. If omitted, then CM attempts to bind the license to the cluster. If this step fails with a lock code error, it will attempt to bind to the instance.",
			},
			"hash": schema.StringAttribute{
				Computed: true,
			},
			"type": schema.StringAttribute{
				Computed: true,
			},
			"state": schema.StringAttribute{
				Computed: true,
			},
			"start": schema.StringAttribute{
				Computed: true,
			},
			"expiration": schema.StringAttribute{
				Computed: true,
			},
			"version": schema.StringAttribute{
				Computed: true,
			},
			"license_count": schema.Int64Attribute{
				Computed: true,
			},
			"trial_seconds_remaining": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMLicense) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_license.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMLicenseTFSDK
	var payload CMLicenseJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.License = plan.License.ValueString()
	if plan.BindType.ValueString() != "" && plan.BindType.ValueString() != types.StringNull().ValueString() {
		payload.BindType = plan.BindType.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_license.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Add License",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_DOMAIN, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_license.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error adding license on CipherTrust Manager: ",
			"Could not add license, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	tflog.Debug(ctx, "[resource_license.go -> Create Output]["+response+"]")

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_license.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMLicense) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMLicenseTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_DOMAIN)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_license.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CM Licenses on CipherTrust Manager: ",
			"Could not read CM License id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.License = types.StringValue(gjson.Get(response, "name").String())
	state.BindType = types.StringValue(gjson.Get(response, "hsm_connection_id").String())
	state.Hash = types.StringValue(gjson.Get(response, "hash").String())
	state.Type = types.StringValue(gjson.Get(response, "type").String())
	state.State = types.StringValue(gjson.Get(response, "state").String())
	state.Start = types.StringValue(gjson.Get(response, "start").String())
	state.Expiration = types.StringValue(gjson.Get(response, "expiration").String())
	state.Version = types.StringValue(gjson.Get(response, "version").String())
	state.LicenseCount = types.Int64Value(gjson.Get(response, "license_count").Int())
	state.TrialSecondsRemaining = types.StringValue(gjson.Get(response, "trial_seconds_remaining").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_license.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMLicense) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMLicense) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMLicenseTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing license
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_DOMAIN, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_license.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust License",
			"Could not delete license, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMLicense) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
