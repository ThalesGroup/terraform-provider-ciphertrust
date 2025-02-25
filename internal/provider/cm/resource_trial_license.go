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
	_ resource.Resource              = &resourceCMTrialLicense{}
	_ resource.ResourceWithConfigure = &resourceCMTrialLicense{}
)

func NewResourceCMTrialLicense() resource.Resource {
	return &resourceCMTrialLicense{}
}

type resourceCMTrialLicense struct {
	client *common.Client
}

func (r *resourceCMTrialLicense) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_trial_license"
}

// Schema defines the schema for the resource.
func (r *resourceCMTrialLicense) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Description: "ID of the trial license",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Current status of the trial license",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the trial license",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the license",
			},
			"activated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date of the last activation",
			},
			"deactivated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date of the last de-activation",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMTrialLicense) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_trial_license.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CMTrialLicenseTFSDK

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	jsonStr, err := r.client.GetAll(ctx, id, common.URL_TRIAL_LICENSE)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_trial_license.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read trial licenses from CM",
			err.Error(),
		)
		return
	}

	licenses := []CMTrialLicenseJSON{}
	err = json.Unmarshal([]byte(jsonStr), &licenses)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_trial_license.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read trial licenses from CM",
			err.Error(),
		)
		return
	}

	if len(licenses) == 1 {
		license := licenses[0]
		plan.ID = types.StringValue(license.ID)
		plan.Name = types.StringValue(license.Name)
		plan.Status = types.StringValue(license.Status)
		plan.Description = types.StringValue(license.Description)
		plan.ActivatedAt = types.StringValue(license.ActivatedAt)
		plan.DeactivatedAt = types.StringValue(license.DeactivatedAt)
	}

	if plan.Status.ValueString() == "available" || plan.Status.ValueString() == "deactivated" {
		//Trial License is available and can be activated
		URLActivateLicense := common.URL_TRIAL_LICENSE + "/" + plan.ID.ValueString() + "/activate"
		response, err := r.client.PostDataV2(ctx, id, URLActivateLicense, nil)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_trial_license.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Error activating trial license on CipherTrust Manager: ",
				"Could not activate trial license, unexpected error: "+err.Error(),
			)
			return
		}
		tflog.Debug(ctx, "[resource_trial_license.go -> Create Output]["+response+"]")
	} else if plan.Status.ValueString() == "activated" {
		tflog.Debug(ctx, "[resource_trial_license.go -> Create Output][Already Activated]")
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_trial_license.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCMTrialLicense) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMTrialLicenseTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_TRIAL_LICENSE)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_trial_license.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading trial license on CipherTrust Manager: ",
			"Could not read trial license id : "+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Status = types.StringValue(gjson.Get(response, "status").String())
	state.Description = types.StringValue(gjson.Get(response, "description").String())
	state.ActivatedAt = types.StringValue(gjson.Get(response, "activated_at").String())
	state.DeactivatedAt = types.StringValue(gjson.Get(response, "deactivated_at").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_trial_license.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMTrialLicense) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMTrialLicense) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMTrialLicenseTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing license
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_TRIAL_LICENSE, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_trial_license.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust NTP",
			"Could not delete NTP, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCMTrialLicense) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
