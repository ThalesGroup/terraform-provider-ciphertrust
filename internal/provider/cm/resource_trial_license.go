// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"strings"
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
	_ resource.Resource                   = &resourceCMTrialLicense{}
	_ resource.ResourceWithConfigure      = &resourceCMTrialLicense{}
	_ resource.ResourceWithValidateConfig = &resourceCMTrialLicense{}
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

func (r *resourceCMTrialLicense) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_trial_license", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMTrialLicense) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Activates a CipherTrust Manager trial license. **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
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
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the trial license",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the license",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"activated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date of the last activation",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"deactivated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date of the last de-activation",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"license_type": schema.StringAttribute{
				Optional:    true,
				Description: "The name, type, or substring identifier of the trial license to activate (e.g. 'CCKM', 'CTE', 'KMIP'). Required if multiple trial licenses exist on the CipherTrust Manager appliance.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
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

	var selectedLicense *CMTrialLicenseJSON

	if len(licenses) == 0 {
		resp.Diagnostics.AddError(
			"No Trial Licenses Found",
			"No trial licenses are available on this CipherTrust Manager appliance.",
		)
		return
	}

	licenseType := plan.LicenseType.ValueString()

	if len(licenses) == 1 {
		license := licenses[0]
		if licenseType != "" && licenseType != types.StringNull().ValueString() {
			// If user specified a type, make sure it matches (case-insensitive substring match on name or description)
			if !strings.Contains(strings.ToLower(license.Name), strings.ToLower(licenseType)) &&
				!strings.Contains(strings.ToLower(license.Description), strings.ToLower(licenseType)) {
				resp.Diagnostics.AddError(
					"Trial License Type Mismatch",
					fmt.Sprintf("The only available trial license is '%s' (%s), which does not match your configured license_type: '%s'.", license.Name, license.Description, licenseType),
				)
				return
			}
		}
		selectedLicense = &license
	} else {
		// len(licenses) > 1
		if licenseType == "" || licenseType == types.StringNull().ValueString() {
			resp.Diagnostics.AddError(
				"Multiple Trial Licenses Found",
				"Multiple trial licenses exist on this CipherTrust Manager appliance. You must explicitly configure the 'license_type' attribute to deterministically specify which license to activate.",
			)
			return
		}

		// Find the matching license
		for _, lic := range licenses {
			if strings.Contains(strings.ToLower(lic.Name), strings.ToLower(licenseType)) ||
				strings.Contains(strings.ToLower(lic.Description), strings.ToLower(licenseType)) {
				if selectedLicense != nil {
					resp.Diagnostics.AddError(
						"Ambiguous Trial License Selection",
						fmt.Sprintf("Multiple trial licenses match your configured license_type '%s' (matches: '%s' and '%s'). Please specify a more precise license_type.", licenseType, selectedLicense.Name, lic.Name),
					)
					return
				}
				copied := lic
				selectedLicense = &copied
			}
		}

		if selectedLicense == nil {
			resp.Diagnostics.AddError(
				"No Matching Trial License Found",
				fmt.Sprintf("No trial licenses match your configured license_type: '%s'. Available licenses on appliance: %s", licenseType, getLicenseNames(licenses)),
			)
			return
		}
	}

	plan.ID = types.StringValue(selectedLicense.ID)
	plan.Name = types.StringValue(selectedLicense.Name)
	plan.Status = types.StringValue(selectedLicense.Status)
	plan.Description = types.StringValue(selectedLicense.Description)
	plan.ActivatedAt = types.StringValue(selectedLicense.ActivatedAt)
	plan.DeactivatedAt = types.StringValue(selectedLicense.DeactivatedAt)

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

	// Re-fetch the license data to get the updated values after activation
	if err := r.readTrialLicenseFromAPI(ctx, plan.ID.ValueString(), &plan); err != nil {
		resp.Diagnostics.AddError(
			"Error reading trial license after activation on CipherTrust Manager: ",
			"Could not read trial license id : "+plan.ID.ValueString()+" unexpected error: "+err.Error(),
		)
		return
	}
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

	err := r.readTrialLicenseFromAPI(ctx, state.ID.ValueString(), &state)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddWarning(
				"Trial License Not Found",
				"The Trial License resource was not found on CipherTrust Manager (HTTP 404). It may have been deleted outside of Terraform. Removing it from state.",
			)
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_trial_license.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading trial license on CipherTrust Manager: ",
			"Could not read trial license id : "+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	// Desired State Model: if the license is not active (deactivated or available),
	// treat it as missing out-of-band so that Terraform plans a recreation/reactivation.
	if state.Status.ValueString() != "activated" {
		resp.Diagnostics.AddWarning(
			"Trial License Deactivated Out-Of-Band",
			fmt.Sprintf("The Trial License '%s' has status '%s' on CipherTrust Manager. Removing from state to trigger re-activation.", state.Name.ValueString(), state.Status.ValueString()),
		)
		resp.State.RemoveResource(ctx)
		return
	}

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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_trial_license.go -> Update]")
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"ciphertrust_trial_license does not support updates. The trial license state is managed by activation/deactivation via Create and Delete.",
	)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_trial_license.go -> Update]")
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMTrialLicense) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMTrialLicenseTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Deactivate the trial license
	URLDeactivateLicense := common.URL_TRIAL_LICENSE + "/" + state.ID.ValueString() + "/deactivate"
	response, err := r.client.PostDataV2(ctx, state.ID.ValueString(), URLDeactivateLicense, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_trial_license.go -> Delete]["+state.ID.ValueString()+"]["+response+"]")
	if err != nil {
		// Gracefully handle case where it is already deactivated/expired
		errStr := err.Error()
		if strings.Contains(errStr, "status: 400") || strings.Contains(errStr, "status: 404") || strings.Contains(strings.ToLower(errStr), "not activated") || strings.Contains(strings.ToLower(errStr), "already deactivated") {
			tflog.Warn(ctx, fmt.Sprintf("Ignored error during Trial License deactivation (resource may already be deactivated/expired): %v", err))
			return
		}
		resp.Diagnostics.AddError(
			"Error Deactivating CipherTrust Trial License",
			"Could not deactivate trial license, unexpected error: "+err.Error(),
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

// readTrialLicenseFromAPI fetches the trial license data from the API and populates the state struct.
// This helper function is used by both Create and Read to avoid code duplication.
func (r *resourceCMTrialLicense) readTrialLicenseFromAPI(ctx context.Context, licenseID string, state *CMTrialLicenseTFSDK) error {
	id := uuid.New().String()
	response, err := r.client.ReadDataByParam(ctx, id, licenseID, common.URL_TRIAL_LICENSE)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_trial_license.go -> readTrialLicenseFromAPI]["+id+"]")
		return err
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Status = types.StringValue(gjson.Get(response, "status").String())
	state.Description = types.StringValue(gjson.Get(response, "description").String())
	state.ActivatedAt = types.StringValue(gjson.Get(response, "activated_at").String())
	state.DeactivatedAt = types.StringValue(gjson.Get(response, "deactivated_at").String())

	return nil
}

func getLicenseNames(licenses []CMTrialLicenseJSON) string {
	names := []string{}
	for _, l := range licenses {
		names = append(names, fmt.Sprintf("'%s'", l.Name))
	}
	return strings.Join(names, ", ")
}
