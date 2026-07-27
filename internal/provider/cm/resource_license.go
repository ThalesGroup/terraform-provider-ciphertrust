package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceCMLicense{}
	_ resource.ResourceWithConfigure      = &resourceCMLicense{}
	_ resource.ResourceWithValidateConfig = &resourceCMLicense{}
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

func (r *resourceCMLicense) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_license", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMLicense) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CipherTrust Manager license. **Only available on CipherTrust Manager — not supported on CDSPaaS.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"license": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "(Immutable) License String",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"bind_type": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf([]string{
						"instance",
						"cluster"}...),
				},
				Description: "(Immutable) Binding type for this license. Can be either 'instance' or 'cluster'. If omitted, then CM attempts to bind the license to the cluster. If this step fails with a lock code error, it will attempt to bind to the instance.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"hash": schema.StringAttribute{
				Computed:    true,
				Description: "Hash of the license.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"type": schema.StringAttribute{
				Computed:    true,
				Description: "License type, e.g. \"Normal\" or \"Trial\".",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			// state: NO UseStateForUnknown — license state changes over lifecycle
			// (e.g. "Pending" → "Active" → "Expired").
			"state": schema.StringAttribute{
				Computed:    true,
				Description: "The current state of the license (e.g. \"active\" or \"inactive\" per the CM API). This value can change over the license's lifecycle as it is activated, renewed, or expires.",
			},
			"start": schema.StringAttribute{
				Computed:    true,
				Description: "Start date/time of the license.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"expiration": schema.StringAttribute{
				Computed:    true,
				Description: "End date/time of the license, or \"no expiration\" if it never expires. For trial licenses, use trial_seconds_remaining instead.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"version": schema.StringAttribute{
				Computed:    true,
				Description: "Version of the license feature.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"license_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of licenses granted.",
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.UseStateForUnknown(),
				},
			},
			// trial_seconds_remaining: NO UseStateForUnknown — continuously decrementing countdown.
			"trial_seconds_remaining": schema.StringAttribute{
				Computed:    true,
				Description: "For trial licenses only, the number of seconds remaining until the trial period ends.",
			},
		},
	}
}

// findLicenseIDByString retrieves all licenses and finds the ID of the license with the matching license string
func (r *resourceCMLicense) findLicenseIDByString(ctx context.Context, id, licenseStr string) (string, error) {
	response, err := r.client.GetAll(ctx, id, common.URL_LICENSE)
	if err != nil {
		return "", err
	}

	licenses := gjson.Parse(response).Array()
	for _, license := range licenses {
		if license.Get("license").String() == licenseStr {
			return license.Get("id").String(), nil
		}
	}
	return "", nil
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMLicense) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_license.go -> Create][" + id + "]")

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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_license.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Add License",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_LICENSE, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_license.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error adding license on CipherTrust Manager: ",
			"Could not add license, unexpected error: "+err.Error(),
		)
		return
	}

	// Check if the response contains an ID
	responseID := gjson.Get(response, "id").String()
	if responseID != "" {
		plan.ID = types.StringValue(responseID)
	} else {
		// ID not in response, determine it by finding matching license string
		r.client.Log.Debug("[resource_license.go -> Create] ID not in response, determining by finding matching license string")

		newLicenseID, err := r.findLicenseIDByString(ctx, id, plan.License.ValueString())
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_license.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error listing licenses after create: ",
				"Could not list licenses, unexpected error: "+err.Error(),
			)
			return
		}

		if newLicenseID == "" {
			resp.Diagnostics.AddError(
				"Error determining license ID: ",
				"Could not find the newly created license with the matching license string",
			)
			return
		}

		r.client.Log.Debug("[resource_license.go -> Create] Determined new license ID: " + newLicenseID)
		plan.ID = types.StringValue(newLicenseID)

		// Fetch the license details to populate computed attributes
		response, err = r.client.ReadDataByParam(ctx, id, newLicenseID, common.URL_LICENSE)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_license.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error reading license details after create: ",
				"Could not read license details, unexpected error: "+err.Error(),
			)
			return
		}
		r.client.Log.Debug("[resource_license.go -> Create] Fetched license details for ID: " + newLicenseID)
	}

	// Computed-only — unconditional hydration.
	plan.Hash = types.StringValue(gjson.Get(response, "hash").String())
	plan.Type = types.StringValue(gjson.Get(response, "type").String())
	plan.State = types.StringValue(gjson.Get(response, "state").String())
	plan.Start = types.StringValue(gjson.Get(response, "start").String())
	plan.Expiration = types.StringValue(gjson.Get(response, "expiration").String())
	plan.Version = types.StringValue(gjson.Get(response, "version").String())
	plan.LicenseCount = types.Int64Value(gjson.Get(response, "license_count").Int())
	plan.TrialSecondsRemaining = types.StringValue(gjson.Get(response, "trial_seconds_remaining").String())

	if gjson.Get(response, "bind_type").Exists() && gjson.Get(response, "bind_type").String() != "" {
		plan.BindType = types.StringValue(gjson.Get(response, "bind_type").String())
	} else if plan.BindType.IsUnknown() {
		plan.BindType = types.StringNull()
	}
	// If plan.BindType already has a value from the user's config, keep it

	r.client.Log.Debug("[resource_license.go -> Create Output][" + response + "]")

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_license.go -> Create][" + id + "]")
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
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_license.go -> Read][" + id + "]")
	// defer ensures MSG_METHOD_END fires on ALL return paths: 404 early return,
	// error early return, and normal return.
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_license.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Capture write-only field before any mutation.
	// CM GET /v1/licensing/licenses/{id} does not return the license string —
	// confirmed absent from the Swagger Licenses definition (present only in
	// PostLicense for the POST request body).
	//
	// Restoring the prior state value prevents ImmutableString() from seeing a
	// spurious "" → <license> transition on every plan/refresh cycle after the
	// initial create (TFIN-430 fix).
	//
	// During terraform destroy, Terraform computes the plan value for a Required
	// attribute as the current state value (no config change is being applied).
	// With state.License preserved as the real license string,
	// req.StateValue == req.PlanValue in ImmutableString.PlanModifyString(), so
	// no immutability error fires and destroy proceeds normally.
	priorLicense := state.License

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), common.URL_LICENSE)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				"License Not Found",
				"The License resource was not found on CipherTrust Manager (HTTP 404). It may have been deleted outside of Terraform. Removing it from state.",
			)
			resp.State.RemoveResource(ctx)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_license.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading CM Licenses on CipherTrust Manager: ",
			"Could not read CM License id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())

	// license is write-only: absent from the Swagger Licenses GET response schema.
	// Restore the prior state value so ImmutableString() sees an unchanged value
	// on every plan/refresh cycle after the initial create.
	state.License = priorLicense

	// Optional+Computed — only hydrate when user configured bind_type (state non-null).
	// CM returns a non-empty default bind_type even when the user omitted it;
	// preserving null avoids perpetual state="instance" vs config=null drift.
	if !state.BindType.IsNull() {
		if r := gjson.Get(response, "bind_type"); r.Exists() && r.String() != "" {
			state.BindType = types.StringValue(r.String())
		} else {
			state.BindType = types.StringNull()
		}
	}
	// Computed-only — unconditional hydration from Swagger Licenses GET response fields.
	state.Hash = types.StringValue(gjson.Get(response, "hash").String())
	state.Type = types.StringValue(gjson.Get(response, "type").String())
	state.State = types.StringValue(gjson.Get(response, "state").String())
	state.Start = types.StringValue(gjson.Get(response, "start").String())
	state.Expiration = types.StringValue(gjson.Get(response, "expiration").String())
	state.Version = types.StringValue(gjson.Get(response, "version").String())
	state.LicenseCount = types.Int64Value(gjson.Get(response, "license_count").Int())
	state.TrialSecondsRemaining = types.StringValue(gjson.Get(response, "trial_seconds_remaining").String())

	// Note: `feature` is present in the Swagger Licenses definition but absent from
	// CMLicenseTFSDK. CM-side changes to feature are invisible to drift detection.
	// Pre-existing gap; out of scope for TFIN-430.

	// Set refreshed state.
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMLicense) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_license.go -> Update]")
	resp.Diagnostics.AddError(
		"Update Not Supported",
		"ciphertrust_license does not support updates. Delete and recreate this resource to change any field.",
	)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_license.go -> Update]")
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
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_LICENSE, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_license.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			return
		}
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
