package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &resourceCMProperty{}
	_ resource.ResourceWithConfigure      = &resourceCMProperty{}
	_ resource.ResourceWithValidateConfig = &resourceCMProperty{}
	_ resource.ResourceWithImportState    = &resourceCMProperty{}
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

func (r *resourceCMProperty) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_property", resp)
}

// Schema defines the schema for the resource.
func (r *resourceCMProperty) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a CipherTrust Manager system property. **Only available on CipherTrust Manager — not supported on CDSPaaS, where system properties are managed by the platform.**",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for the system property.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the system property. Immutable after creation.",
				PlanModifiers: []planmodifier.String{
					NameImmutableModifier{},
				},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"value": schema.StringAttribute{
				Optional:    true,
				Description: "Value to set for the property. If omitted or null, the property is reset to its CM default via POST /configs/properties/{name}/reset. An explicit empty string is rejected at plan time.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the property and its value (read-only from API)",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCMProperty) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_property.go -> Create][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_property.go -> Create][" + id + "]")

	var plan CMPropertyTFSDK
	var payload CMPropertyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Value.IsNull() || plan.Value.IsUnknown() {
		// value omitted from config — reset the property to CM's default.
		var resetPayload []byte
		response, err := r.client.PostDataV2(
			ctx,
			id,
			common.URL_CM_PROPERTIES+"/"+plan.Name.ValueString()+"/reset",
			resetPayload)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error resetting property on CipherTrust Manager: ",
				"Could not reset property "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
			)
			return
		}
		r.client.Log.Debug("[resource_property.go -> Create (reset) -> Response][" + response + "]")
	} else {
		payload.Value = plan.Value.ValueString()

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Invalid data input: Property Updation",
				err.Error(),
			)
			return
		}

		response, err := r.client.UpdateDataFullURL(
			ctx,
			id,
			common.URL_CM_PROPERTIES+"/"+plan.Name.ValueString(),
			payloadJSON,
			"name")
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Create][" + id + "]")
			resp.Diagnostics.AddError(
				"Error updating property on CipherTrust Manager: ",
				"Could not update property "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
			)
			return
		}
		r.client.Log.Debug("[resource_property.go -> Create Output -> Response][" + response + "]")
	}

	// Read back the property to get the description and other computed fields.
	readResponse, err := r.client.ReadDataByParam(ctx, id, plan.Name.ValueString(), common.URL_CM_PROPERTIES)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Create -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading CM Property on CipherTrust Manager after creation: ",
			"Could not read CM Property: "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// plan.Value is already correct (either the user-provided string or types.StringNull()).
	plan.ID = plan.Name
	plan.Description = types.StringValue(gjson.Get(readResponse, "description").String())

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
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_property.go -> Read][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_property.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.Name.ValueString(), common.URL_CM_PROPERTIES)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			r.client.Log.Debug(common.ERR_METHOD_END + "property not found (404) [resource_property.go -> Read][" + id + "]")
			resp.Diagnostics.AddError(
				fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "CM Property"),
				fmt.Sprintf(common.NotFoundReadErrorDetailFmt, "CM Property", state.Name.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading CM Property on CipherTrust Manager: ",
			"Could not read CM Property: "+state.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.ID = state.Name
	if state.Value.IsNull() || state.Value.IsUnknown() {
		state.Value = types.StringNull()
	} else {
		vr := gjson.Get(response, "value")
		if vr.Exists() {
			state.Value = types.StringValue(vr.String())
		} else {
			state.Value = types.StringNull()
		}
	}
	state.Description = types.StringValue(gjson.Get(response, "description").String())

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCMProperty) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_property.go -> Update][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_property.go -> Update][" + id + "]")

	var plan CMPropertyTFSDK
	var payload CMPropertyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Value.IsNull() || plan.Value.IsUnknown() {
		// value removed from config — reset the property to CM's default.
		var resetPayload []byte
		response, err := r.client.PostDataV2(
			ctx,
			id,
			common.URL_CM_PROPERTIES+"/"+plan.Name.ValueString()+"/reset",
			resetPayload)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Update][" + id + "]")
			resp.Diagnostics.AddError(
				"Error resetting property on CipherTrust Manager: ",
				"Could not reset property "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
			)
			return
		}
		r.client.Log.Debug("[resource_property.go -> Update (reset) -> Response][" + response + "]")
	} else {
		payload.Value = plan.Value.ValueString()

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Update][" + id + "]")
			resp.Diagnostics.AddError(
				"Invalid data input: Property Updation",
				err.Error(),
			)
			return
		}

		response, err := r.client.UpdateDataFullURL(
			ctx,
			id,
			common.URL_CM_PROPERTIES+"/"+plan.Name.ValueString(),
			payloadJSON,
			"name")
		if err != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Update][" + id + "]")
			resp.Diagnostics.AddError(
				"Error updating property on CipherTrust Manager: ",
				"Could not update property "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
			)
			return
		}
		r.client.Log.Debug("[resource_property.go -> Update -> Response][" + response + "]")
	}

	// Read back the property to get the description and other computed fields.
	readResponse, err := r.client.ReadDataByParam(ctx, id, plan.Name.ValueString(), common.URL_CM_PROPERTIES)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Update -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading CM Property on CipherTrust Manager after update: ",
			"Could not read CM Property: "+plan.Name.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// plan.Value is already correct (either the user-provided string or types.StringNull()).
	plan.ID = plan.Name
	plan.Description = types.StringValue(gjson.Get(readResponse, "description").String())

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCMProperty) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMPropertyTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_property.go -> Delete][" + id + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_property.go -> Delete][" + id + "]")

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
	r.client.Log.Debug("[resource_property.go -> Delete -> Response][" + response + "]")
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			resp.Diagnostics.AddWarning(
				common.NotFoundDeleteWarningSummary,
				fmt.Sprintf(common.NotFoundDeleteWarningDetailFmt, "CM Property", state.Name.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_property.go -> Delete][" + state.Name.ValueString() + "]")
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

func (r *resourceCMProperty) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("name"), req, resp)
}
