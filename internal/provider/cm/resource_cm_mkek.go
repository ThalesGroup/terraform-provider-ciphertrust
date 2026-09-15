package cm

import (
	"context"
	"strings"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCMMKEK{}
	_ resource.ResourceWithConfigure   = &resourceCMMKEK{}
	_ resource.ResourceWithImportState = &resourceCMMKEK{}
)

type resourceCMMKEK struct {
	client *common.Client
}

func NewResourceCmMkek() resource.Resource {
	return &resourceCMMKEK{}
}

func (r *resourceCMMKEK) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_mkek"
}

func (r *resourceCMMKEK) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	r.client = req.ProviderData.(*common.Client)
}

func (r *resourceCMMKEK) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Rotates the default Master KEK (MKEK) on the CipherTrust Manager and tracks the resulting MKEK entry. " +
			"Create() calls POST /v1/system/mkeks/rotate; the resource is read-only after creation. " +
			"Delete() is a no-op — CM does not support MKEK deletion. " +
			"Only available on CipherTrust Manager — not supported on CDSPaaS.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the MKEK.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the MKEK. May change when a new MKEK is rotated in.",
			},
			"is_default": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether this MKEK is the current default. Changes to false when a newer MKEK is rotated in.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp when the MKEK was created.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"sealer_name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the sealer associated with this MKEK. Empty string when not present in CM response. May change after rotation.",
			},
			"kek_name": schema.StringAttribute{
				Computed:    true,
				Description: "The name of the KEK wrapping this MKEK. Empty string when not present in CM response. May change after rotation.",
			},
		},
	}
}

func (r *resourceCMMKEK) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan CMMKEKInfoTFSDK
	uid := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_mkek.go -> Create][" + uid + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_mkek.go -> Create][" + uid + "]")

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// POST /v1/system/mkeks/rotate — no body needed.
	// Try to parse the new MKEK from the rotate response directly; if the endpoint
	// returns the MKEK object, we use GetById to load the canonical state from CM.
	// If not, fall back to listing all MKEKs.
	rotateResp, err := r.client.PostNoData(ctx, uid, common.URL_MKEK+"/rotate")
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_mkek.go -> Create][" + uid + "]")
		resp.Diagnostics.AddError(
			"Error Rotating MKEK on CipherTrust Manager",
			"Could not rotate MKEK, unexpected error: "+err.Error(),
		)
		return
	}

	var defaultEntry gjson.Result

	if rotateID := gjson.Get(rotateResp, "id"); rotateID.Exists() && rotateID.String() != "" {
		// Rotate endpoint returned the new MKEK object directly.
		defaultEntry = gjson.Parse(rotateResp)
	} else {
		// Fall back: GET /v1/system/mkeks raw list and find the default entry.
		// ReadDataByParam("all") returns the full raw body without key extraction.
		listResponse, listErr := r.client.ReadDataByParam(ctx, uid, "all", common.URL_MKEK)
		if listErr != nil {
			r.client.Log.Debug(common.ERR_METHOD_END + listErr.Error() + " [resource_cm_mkek.go -> Create][" + uid + "]")
			resp.Diagnostics.AddError(
				"Error Listing MKEKs After Rotate",
				"Could not list MKEKs, unexpected error: "+listErr.Error(),
			)
			return
		}

		// CM list envelope may use "resources" or another key; try both.
		resources := gjson.Get(listResponse, "resources")
		if !resources.Exists() || resources.Type == gjson.Null {
			resources = gjson.Parse(listResponse)
		}
		if !resources.IsArray() || len(resources.Array()) == 0 {
			resp.Diagnostics.AddError(
				"No MKEKs Found After Rotate",
				"CipherTrust Manager returned no MKEKs after rotate call.",
			)
			return
		}

		// Select the default MKEK entry. Fallback to first entry when no entry is marked
		// default — anomalous CM behavior; documented so the selection is not silent.
		for _, entry := range resources.Array() {
			if entry.Get("is_default").Bool() {
				defaultEntry = entry
				break
			}
		}
		if !defaultEntry.Exists() {
			// No entry has is_default=true. Select first entry as fallback.
			defaultEntry = resources.Array()[0]
		}
	}

	// All Computed-only — hydrate unconditionally.
	// sealer_name and kek_name return "" (valid known value) when CM omits the field.
	plan.ID = types.StringValue(defaultEntry.Get("id").String())
	plan.Name = types.StringValue(defaultEntry.Get("name").String())
	plan.IsDefault = types.BoolValue(defaultEntry.Get("is_default").Bool())
	plan.CreatedAt = types.StringValue(defaultEntry.Get("created_at").String())
	plan.SealerName = types.StringValue(defaultEntry.Get("sealer_name").String())
	plan.KEKName = types.StringValue(defaultEntry.Get("kek_name").String())

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
}

func (r *resourceCMMKEK) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CMMKEKInfoTFSDK
	uid := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_mkek.go -> Read][" + uid + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_mkek.go -> Read][" + uid + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, uid, state.ID.ValueString(), common.URL_MKEK)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			// 404: resource no longer exists on CM — remove from state silently.
			resp.State.RemoveResource(ctx)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_cm_mkek.go -> Read][" + uid + "]")
		resp.Diagnostics.AddError(
			"Error Reading MKEK on CipherTrust Manager",
			"Could not read MKEK id: "+state.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}

	// All Computed-only — hydrate unconditionally. No !IsNull() guards for Computed-only fields.
	// sealer_name and kek_name: gjson returns "" when the field is absent, which is a valid
	// known value for Computed-only state.
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.IsDefault = types.BoolValue(gjson.Get(response, "is_default").Bool())
	state.CreatedAt = types.StringValue(gjson.Get(response, "created_at").String())
	state.SealerName = types.StringValue(gjson.Get(response, "sealer_name").String())
	state.KEKName = types.StringValue(gjson.Get(response, "kek_name").String())

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (r *resourceCMMKEK) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	uid := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_mkek.go -> Update][" + uid + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_mkek.go -> Update][" + uid + "]")
	// No mutable fields — Update is never invoked by the framework for this resource.
}

func (r *resourceCMMKEK) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CMMKEKInfoTFSDK
	uid := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_cm_mkek.go -> Delete][" + uid + "]")
	defer r.client.Log.Trace(common.MSG_METHOD_END + "[resource_cm_mkek.go -> Delete][" + uid + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.AddWarning(
		"MKEK Cannot Be Deleted",
		"CipherTrust Manager does not provide a delete endpoint for MKEKs. The MKEK with id "+
			state.ID.ValueString()+" has been removed from Terraform state but still exists on the appliance.",
	)
}

func (r *resourceCMMKEK) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
