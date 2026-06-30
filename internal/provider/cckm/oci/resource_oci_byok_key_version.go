package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIByokVersion{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIByokVersion{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIByokVersion{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMOCIByokVersion{}
)

func NewResourceCCKMOCIByokVersion() resource.Resource {
	return &resourceCCKMOCIByokVersion{}
}

type resourceCCKMOCIByokVersion struct {
	client *common.Client
}

func (r *resourceCCKMOCIByokVersion) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_byok_key_version"
}

func (r *resourceCCKMOCIByokVersion) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMOCIByokVersion) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage OCI BYOK key versions in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "The account which owns this resource.",
			},
			"cckm_key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager Key ID.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager cloud name.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the application was created",
			},
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The key's CipherTrust Manager resource ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager origin of the key version's material.",
			},
			"oci_key_version_params": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "OCI key attributes.",
				Attributes: map[string]schema.Attribute{
					"compartment_id": schema.StringAttribute{
						Computed:    true,
						Description: "The compartment's OCID.",
					},
					"is_primary": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the key belongs to a primary vault or a replica vault.",
					},
					"key_id": schema.StringAttribute{
						Computed:    true,
						Description: "The key's OCID.",
					},
					"lifecycle_state": schema.StringAttribute{
						Computed:    true,
						Description: "The key version's current lifecycle state.",
					},
					"origin": schema.StringAttribute{
						Computed:    true,
						Description: "Origin of the version;s key material.",
					},
					"public_key": schema.StringAttribute{
						Computed:    true,
						Description: "Version's public key.",
					},
					"replication_id": schema.StringAttribute{
						Computed:    true,
						Description: "The replication ID associated with a key version operation.",
					},
					"restored_from_key_version_id": schema.StringAttribute{
						Computed:    true,
						Description: "Key version OCID from which this key version was restored.",
					},
					"time_created": schema.StringAttribute{
						Computed:    true,
						Description: "The time the key version was created.",
					},
					"time_of_deletion": schema.StringAttribute{
						Computed:    true,
						Description: "The time when the key version will be deleted.",
					},
					"vault_id": schema.StringAttribute{
						Computed:    true,
						Description: "OCI Vault OCID.",
					},
					"version_id": schema.StringAttribute{
						Computed:    true,
						Description: "OCI version ID",
					},
				},
			},
			"refreshed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the key was refreshed.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "(Updatable) Number of days to wait before permanently deleting the OCI BYOK key version " +
					"when this resource is destroyed. If omitted during resource creation, " +
					"the value defaults to " + strconv.Itoa(scheduleForDeletionDays) + ". Once set, the last configured value is retained in state " +
					"and is used during destroy unless changed explicitly.",
				PlanModifiers: []planmodifier.Int64{retainOrDefaultInt64{defaultVal: scheduleForDeletionDays}},
				Validators:    []validator.Int64{int64validator.AtLeast(scheduleForDeletionDays), int64validator.AtMost(30)},
			},
			"source_key_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the key that will be uploaded from a key source to OCI.",
			},
			"source_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the key that will be uploaded from the key source to OCI.",
			},
			"source_key_tier": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("local"),
				Description: "Key source from where the key will be uploaded. The default is 'local'. The only option is 'local'.",
				Validators:  []validator.String{stringvalidator.OneOf([]string{"local"}...)},
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the application was updated.",
			},
			"uri": schema.StringAttribute{
				Description: "CipherTrust Manager's unique identifier for the resource.",
				Computed:    true,
			},
		},
	}
}

// Create uploads a new BYOK key version to OCI via CipherTrust Manager.
// After the version is successfully created, subsequent operations (waitForKeyVersionState,
// GetById) are downgraded to warnings so the created version is always stored in state.
// Warnings are emitted when:
//   - the version's lifecycle_state does not settle within oci_operation_timeout
//   - the post-creation GetById refresh call fails (state is set from the create response)
func (r *resourceCCKMOCIByokVersion) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key_version.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key_version.go -> Create]["+id+"]")

	mutexKey := fmt.Sprintf("ocikeyversion-%s", id)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	var plan models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := plan.CCKMKeyID.ValueString()
	payload := models.AddKeyVersionPayloadJSON{
		IsNative:      false,
		SourceKeyID:   plan.SourceKeyID.ValueString(),
		SourceKeyTier: plan.SourceKeyTier.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error uploading key to OCI, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := ociPostDataV2WithRetry(ctx, r.client, id, common.URL_OCI+"/keys/"+keyID+"/versions", payloadJSON)
	if err != nil {
		msg := "Error adding key version to OCI."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	versionID := gjson.Get(response, "id").String()
	plan.ID = types.StringValue(versionID)

	// No errors now

	var waitDiags diag.Diagnostics
	waitForKeyVersionState(ctx, id, r.client, keyID, versionID, keyStateEnabled, &waitDiags)
	if waitDiags.HasError() {
		for _, d := range waitDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	getResponse, err := r.client.GetById(ctx, id, versionID, common.URL_OCI+"/keys/"+keyID+"/versions")
	if err != nil {
		msg := "Error reading OCI key version."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResponse
	}

	var setStateDiags diag.Diagnostics
	tflog.Debug(ctx, "[resource_oci_byok_key_version.go -> Create][response:"+redactOCIResponse(response)+"]")
	setBYOOKKeyVersionState(ctx, response, &plan, &setStateDiags)
	for _, d := range setStateDiags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the OCI BYOK key version state from CipherTrust Manager.
// Returns a warning and removes the resource from state if the version is not found (404)
// or if the version is scheduled for deletion.
func (r *resourceCCKMOCIByokVersion) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key_version.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key_version.go -> Read]["+id+"]")

	var state models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	versionID := state.ID.ValueString()
	keyID := state.CCKMKeyID.ValueString()

	response := getOciKeyVersion(ctx, id, r.client, keyID, versionID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	readVersionState := gjson.Get(response, "oci_key_version_params.lifecycle_state").String()
	if readVersionState == keyStateScheduledForDeletion || readVersionState == keyStatePendingDeletion {
		msg := fmt.Sprintf(utils.PendingDeletionReadFmt, "OCI", "BYOK key version", readVersionState, "OCI")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "version_id": versionID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}
	setBYOOKKeyVersionState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update checks the OCI BYOK key version state in CipherTrust Manager and retains
// the resource in state if the version is scheduled for deletion. The only schema
// attribute that can differ between plan and state is schedule_for_deletion_days,
// which is stored locally and applied at destroy time only; its updated value is
// preserved in state after the check.
func (r *resourceCCKMOCIByokVersion) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key_version.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key_version.go -> Update]["+id+"]")

	var state models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.CCKMKeyID.ValueString()
	versionID := state.ID.ValueString()

	response := getOciKeyVersion(ctx, id, r.client, keyID, versionID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	updateVersionState := gjson.Get(response, "oci_key_version_params.lifecycle_state").String()
	if updateVersionState == keyStateScheduledForDeletion || updateVersionState == keyStatePendingDeletion {
		msg := fmt.Sprintf(utils.PendingDeletionUpdateFmt, "OCI", "BYOK key version", updateVersionState, "OCI")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "version_id": versionID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}

	var plan models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	setBYOOKKeyVersionState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete schedules the OCI BYOK key version for deletion via deleteKeyVersion
// (oci_key_version_common.go).
// Returns a warning if:
//   - the version is not found (404)  -  resource is removed from state
//   - the version is the current version of the parent key  -  resource is removed from
//     state but the version remains active in OCI until the parent key is deleted
func (r *resourceCCKMOCIByokVersion) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key_version.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key_version.go -> Delete]["+id+"]")
	var state models.BYOKKeyVersionTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.CCKMKeyID.ValueString()
	versionID := state.ID.ValueString()
	days := state.ScheduleForDeletionDays.ValueInt64()
	deleteKeyVersion(ctx, id, r.client, keyID, versionID, days, &resp.Diagnostics)
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceCCKMOCIByokVersion) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state models.BYOKKeyVersionTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string

	if plan.CCKMKeyID != state.CCKMKeyID {
		changed = append(changed, "cckm_key_id")
	}

	if plan.SourceKeyID != state.SourceKeyID {
		changed = append(changed, "source_key_id")
	}

	// source_key_tier is Optional+Computed; skip when the plan value is not yet known.
	if !plan.SourceKeyTier.IsUnknown() && plan.SourceKeyTier != state.SourceKeyTier {
		changed = append(changed, "source_key_tier")
	}

	if len(changed) > 0 {
		resp.Diagnostics.AddError(
			"Immutable attribute change detected",
			fmt.Sprintf(
				"The following attributes cannot be modified after creation: %s. "+
					"Delete and recreate the resource to apply these changes.",
				strings.Join(changed, ", "),
			),
		)
	}
}

// ImportState imports an OCI BYOK key version using the composite ID format: cckm_key_id.version_id.
func (r *resourceCCKMOCIByokVersion) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key_version.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key_version.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
	versionInfo := strings.Split(req.ID, ".")
	if len(versionInfo) != 2 {
		msg := "Invalid OCI BYOK key version import ID. Please set id to cckm_key_id.version_id."
		details := utils.ApiError(msg, map[string]interface{}{"id": req.ID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	keyID := versionInfo[0]
	versionID := versionInfo[1]
	response, err := r.client.GetById(ctx, id, versionID, common.URL_OCI+"/keys/"+keyID+"/versions")
	if err != nil {
		msg := "Error reading OCI key version."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID, "version_id": versionID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[resource_oci_byok_key_version.go -> ImportState][response:"+redactOCIResponse(response)+"]")
	var state models.BYOKKeyVersionTFSDK
	state.CCKMKeyID = types.StringValue(keyID)
	state.ID = types.StringValue(versionID)
	setBYOOKKeyVersionState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	state.ScheduleForDeletionDays = types.Int64Value(scheduleForDeletionDays)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// setBYOOKKeyVersionState populates the full TFSDK state for the BYOK key version resource.
// Delegates shared fields to setCommonKeyVersionState (oci_key_version_common.go).
// Note: function name contains a typo (double-O: BYOOK)  -  preserved to avoid unnecessary churn.
func setBYOOKKeyVersionState(ctx context.Context, response string, state *models.BYOKKeyVersionTFSDK, diags *diag.Diagnostics) {
	setCommonKeyVersionState(ctx, response, &state.KeyVersionTFSDK, diags)
	state.SourceKeyID = types.StringValue(gjson.Get(response, "source_key_identifier").String())
	state.SourceKeyName = types.StringValue(gjson.Get(response, "source_key_name").String())
	state.SourceKeyTier = types.StringValue(gjson.Get(response, "source_key_tier").String())
}
