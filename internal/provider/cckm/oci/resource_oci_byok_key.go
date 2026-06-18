package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMOCIByokKey{}
	_ resource.ResourceWithConfigure   = &resourceCCKMOCIByokKey{}
	_ resource.ResourceWithImportState = &resourceCCKMOCIByokKey{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMOCIByokKey{}
)

const (
	ociKeySleepSeconds           = 3
	refreshTokenSeconds          = 180
	keyStateEnabling             = "ENABLING"
	keyStateEnabled              = "ENABLED"
	keyStateDisabling            = "DISABLING"
	keyStateDisabled             = "DISABLED"
	keyStateUpdating             = "UPDATING"
	keyStateScheduledForDeletion = "SCHEDULING_DELETION"
	keyStateChangingCompartment  = "CHANGING_COMPARTMENT"
	notFoundError                = "status: 404"
	scheduleForDeletionDays      = 7
)

func NewResourceCCKMOCIByokKey() resource.Resource {
	return &resourceCCKMOCIByokKey{}
}

type resourceCCKMOCIByokKey struct {
	client *common.Client
}

func (r *resourceCCKMOCIByokKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_byok_key"
}

func (r *resourceCCKMOCIByokKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMOCIByokKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage OCI BYOK keys in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"account": schema.StringAttribute{
				Computed:    true,
				Description: "The account which owns this resource.",
			},
			"auto_rotate": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the key is enabled for auto-rotation.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager cloud name.",
			},
			"compartment_name": schema.StringAttribute{
				Computed:    true,
				Description: "The compartment's name.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the key was created in CipherTrust Manager.",
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Updatable) Enable or disable the key. Default is true.",
				Default:     booldefault.StaticBool(true),
			},
			"enable_auto_rotation": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "(Updatable) Enable the key for a scheduled rotation job.",
				Attributes: map[string]schema.Attribute{
					"job_config_id": schema.StringAttribute{
						Required:    true,
						Description: "(Updatable) CipherTrust Manager resource ID of a key rotation scheduler.",
					},
					"key_source": schema.StringAttribute{
						Required:    true,
						Description: "(Updatable) Currently, the only option is 'ciphertrust'.",
						Validators:  []validator.String{stringvalidator.OneOf("ciphertrust")},
					},
				},
			},
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The key's CipherTrust Manager resource ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager origin of the key's material.",
			},
			"labels": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "A list of key:value pairs associated with the key.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "(Updatable) Name for the key.",
			},
			"oci_key_params": schema.SingleNestedAttribute{
				Required:    true,
				Description: "OCI key attributes.",
				Attributes: map[string]schema.Attribute{
					"algorithm": schema.StringAttribute{
						Computed:    true,
						Description: "The algorithm used by the key's versions to encrypt or decrypt.",
					},
					"compartment_id": schema.StringAttribute{
						Required:    true,
						Description: "(Updatable) The compartment's OCID.",
					},
					"current_key_version": schema.StringAttribute{
						Computed:    true,
						Description: "The OCID of the key's current version.",
					},
					"curve_id": schema.StringAttribute{
						Computed:    true,
						Description: "The curve ID of the ECDSA key.",
					},
					"defined_tags": schema.SetNestedAttribute{
						Optional:    true,
						Computed:    true,
						Description: "(Updatable) Defined tags for the key.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"tag": schema.StringAttribute{
									Required:    true,
									Description: "The tag's namespace as defined in OCI.",
								},
								"values": schema.MapAttribute{
									Required:    true,
									ElementType: types.StringType,
									Description: "The key:value pairs to associate with the tag as defined in OCI.",
								},
							},
						},
					},
					"display_name": schema.StringAttribute{
						Computed:    true,
						Description: "The key's name.",
					},
					"freeform_tags": schema.MapAttribute{
						Optional:    true,
						Computed:    true,
						ElementType: types.StringType,
						Description: "(Updatable) Freeform tags for the key. Freeform tags are key:value pairs.",
					},
					"is_primary": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the key belongs to a primary vault or a replica vault.",
					},
					"key_id": schema.StringAttribute{
						Computed:    true,
						Description: "The key's OCID.",
					},
					"length": schema.Int64Attribute{
						Computed:    true,
						Description: "The length of the key.",
					},
					"lifecycle_state": schema.StringAttribute{
						Computed:    true,
						Description: "The key's current lifecycle state.",
					},
					"protection_mode": schema.StringAttribute{
						Required:    true,
						Description: "The protection mode of the key. Options are: HSM or SOFTWARE.",
						Validators:  []validator.String{stringvalidator.OneOf([]string{"HSM", "SOFTWARE"}...)},
					},
					"replication_id": schema.StringAttribute{
						Computed:    true,
						Description: "The replication ID associated with a key operation.",
					},
					"restored_from_key_id": schema.StringAttribute{
						Computed:    true,
						Description: "The OCID of the key from which this key was restored.",
					},
					"time_created": schema.StringAttribute{
						Computed:    true,
						Description: "The time the key was created.",
					},
					"time_of_deletion": schema.StringAttribute{
						Computed:    true,
						Description: "The time when the key version will be deleted.",
					},
					"vault_name": schema.StringAttribute{
						Computed:    true,
						Description: "The vault's name.",
					},
				},
			},
			"refreshed_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the key was refreshed.",
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "The key's region.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "(Updatable) Waiting period in days after the key is destroyed before the key is deleted from OCI. Only relevant when the resource is destroyed. Must be between 7 and 30. Default is " + strconv.Itoa(scheduleForDeletionDays) + ".",
				Default:     int64default.StaticInt64(scheduleForDeletionDays),
				Validators: []validator.Int64{
					int64validator.AtLeast(scheduleForDeletionDays),
					int64validator.AtMost(30),
				},
			},
			"source_key_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the key that will be uploaded from a key source to OCI.",
			},
			"source_key_tier": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString("local"),
				Description: "Key source from where the key will be uploaded. The default is 'local'. The only option is 'local'.",
				Validators:  []validator.String{stringvalidator.OneOf([]string{"local"}...)},
			},
			"tenancy": schema.StringAttribute{
				Computed:    true,
				Description: "The key's tenancy.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date/time the application was updated.",
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager's unique identifier for the resource.",
			},
			"vault": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI vault resource ID.",
			},
			"vault_id": schema.StringAttribute{
				Computed:    true,
				Description: "The vault's OCID.",
			},
			"version_summary": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Key version summary.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"cckm_version_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the version.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the version was created in CipherTrust Manager.",
						},
						"source_key_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager key ID used to create the version.",
						},
						"source_key_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the key used to create the version.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Description: "Source of the key used to create the version.",
						},
						"version_id": schema.StringAttribute{
							Computed:    true,
							Description: "The key version's OCID",
						},
					},
				},
			},
		},
	}
}

// Create uploads an existing CipherTrust Manager key to OCI as a BYOK key. If the upload succeeds, subsequent
// failures (state wait, auto-rotation enablement, key disable, refresh) are reported as warnings only  -  the
// resource is created and its ID is committed to state before any of those post-upload steps run.
func (r *resourceCCKMOCIByokKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key.go -> Create]["+id+"]")

	var plan models.BYOKKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload := models.UploadKeyPayloadJSON{
		SourceKeyTier:       plan.SourceKeyTier.ValueString(),
		SourceKeyIdentifier: plan.SourceKeyIdentifier.ValueString(),
		Vault:               plan.Vault.ValueString(),
		Name:                plan.Name.ValueString(),
		ProtectionMode:      plan.KeyParams.ProtectionMode.ValueString(),
		CompartmentID:       plan.KeyParams.CompartmentID.ValueString(),
	}
	definedTags := getDefinedTagsFromPlan(ctx, &plan.KeyParams.DefinedTags, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.DefinedTags = definedTags
	freeformTags := getFreeformTagsFromPlan(ctx, &plan.KeyParams.FreeformTags, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.FreeformTags = freeformTags

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error uploading key to OCI, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": payload.Name})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	response, err := ociPostDataV2WithRetry(ctx, r.client, id, common.URL_OCI+"/upload-key", payloadJSON)
	if err != nil {
		msg := "Error uploading key to OCI."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": payload.Name})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	keyID := gjson.Get(response, "id").String()
	keyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	plan.ID = types.StringValue(keyID)

	// no errors after this as the key is created

	var waitDiags diag.Diagnostics
	waitForKeyStateChange(ctx, id, r.client, keyID, keyState, false, &waitDiags)
	if waitDiags.HasError() {
		for _, d := range waitDiags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	if plan.EnableAutoRotation != nil {
		var diags diag.Diagnostics
		enableSchedulerRotation(ctx, id, r.client, keyID, plan.EnableAutoRotation, &diags)
		if diags.HasError() {
			for _, d := range diags {
				resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
			}
		}
	}

	if !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		disableKey(ctx, id, r.client, keyID, &diags)
		if diags.HasError() {
			for _, d := range diags {
				resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
			}
		}
	}

	refreshResponse, err := ociPostNoDataWithRetry(ctx, r.client, id, common.URL_OCI+"/keys/"+keyID+"/refresh")
	if err != nil {
		msg := "Error refreshing OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		resp.Diagnostics.AddWarning(details, "")
		tflog.Error(ctx, details)
	} else {
		response = refreshResponse
	}

	var setStateDiags diag.Diagnostics
	tflog.Debug(ctx, "[resource_oci_byok_key.go -> Create][response:"+redactOCIResponse(response)+"]")
	setByokKeyState(ctx, id, r.client, response, &plan, &setStateDiags)
	for _, d := range setStateDiags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the resource state from the CipherTrust Manager API.
// Returns an error if the vault or key is not found (HTTP 404).
// Removes the resource from state only if the key lifecycle state is SCHEDULING_DELETION.
func (r *resourceCCKMOCIByokKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key.go -> Read]["+id+"]")

	var state models.BYOKKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()

	vaultID := state.Vault.ValueString()
	response := getOciKey(ctx, id, r.client, vaultID, keyID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	readKeyState := gjson.Get(response, "oci_params.lifecycle_state").String()
	if readKeyState == keyStateScheduledForDeletion {
		msg := "OCI BYOK key is scheduled for deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	setByokKeyState(ctx, id, r.client, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update applies changes to a BYOK key. Updatable attributes are: name, oci_key_params.compartment_id,
// oci_key_params.freeform_tags, oci_key_params.defined_tags, enable_key, and enable_auto_rotation.
// Attributes source_key_id, source_key_tier, vault, and oci_key_params.protection_mode are not updatable
// and require destroy + recreate.
func (r *resourceCCKMOCIByokKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key.go -> Update]["+id+"]")

	var plan models.BYOKKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var state models.BYOKKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()

	vaultID := state.Vault.ValueString()
	preCheckResponse := getOciKey(ctx, id, r.client, vaultID, keyID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	preCheckKeyState := gjson.Get(preCheckResponse, "oci_params.lifecycle_state").String()
	if preCheckKeyState == keyStateScheduledForDeletion {
		msg := "OCI BYOK key is scheduled for deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}

	updateKey(ctx, id, r.client, keyID, &plan.KeyCommonTFSDK, &state.KeyCommonTFSDK, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, keyID, common.URL_OCI+"/keys")
	if err != nil {
		msg := "Error reading OCI key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[resource_oci_byok_key.go -> Update][response:"+redactOCIResponse(response)+"]")
	setByokKeyState(ctx, id, r.client, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete schedules the OCI BYOK key for deletion via deleteKey.
// The key is not immediately removed from OCI; it enters a pending-deletion state for the number of
// days specified by schedule_for_deletion_days (7-30) before being permanently deleted.
func (r *resourceCCKMOCIByokKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key.go -> Delete]["+id+"]")
	var state models.BYOKKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()

	days := state.ScheduleForDeletionDays.ValueInt64()
	deleteOCIKey(ctx, id, r.client, state.Vault.ValueString(), keyID, days, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that OCI does not allow to be modified after creation.
func (r *resourceCCKMOCIByokKey) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state models.BYOKKeyTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// Defensive nil check.
	if plan.KeyParams == nil || state.KeyParams == nil {
		return
	}

	var changed []string

	if plan.KeyParams.ProtectionMode != state.KeyParams.ProtectionMode {
		changed = append(changed, "oci_key_params.protection_mode")
	}

	if plan.SourceKeyIdentifier != state.SourceKeyIdentifier {
		changed = append(changed, "source_key_id")
	}

	// source_key_tier is Optional+Computed; skip when the plan value is not yet known.
	if !plan.SourceKeyTier.IsUnknown() && plan.SourceKeyTier != state.SourceKeyTier {
		changed = append(changed, "source_key_tier")
	}

	if plan.Vault != state.Vault {
		changed = append(changed, "vault")
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

// ImportState imports an existing OCI BYOK key into Terraform state using its CipherTrust Manager resource ID.
func (r *resourceCCKMOCIByokKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_oci_byok_key.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_oci_byok_key.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setByokKeyState calls setKeyState for all common key fields, then additionally sets oci_key_params.curve_id
// and reconstructs source_key_id and source_key_tier by listing key versions. The first version (sorted ascending
// by createdAt) is used because the API response does not return these upload-time fields directly. If the version
// list call fails, a warning is emitted and the previous state values are preserved.
func setByokKeyState(ctx context.Context, id string, client *common.Client, response string, state *models.BYOKKeyTFSDK, diags *diag.Diagnostics) {
	setKeyState(ctx, id, client, response, &state.KeyTFSDK, diags)
	if diags.HasError() {
		return
	}
	state.KeyParams.CurveID = types.StringValue(gjson.Get(response, "oci_params.curve_id").String())
	filters := url.Values{}
	filters.Add("sort", "createdAt")
	keyID := state.ID.ValueString()
	versionsResponse, err := client.ListWithFilters(ctx, id, common.URL_OCI+"/keys/"+keyID+"/versions", filters)
	if err != nil {
		msg := "Failed to list OCI key versions."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		diags.AddWarning(details, "")
		return
	}
	if gjson.Get(versionsResponse, "resources").Exists() {
		resources := gjson.Get(versionsResponse, "resources").Array()
		if len(resources) > 0 {
			sourceKeyID := gjson.Get(resources[0].Raw, "source_key_identifier").String()
			sourceKeyTier := gjson.Get(resources[0].Raw, "source_key_tier").String()
			state.SourceKeyIdentifier = types.StringValue(sourceKeyID)
			state.SourceKeyTier = types.StringValue(sourceKeyTier)
		}
	}
}
