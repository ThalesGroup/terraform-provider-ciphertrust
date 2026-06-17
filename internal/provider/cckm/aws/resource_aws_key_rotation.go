package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource               = &resourceAWSKeyRotation{}
	_ resource.ResourceWithConfigure  = &resourceAWSKeyRotation{}
	_ resource.ResourceWithModifyPlan = &resourceAWSKeyRotation{}
)

// nativeRotationAwsParamAttrTypes defines the attribute types for the aws_params nested object
// inside each rotation_history entry. It must match nativeKeyRotationAwsParamTFSDK exactly.
var nativeRotationAwsParamAttrTypes = map[string]attr.Type{
	"import_state":       types.StringType,
	"key_id":             types.StringType,
	"key_material_id":    types.StringType,
	"key_material_state": types.StringType,
	"rotation_date":      types.StringType,
	"rotation_type":      types.StringType,
}

// nativeRotationEntryAttrTypes defines the attribute types for one rotation_history entry.
// It must match nativeKeyRotationEntryTFSDK exactly.
var nativeRotationEntryAttrTypes = map[string]attr.Type{
	"id":                  types.StringType,
	"created_at":          types.StringType,
	"updated_at":          types.StringType,
	"local_key_id":        types.StringType,
	"kms_id":              types.StringType,
	"key_material_origin": types.StringType,
	"aws_params": types.ObjectType{
		AttrTypes: nativeRotationAwsParamAttrTypes,
	},
}

// nativeRotationEntryElemType is the element type used for the rotation_history list attribute.
var nativeRotationEntryElemType = types.ObjectType{AttrTypes: nativeRotationEntryAttrTypes}

func NewResourceAWSKeyRotation() resource.Resource {
	return &resourceAWSKeyRotation{}
}

type resourceAWSKeyRotation struct {
	client *common.Client
}

func (r *resourceAWSKeyRotation) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key_rotation"
}

func (r *resourceAWSKeyRotation) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSKeyRotation) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to perform an on-demand rotation of an AWS native symmetric key. " +
			"Each time the trigger value changes, exactly one rotation is requested from AWS via " +
			"CipherTrust Manager. The rotation is a single-shot operation: once rotate-material has " +
			"been called it will never be retried automatically. " +
			"To request another rotation, change the trigger value to cause resource replacement. " +
			"This resource does not manage EXTERNAL keys; use aws_key_material for those. " +
			"\n\n\n\nNote: This resource and the datasource are only available for CipherTrust Manager version 2.20 and greater.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Resource identifier in the form <key_id>/<trigger>.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager UUID of the AWS native symmetric key to rotate. This attribute cannot be changed after creation.",
			},
			"trigger": schema.StringAttribute{
				Required: true,
				Description: "Arbitrary user-supplied value that controls when a rotation is requested. " +
					"Changing this value causes resource replacement, which requests exactly one additional on-demand rotation.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"rotation_history": schema.ListNestedAttribute{
				Computed:    true,
				Description: "Rotation history records for the key, refreshed after each successful rotation and on every plan/apply.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager ID for this rotation record.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time this rotation record was created in CipherTrust Manager.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time this rotation record was last updated in CipherTrust Manager.",
						},
						"local_key_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager ID of the AWS key this rotation record belongs to.",
						},
						"kms_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager AWS KMS ID.",
						},
						"key_material_origin": schema.StringAttribute{
							Computed:    true,
							Description: "Origin of the key material (e.g. 'native').",
						},
						"aws_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "AWS key-material attributes for this rotation entry.",
							Attributes: map[string]schema.Attribute{
								"import_state": schema.StringAttribute{
									Computed:    true,
									Description: "Import state of the key material.",
								},
								"key_id": schema.StringAttribute{
									Computed:    true,
									Description: "AWS key ARN or ID.",
								},
								"key_material_id": schema.StringAttribute{
									Computed:    true,
									Description: "Unique identifier for this key material version.",
								},
								"key_material_state": schema.StringAttribute{
									Computed:    true,
									Description: "State of the key material (e.g. CURRENT or NON_CURRENT).",
								},
								"rotation_date": schema.StringAttribute{
									Computed:    true,
									Description: "Date and time the key material rotation completed.",
								},
								"rotation_type": schema.StringAttribute{
									Computed:    true,
									Description: "Whether the rotation was ON_DEMAND or scheduled.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// Create performs one on-demand rotation of an AWS native symmetric key.
// It refreshes the key before snapshotting the pre-rotation state, calls
// rotate-material exactly once, then polls for completion before saving state.
func (r *resourceAWSKeyRotation) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Create]["+id+"]")

	var plan AWSNativeKeyRotationTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := plan.KeyID.ValueString()

	// Step 1: verify the key exists and is a native symmetric key. Capture updated_at
	// so we can detect when the subsequent refresh has completed.
	keyJSON, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error rotating AWS key: key not found in CipherTrust Manager."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	keyOrigin := gjson.Get(keyJSON, "aws_param.Origin").String()
	keyType := gjson.Get(keyJSON, "key_type").String()
	if keyOrigin != "AWS_KMS" || keyType != "symmetric" {
		msg := "key_id must refer to an AWS native symmetric key (Origin=AWS_KMS, key_type=symmetric). " +
			"This resource does not support EXTERNAL or asymmetric keys. Use aws_key_material for EXTERNAL keys."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "origin": keyOrigin, "key_type": keyType})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	preRefreshUpdatedAt := gjson.Get(keyJSON, "updatedAt").String()

	// Step 2: pre-rotation refresh (gives CCKM a chance to sync any out-of-band
	// rotations before we snapshot the pre-rotation state).
	_, refreshErr := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/refresh", []byte("{}"))
	if refreshErr != nil {
		msg := "Warning: pre-rotation key refresh failed; continuing with current cached state."
		details := utils.ApiError(msg, map[string]interface{}{"error": refreshErr.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		// Step 3: wait for the refresh to complete by polling for updated_at to change.
		// We do a best-effort wait; if it times out we continue with cached state.
		waitForKeyUpdatedAt(ctx, id, keyID, preRefreshUpdatedAt, r.client)
		// Extra buffer: rotation-history records are written last during a refresh.
		time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
	}

	// Step 4: re-fetch key to get a fresh snapshot of current state.
	keyJSON, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key state before rotation."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	prevMaterialID := gjson.Get(keyJSON, "aws_param.CurrentKeyMaterialId").String()

	// Step 5: snapshot the rotation history count before calling rotate-material.
	rotListFilters := url.Values{"limit": []string{"-1"}}
	rotListJSON, err := r.client.ListWithFilters(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotations", rotListFilters)
	if err != nil {
		msg := "Error reading rotation history before rotation."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	prevRotationCount := gjson.Get(rotListJSON, "total").Int()
	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_rotation.go -> Create] pre-rotation snapshot: key_id=%s prevMaterialID=%q prevRotationCount=%d",
		keyID, prevMaterialID, prevRotationCount,
	))

	// Step 6: call rotate-material exactly once. This is a single-shot action.
	// If the call succeeds we must NOT retry it, even if polling later times out.
	_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotate-material", nil)
	if err != nil {
		msg := "Error calling rotate-material on AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Info(ctx, "[resource_aws_key_rotation.go -> Create] rotate-material called successfully for key_id="+keyID)

	// Step 7: poll until the rotation is confirmed or timeout expires.
	// waitForNativeRotation sleeps at the top of each iteration so no head-start
	// sleep is needed here.
	if !waitForNativeRotation(ctx, id, keyID, r.client, prevMaterialID, prevRotationCount, &resp.Diagnostics) {
		// waitForNativeRotation added the error to diags. Do not write state because
		// rotate-material already fired - the user must change trigger to retry.
		return
	}

	// Step 8: fetch the final rotation history to populate state.
	rotHistory, listErr := fetchNativeRotationHistory(ctx, id, keyID, r.client)
	if listErr != nil {
		msg := "Error reading rotation history after successful rotation."
		details := utils.ApiError(msg, map[string]interface{}{"error": listErr.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	plan.RotationHistory = rotHistory
	plan.ID = types.StringValue(keyID + "/" + plan.Trigger.ValueString())
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read confirms the key still exists in CipherTrust Manager and refreshes
// the rotation_history computed attribute. If the key is pending deletion,
// the resource is removed from state with a warning.
func (r *resourceAWSKeyRotation) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Read]["+id+"]")

	var state AWSNativeKeyRotationTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := state.KeyID.ValueString()
	keyJSON, preserveState := getAwsKey(ctx, id, r.client, "", keyID, "reading", &resp.Diagnostics)
	if preserveState {
		// KMS is gone - keep existing state unchanged.
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	keyState := gjson.Get(keyJSON, "aws_param.KeyState").String()
	if keyState == "PendingDeletion" || keyState == "PendingReplicaDeletion" {
		msg := "AWS key is pending deletion; removing rotation resource from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}

	// Refresh the rotation history.
	rotHistory, listErr := fetchNativeRotationHistory(ctx, id, keyID, r.client)
	if listErr != nil {
		msg := "Error reading rotation history during refresh."
		details := utils.ApiError(msg, map[string]interface{}{"error": listErr.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		// Use the existing rotation_history from state rather than failing the read.
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}

	state.RotationHistory = rotHistory
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is a no-op. Both key_id and trigger are immutable (key_id via ModifyPlan error,
// trigger via RequiresReplace), so Update should never be called in practice.
func (r *resourceAWSKeyRotation) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
}

// Delete is a no-op. Removing this resource from state does not undo the rotation.
func (r *resourceAWSKeyRotation) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
}

// ModifyPlan enforces immutability of key_id and marks rotation_history as Unknown
// when trigger changes (causing a replacement that will produce a new rotation).
func (r *resourceAWSKeyRotation) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state AWSNativeKeyRotationTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// key_id must not change after creation.
	if plan.KeyID != state.KeyID {
		resp.Diagnostics.AddError(
			"key_id cannot be changed",
			"The key_id attribute cannot be modified after this resource is created. "+
				"Delete and recreate this resource to rotate a different key.",
		)
		return
	}

	// When trigger changes, RequiresReplace will cause a replacement. Mark
	// rotation_history as Unknown so Terraform shows the correct plan output.
	if plan.Trigger != state.Trigger {
		resp.Diagnostics.Append(
			resp.Plan.SetAttribute(ctx, path.Root("rotation_history"), types.ListUnknown(nativeRotationEntryElemType))...,
		)
	}
}

// waitForKeyUpdatedAt polls the key record until its updated_at timestamp changes from
// prevUpdatedAt, or until the timeout expires. This is used to detect when a /refresh
// call has completed. It is best-effort: a timeout is not treated as an error.
func waitForKeyUpdatedAt(
	ctx context.Context,
	id string,
	keyID string,
	prevUpdatedAt string,
	client *common.Client,
) {
	const (
		maxPolls     = 12
		pollInterval = shortAwsKeyOpSleep
	)
	for i := 0; i < maxPolls; i++ {
		time.Sleep(time.Duration(pollInterval) * time.Second)
		keyJSON, err := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
		if err != nil {
			tflog.Warn(ctx, fmt.Sprintf("[resource_aws_key_rotation.go -> waitForKeyUpdatedAt] poll %d/%d: error fetching key: %s",
				i+1, maxPolls, err.Error(),
			))
			continue
		}
		currentUpdatedAt := gjson.Get(keyJSON, "updatedAt").String()
		if currentUpdatedAt != "" && currentUpdatedAt != prevUpdatedAt {
			tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_rotation.go -> waitForKeyUpdatedAt] refresh detected: updated_at changed from %q to %q",
				prevUpdatedAt, currentUpdatedAt,
			))
			return
		}
	}
	tflog.Warn(ctx, "[resource_aws_key_rotation.go -> waitForKeyUpdatedAt] timed out waiting for updated_at to change; continuing")
}

// waitForNativeRotation polls CipherTrust Manager after a rotate-material call to confirm
// that the rotation completed. It checks two conditions on each poll:
//  1. aws_param.CurrentKeyMaterialId changed from prevMaterialID.
//  2. The rotation history record count increased beyond prevRotationCount.
//
// The function sleeps at the TOP of each iteration before fetching so the first poll
// also includes a wait. No /refresh calls are made at any point to avoid confusing
// CCKM state.
// Returns true on confirmed success, false if the timeout expired (error added t
func waitForNativeRotation(
	ctx context.Context,
	id string,
	keyID string,
	client *common.Client,
	prevMaterialID string,
	prevRotationCount int64,
	diags *diag.Diagnostics,
) bool {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> waitForNativeRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> waitForNativeRotation]["+id+"]")

	const (
		maxPolls     = 12
		pollInterval = shortAwsKeyOpSleep
	)

	rotListFilters := url.Values{"limit": []string{"-1"}}

	for i := 0; i < maxPolls; i++ {
		// Sleep first on every iteration (including the first) before fetching.
		time.Sleep(time.Duration(pollInterval) * time.Second)

		// Fetch the key record without calling /refresh first.
		keyJSON, err := client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error fetching key during rotation poll."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return false
		}
		currentMaterialID := gjson.Get(keyJSON, "aws_param.CurrentKeyMaterialId").String()

		// Fetch current rotation count.
		rotListJSON, listErr := client.ListWithFilters(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotations", rotListFilters)
		var currentRotationCount int64
		if listErr == nil {
			currentRotationCount = gjson.Get(rotListJSON, "total").Int()
		}

		tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_rotation.go -> waitForNativeRotation] poll %d/%d - rotationCount: prev=%d current=%d, currentMaterialID: prev=%q current=%q",
			i+1, maxPolls, prevRotationCount, currentRotationCount, prevMaterialID, currentMaterialID,
		))

		confirmed := false
		if currentMaterialID != "" && currentMaterialID != prevMaterialID {
			tflog.Info(ctx, "[resource_aws_key_rotation.go -> waitForNativeRotation] rotation confirmed via material ID change")
			confirmed = true
		} else if currentRotationCount > prevRotationCount {
			tflog.Info(ctx, "[resource_aws_key_rotation.go -> waitForNativeRotation] rotation confirmed via rotation count increase")
			confirmed = true
		}

		if confirmed {
			return true
		}

	}

	// Timeout reached. rotate-material was already called so state is NOT saved.
	// The user must change trigger to attempt another rotation.
	msg := "On-demand rotation was requested but completion could not be confirmed before the timeout expired. " +
		"The rotation may still complete asynchronously. " +
		"Refresh the key before retrying."
	details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
	tflog.Error(ctx, details)
	diags.AddError(details, "")
	return false
}

// fetchNativeRotationHistory retrieves all rotation records for the given key and returns
// a types.List of rotation history entries suitable for use in AWSNativeKeyRotationTFSDK.
// An error is returned when the API call or JSON parsing fails.
func fetchNativeRotationHistory(ctx context.Context, id string, keyID string, client *common.Client) (types.List, error) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> fetchNativeRotationHistory]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> fetchNativeRotationHistory]["+id+"]")

	emptyList, _ := types.ListValue(nativeRotationEntryElemType, []attr.Value{})

	filters := url.Values{"limit": []string{"-1"}}
	listJSON, err := client.ListWithFilters(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotations", filters)
	if err != nil {
		return emptyList, err
	}

	var rotationList NativeKeyRotationListJSON
	if unmarshalErr := json.Unmarshal([]byte(listJSON), &rotationList); unmarshalErr != nil {
		return emptyList, unmarshalErr
	}

	entries := make([]attr.Value, 0, len(rotationList.Resources))
	for _, r := range rotationList.Resources {
		awsParamVal, diags := types.ObjectValue(nativeRotationAwsParamAttrTypes, map[string]attr.Value{
			"import_state":       types.StringValue(r.AwsParam.ImportState),
			"key_id":             types.StringValue(r.AwsParam.KeyID),
			"key_material_id":    types.StringValue(r.AwsParam.KeyMaterialID),
			"key_material_state": types.StringValue(r.AwsParam.KeyMaterialState),
			"rotation_date":      types.StringValue(r.AwsParam.RotationDate),
			"rotation_type":      types.StringValue(r.AwsParam.RotationType),
		})
		if diags.HasError() {
			continue
		}

		entryVal, diags := types.ObjectValue(nativeRotationEntryAttrTypes, map[string]attr.Value{
			"id":                  types.StringValue(r.ID),
			"created_at":          types.StringValue(r.CreatedAt),
			"updated_at":          types.StringValue(r.UpdatedAt),
			"local_key_id":        types.StringValue(r.LocalKeyID),
			"kms_id":              types.StringValue(r.KmsID),
			"key_material_origin": types.StringValue(r.KeyMaterialOrigin),
			"aws_params":          awsParamVal,
		})
		if diags.HasError() {
			continue
		}
		entries = append(entries, entryVal)
	}

	result, diags := types.ListValue(nativeRotationEntryElemType, entries)
	if diags.HasError() {
		return emptyList, fmt.Errorf("error building rotation_history list")
	}
	return result, nil
}
