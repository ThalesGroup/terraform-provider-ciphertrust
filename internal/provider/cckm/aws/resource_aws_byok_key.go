package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceAWSByokKey{}
	_ resource.ResourceWithConfigure   = &resourceAWSByokKey{}
	_ resource.ResourceWithImportState = &resourceAWSByokKey{}
	_ resource.ResourceWithModifyPlan  = &resourceAWSByokKey{}
)

// NewResourceAWSByokKey returns a new aws_byok_key resource instance.
func NewResourceAWSByokKey() resource.Resource {
	return &resourceAWSByokKey{}
}

type resourceAWSByokKey struct {
	client *common.Client
}

func (r *resourceAWSByokKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_byok_key"
}

func (r *resourceAWSByokKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSByokKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage AWS EXTERNAL (BYOK) keys in CipherTrust Manager. " +
			"Key material from a CipherTrust Manager source key is uploaded to AWS via the upload-key API. " +
			"If the KMS is not found during refresh the key is kept in state until the KMS is recovered. " +
			"A key pending deletion is kept in state on refresh with a warning.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager ID of the key.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) AWS region in which to create the key.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"source_key_identifier": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "(Immutable) CipherTrust Manager key ID to upload to AWS as BYOK material. " +
					"Leave blank to create an EXTERNAL key in PendingImport state with no key material uploaded. " +
					"Populated on read from the API once material has been imported.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"source_key_tier": schema.StringAttribute{
				Computed: true,
				Optional: true,
				Description: "(Immutable) Source of the key material. The only valid value when specified is 'local' (a CipherTrust Manager key). " +
					"Leave blank when not importing key material.",
				Validators: []validator.String{
					stringvalidator.OneOf("local"),
				},
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
			},
			"enable_key": schema.BoolAttribute{
				Optional: true,
				Computed: true,
				Description: "Enable or disable the key. Default is true. " +
					"Cannot be set to false at creation time; disable via update after the key has been created.",
			},
			"kms_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "(Conditionally immutable) CipherTrust Manager ID of the KMS to create the key in. **Required** unless replicating a multi-region key. Can only be changed if the previously configured KMS no longer exists in CipherTrust Manager.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"primary_region": schema.StringAttribute{
				Optional:    true,
				Description: "Updates the primary region of a multi-region key. Only valid during updates.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional: true,
				Computed: true,
				Description: "Number of days to wait before permanently deleting the AWS KMS key " +
					"when this resource is destroyed. If omitted during resource creation, " +
					"the value defaults to 7. Once set, the last configured value is retained in state " +
					"and is used during destroy unless changed explicitly.",
				PlanModifiers: []planmodifier.Int64{retainOrDefaultInt64{defaultVal: 7}},
				Validators:    []validator.Int64{int64validator.AtLeast(7), int64validator.AtMost(30)},
			},
			// Key policy block
			"key_policy": keyPolicySchemaAttribute(),
			// Rotation job block
			"enable_rotation": enableRotationSchemaAttribute(),
			// Replicate key block - no import_key_material flag; material is always imported automatically
			"replicate_key": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Replicate a primary EXTERNAL multi-region key to a new region. " +
					"Key material will be imported from the primary key.",
				Attributes: map[string]schema.Attribute{
					"key_id": schema.StringAttribute{
						Required:    true,
						Description: "CipherTrust Manager resource of the primary key to replicate.",
					},
					"make_primary": schema.BoolAttribute{
						Optional:    true,
						Description: "Promote the replica to primary after replication. Only valid during replication creation.",
					},
				},
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "AWS cloud.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was created.",
			},
			"external_accounts": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Other AWS accounts that have access to this key.",
			},
			"key_admins": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "Key material origin.",
			},
			"key_source": schema.StringAttribute{
				Computed:    true,
				Description: "Source of the key.",
			},
			"key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Key type.",
			},
			"key_users": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"kms_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the AWS KMS resource.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Key:value pairs associated with the key.",
			},
			"local_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key identifier of the external key.",
			},
			"local_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key name of the external key.",
			},
			"policy_template_tag": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "AWS key tag for an associated policy template.",
			},
			"rotated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time when this key was rotated by a scheduled rotation job.",
			},
			"rotated_from": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID this key was rotated from.",
			},
			"rotated_to": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID this key was rotated to.",
			},
			"rotation_status": schema.StringAttribute{
				Computed:    true,
				Description: "Rotation status of the key.",
			},
			"synced_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was synchronized.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was last updated.",
			},
			"multi_region_configuration": schema.SingleNestedAttribute{
				Computed:    true,
				Description: "Multi-region configuration for the key. Set only when multi_region is true.",
				PlanModifiers: []planmodifier.Object{
					nullOrStateForUnknownObject{},
				},
				Attributes: map[string]schema.Attribute{
					"multi_region_key_type": schema.StringAttribute{
						Computed:    true,
						Description: "Whether this key is PRIMARY or REPLICA.",
					},
					"primary_key": schema.SingleNestedAttribute{
						Computed:    true,
						Description: "ARN and region of the primary key.",
						Attributes: map[string]schema.Attribute{
							"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the primary key."},
							"region": schema.StringAttribute{Computed: true, Description: "Region of the primary key."},
						},
					},
					"replica_keys": schema.SetNestedAttribute{
						Computed:    true,
						Description: "ARN and region of each replica key.",
						NestedObject: schema.NestedAttributeObject{
							Attributes: map[string]schema.Attribute{
								"arn":    schema.StringAttribute{Computed: true, Description: "ARN of the replica key."},
								"region": schema.StringAttribute{Computed: true, Description: "Region of the replica key."},
							},
						},
					},
				},
			},
			"aws_param": schema.SingleNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "AWS key parameters. Input fields are sent to the API on create/update; all fields are populated from the API response.",
				Attributes:  byokAwsParamSchemaAttributes(),
				PlanModifiers: []planmodifier.Object{
					nullOrStateForUnknownObject{},
				},
			},
			"rotation_history": rotationHistoryByokSummarySchemaAttribute(),
		},
	}
}

// Create creates a new AWS BYOK (EXTERNAL) key and sets Terraform state.
// Two creation paths are supported:
//   - replicate-key: when the replicate_key block is set, replicates a primary multi-region key.
//   - upload-key: when source_key_identifier is set, uploads CipherTrust Manager key material to
//     a new EXTERNAL key via the upload-key API.
//   - create-key: fallback when source_key_identifier is omitted; creates an EXTERNAL key in
//     PendingImport state with no material. Use aws_key_material to import material later.
//
// After the key is created the final state is read from the API. If the read fails a warning is
// added and the creation response is used for state instead.
func (r *resourceAWSByokKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> Create][" + id + "]")
	var (
		plan     AWSByokKeyTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	commonAwsParams := r.getByokKeyAwsParams(ctx, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if plan.ReplicateKey != nil {
		response = r.replicateByokKey(ctx, id, &plan, commonAwsParams, &resp.Diagnostics)
	} else {
		kmsID := plan.KMSID.ValueString()
		if kmsID == "" {
			msg := "Error creating AWS BYOK key: kms_id is required when not replicating a key."
			resp.Diagnostics.AddError(msg, "")
			return
		}
		if _, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS); err != nil {
			msg := "Error creating AWS BYOK key: kms_id does not resolve to a valid KMS."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		if !plan.SourceKeyID.IsNull() && !plan.SourceKeyID.IsUnknown() && plan.SourceKeyID.ValueString() != "" {
			response = r.uploadByokKey(ctx, id, kmsID, &plan, commonAwsParams, &resp.Diagnostics)
		} else {
			// No source_key_identifier provided - create key in PendingImport state.
			// Use the aws_key_material resource to import material separately.
			response = r.createByokKey(ctx, id, kmsID, &plan, commonAwsParams, &resp.Diagnostics)
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	if response == "" {
		resp.Diagnostics.AddError("Error creating AWS BYOK key: no response received from API.", "")
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	r.client.Log.Debug("[resource_aws_byok_key.go -> Create][response:" + redactAWSResponse(response))

	// Don't return errors after this

	keyID := plan.ID.ValueString()
	var err error
	getResponse, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS BYOK key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
	} else {
		response = getResponse
		r.client.Log.Debug("[resource_aws_byok_key.go -> Create][response:" + redactAWSResponse(response))
	}

	var diags diag.Diagnostics
	r.setByokKeyState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes Terraform state for an AWS BYOK key from CipherTrust Manager.
// If the key is not found and the KMS is also not found, existing state is preserved so that
// recovery is possible without manual state surgery. A key pending deletion is kept in state with a warning.
func (r *resourceAWSByokKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> Read][" + id + "]")
	var state AWSByokKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), state.ID.ValueString(), "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if gjson.Get(response, "gone").Bool() {
		msg := "AWS BYOK key is gone - its region is not in the KMS regions list. Key operations will fail until the region is restored to the KMS."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
	}
	readKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if readKeyState == "PendingDeletion" || readKeyState == "PendingReplicaDeletion" {
		msg := fmt.Sprintf(utils.PendingDeletionReadFmt, "AWS", "BYOK key", readKeyState, "AWS")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": state.ID.ValueString()})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
	}
	r.setByokKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies plan changes to an AWS BYOK key including policy, aliases, tags, rotation, and enable/disable.
// Key material import and rotation are managed separately via the aws_key_material resource.
func (r *resourceAWSByokKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> Update][" + id + "]")
	var (
		plan  AWSByokKeyTFSDK
		state AWSByokKeyTFSDK
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), keyID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_aws_byok_key.go -> Update][get response:" + redactAWSResponse(response))

	updateKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if updateKeyState == "PendingDeletion" || updateKeyState == "PendingReplicaDeletion" {
		msg := fmt.Sprintf(utils.PendingDeletionUpdateFmt, "AWS", "BYOK key", updateKeyState, "AWS")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
		// Policy updates are permitted by AWS on keys pending deletion.
		if plan.KeyPolicy != nil || state.KeyPolicy != nil {
			planUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: plan.KeyPolicy}
			stateUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: state.KeyPolicy}
			var policyDiags diag.Diagnostics
			updateKeyPolicy(ctx, id, r.client, planUpdate, stateUpdate, &policyDiags)
			for _, d := range policyDiags {
				if d.Severity() == diag.SeverityError {
					resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
				} else {
					resp.Diagnostics.Append(d)
				}
			}
			// Re-fetch to reflect any policy change in state.
			if updated, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY); err == nil {
				response = updated
			}
		}
		// key_policy IS updated in this path - reflect the new config value in state.
		state.KeyPolicy = plan.KeyPolicy
		r.setByokKeyState(ctx, response, &state, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	keyEnabled := gjson.Get(response, "aws_param.Enabled").Bool()
	planEnableKey := false
	if !plan.EnableKey.IsUnknown() {
		planEnableKey = plan.EnableKey.ValueBool()
		if !keyEnabled && planEnableKey {
			enableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		}
	}

	planParam := byokAwsParamFromObject(ctx, plan.AWSParam, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	desc := types.StringNull()
	if planParam != nil {
		desc = planParam.Description
	}
	planUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, Description: desc, KeyPolicy: plan.KeyPolicy, EnableRotation: plan.EnableRotation}
	stateUpdate := &AWSKeyUpdateInputTFSDK{KeyID: keyID, KeyPolicy: state.KeyPolicy, EnableRotation: state.EnableRotation}
	updateAwsKeyCommon(ctx, id, r.client, planUpdate, stateUpdate, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if planParam != nil && !planParam.Alias.IsUnknown() {
		updateAliases(ctx, id, r.client, plan.ID.ValueString(), planParam.Alias, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if planParam != nil && !planParam.Tags.IsUnknown() {
		planTags := make(map[string]string, len(planParam.Tags.Elements()))
		if len(planParam.Tags.Elements()) != 0 {
			resp.Diagnostics.Append(planParam.Tags.ElementsAs(ctx, &planTags, false)...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		updateTags(ctx, id, r.client, planTags, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if !plan.PrimaryRegion.IsUnknown() && plan.PrimaryRegion != state.PrimaryRegion {
		newPrimaryRegion := plan.PrimaryRegion.ValueString()
		primaryKeyJSON := getPrimaryKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		primaryKeyID := gjson.Get(primaryKeyJSON, "id").String()
		primaryKeyRegion := gjson.Get(primaryKeyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
		if primaryKeyRegion != newPrimaryRegion {
			awsMrkKeyID := gjson.Get(primaryKeyJSON, "aws_param.KeyId").String()
			newPrimaryKeyID := findKeyCMIDByRegion(ctx, id, r.client, awsMrkKeyID, newPrimaryRegion, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
			updatePrimaryRegion(ctx, id, r.client, primaryKeyID, newPrimaryRegion, newPrimaryKeyID, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		} else {
			resp.Diagnostics.AddWarning("'primary_region' specifies the current primary region", "")
		}
	}
	if !plan.EnableKey.IsUnknown() && keyEnabled && !planEnableKey {
		disableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	var err error
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS BYOK key, failed to read key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	// source_key_identifier and source_key_tier are managed by aws_key_material
	// after initial creation. Carry them forward from prior state so that
	// setByokKeyState never overwrites them with the (possibly rotated) local_key_id
	// returned by the API after a key material rotation.
	plan.SourceKeyID = state.SourceKeyID
	plan.SourceKeyTier = state.SourceKeyTier
	r.setByokKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	r.client.Log.Debug("[resource_aws_byok_key.go -> Update][response:" + redactAWSResponse(response))
}

// Delete schedules an AWS BYOK key for deletion via the schedule-deletion API. In either case:
//   - If the KMS is not found (404), a warning is added and the key is removed from state.
//   - If the KMS has a non-404 error, a hard error is returned and the key is kept in state.
//   - If the key is not found (404), a warning is returned and the key is removed from state.
//   - If the key is already in PendingDeletion or PendingReplicaDeletion state, a warning is returned and the key is removed from state.
func (r *resourceAWSByokKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> Delete][" + id + "]")
	var state AWSByokKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.ID.ValueString()
	response := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), keyID, "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if response == "" {
		return
	}
	keyState := gjson.Get(response, "aws_param.KeyState").String()
	if keyState == "PendingDeletion" || keyState == "PendingReplicaDeletion" {
		msg := fmt.Sprintf(utils.PendingDeletionDeleteFmt, "AWS", "BYOK key")
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		r.client.Log.Warn(details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}
	removeKeyPolicyTemplateTag(ctx, id, r.client, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := ScheduleForDeletionJSON{
		Days: state.ScheduleForDeletionDays.ValueInt64(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error deleting AWS BYOK key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
	if err != nil {
		msg := "Error deleting AWS BYOK key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		if strings.Contains(err.Error(), "is pending deletion") {
			r.client.Log.Warn(details)
			resp.Diagnostics.AddWarning(details, "")
		} else {
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
		}
	}
	r.client.Log.Debug("[resource_aws_byok_key.go -> Delete][response:" + redactAWSResponse(response))
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource.
func (r *resourceAWSByokKey) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		// Destroy - nothing to validate.
		return
	}
	// On create, validate attributes that cannot be used at creation time.
	if req.State.Raw.IsNull() {
		var createPlan AWSByokKeyTFSDK
		resp.Diagnostics.Append(req.Plan.Get(ctx, &createPlan)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if createParam := byokAwsParamFromObject(ctx, createPlan.AWSParam, &resp.Diagnostics); createParam != nil {
			if !createParam.Alias.IsUnknown() && !createParam.Alias.IsNull() && len(createParam.Alias.Elements()) > 1 {
				resp.Diagnostics.AddAttributeError(
					path.Root("aws_param").AtName("alias"),
					"Invalid create-time configuration",
					"At most one alias may be set when creating an AWS BYOK key. "+
						"Additional aliases can be added via update after the key has been created.",
				)
			}
		}
		if createPlan.EnableRotation != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("enable_rotation"),
				"Invalid create-time configuration",
				"'enable_rotation' cannot be set when creating an AWS BYOK key. "+
					"Configure it via update after the key has been created.",
			)
		}
		if !createPlan.EnableKey.IsUnknown() && !createPlan.EnableKey.IsNull() && !createPlan.EnableKey.ValueBool() {
			resp.Diagnostics.AddAttributeError(
				path.Root("enable_key"),
				"Invalid create-time configuration",
				"'enable_key' cannot be set to false when creating an AWS BYOK key. "+
					"Disable the key via update after it has been created.",
			)
		}
		return
	}
	var plan, state AWSByokKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string
	id := uuid.NewString()
	if !plan.KMSID.IsNull() && !plan.KMSID.IsUnknown() && plan.KMSID != state.KMSID {
		kmsID := state.KMSID.ValueString()
		if kmsID != "" {
			_, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
			if err != nil && strings.Contains(err.Error(), notFoundError) {
				msg := "Previous AWS KMS was not found, allowing update."
				details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID})
				r.client.Log.Warn(details)
				resp.Diagnostics.AddWarning(details, "")
			} else {
				changed = append(changed, "kms_id")
			}
		}
	}

	if plan.ReplicateKey != nil && state.ReplicateKey != nil {
		if plan.ReplicateKey.KeyID != state.ReplicateKey.KeyID {
			changed = append(changed, "replicate_key.key_id")
		}
	}

	// When primary_region is being *changed* (not already applied), multi_region_configuration
	// will change (the key flips PRIMARY<->REPLICA and the regions swap). The
	// nullOrStateForUnknownObject plan modifier already copied the old state value into the plan,
	// which would cause an "inconsistent result after apply" error. Override it here by marking it
	// unknown so Terraform accepts whatever value the provider returns after apply.
	// Only do this when the value is actually changing - if primary_region is already stored in
	// state with the same value as the plan, the promotion is already done and the plan is stable.
	planPR := plan.PrimaryRegion.ValueString()
	statePR := state.PrimaryRegion.ValueString()
	if !plan.PrimaryRegion.IsNull() && !plan.PrimaryRegion.IsUnknown() && planPR != "" && planPR != statePR {
		resp.Plan.SetAttribute(ctx, path.Root("multi_region_configuration"), types.ObjectUnknown(multiRegionConfigAttrTypes))
	}

	if len(changed) > 0 {
		resp.Diagnostics.AddError(
			"Attribute is immutable",
			fmt.Sprintf(
				"The following attributes cannot be modified after creation: %s. "+
					"Delete and recreate the resource to apply these changes.",
				strings.Join(changed, ", "),
			),
		)
	}
}

// ImportState imports an existing AWS BYOK key into Terraform state using its resource ID.
func (r *resourceAWSByokKey) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// createByokKey creates an EXTERNAL AWS key with no key material via the create-key API.
// The key will be in PendingImport state until material is imported separately.
// kmsID and commonAwsParams are pre-validated and pre-built by Create before calling this function.
func (r *resourceAWSByokKey) createByokKey(ctx context.Context, id string, kmsID string, plan *AWSByokKeyTFSDK, commonAwsParams CommonAWSParamsJSON, diags *diag.Diagnostics) string {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> createByokKey][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> createByokKey][" + id + "]")
	keyCreateParams := r.getByokKeyCreateParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams.KMS = kmsID
	awsParamFull := AWSKeyParamJSON{
		CommonAWSParamsJSON: commonAwsParams,
		Origin:              "EXTERNAL",
	}
	payload := CreateAWSKeyPayloadJSON{
		CommonAWSKeyCreatePayloadJSON: keyCreateParams,
		AWSParam:                      awsParamFull,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS BYOK key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY, payloadJSON)
	if err != nil {
		msg := "Error creating AWS BYOK key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	r.client.Log.Debug("[resource_aws_byok_key.go -> createByokKey][response:" + redactAWSResponse(response))
	return response
}

// uploadByokKey uploads CipherTrust Manager key material to an EXTERNAL AWS key via the upload-key API.
// kmsID and commonAwsParams are pre-validated and pre-built by Create before calling this function.
func (r *resourceAWSByokKey) uploadByokKey(ctx context.Context, id string, kmsID string, plan *AWSByokKeyTFSDK, commonAwsParams CommonAWSParamsJSON, diags *diag.Diagnostics) string {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> uploadByokKey][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> uploadByokKey][" + id + "]")
	keyCreateParams := r.getByokKeyCreateParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams.KMS = kmsID
	var uploadValidTo string
	if p := byokAwsParamFromObject(ctx, plan.AWSParam, diags); p != nil {
		uploadValidTo = p.ValidTo.ValueString()
	}
	uploadAWSParams := UploadAWSKeyParamJSON{
		CommonAWSParamsJSON: commonAwsParams,
		ValidTo:             uploadValidTo,
		Origin:              "EXTERNAL",
	}
	payload := UploadAWSKeyPayloadJSON{
		AWSParam:                      &uploadAWSParams,
		CommonAWSKeyCreatePayloadJSON: keyCreateParams,
		SourceKeyIdentifier:           plan.SourceKeyID.ValueString(),
		SourceKeyTier:                 plan.SourceKeyTier.ValueString(),
		KeyExpiration:                 uploadAWSParams.ValidTo != "",
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS BYOK key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, "api/v1/cckm/aws/upload-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS BYOK key, failed to upload key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	r.client.Log.Debug("[resource_aws_byok_key.go -> uploadByokKey][response:" + redactAWSResponse(response))
	return response
}

// replicateByokKey replicates a primary EXTERNAL multi-region key to a new region.
// AWS automatically replicates the key material from the primary key to the replica -
// no separate key-material import step is needed for BYOK replication.
// The initial replication API call is a hard error; all subsequent steps are warnings only.
// commonAwsParams is pre-built by Create before calling this function.
func (r *resourceAWSByokKey) replicateByokKey(ctx context.Context, id string, plan *AWSByokKeyTFSDK, commonAwsParams CommonAWSParamsJSON, diags *diag.Diagnostics) string {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_byok_key.go -> replicateByokKey][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_byok_key.go -> replicateByokKey][" + id + "]")
	if plan.ReplicateKey == nil {
		return ""
	}
	primaryKeyID := plan.ReplicateKey.KeyID.ValueString()
	mutexKey := fmt.Sprintf("aws-replicate-key-%s", primaryKeyID)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)
	return replicateKeyCommon(ctx, id, r.client, plan.ReplicateKey, plan.Region.ValueString(), "EXTERNAL", commonAwsParams, plan.KeyPolicy, diags)
}

// getByokKeyAwsParams builds the CommonAWSParamsJSON from an AWSByokKeyTFSDK plan.
// All AWS-specific input parameters are read from plan.AWSParam.
// BYOK keys are always EXTERNAL so Origin is not set here; it is set per-API-call.
func (r *resourceAWSByokKey) getByokKeyAwsParams(ctx context.Context, plan *AWSByokKeyTFSDK, diags *diag.Diagnostics) CommonAWSParamsJSON {
	var awsParams CommonAWSParamsJSON
	p := byokAwsParamFromObject(ctx, plan.AWSParam, diags)
	if p == nil {
		return awsParams
	}
	if len(p.Alias.Elements()) != 0 {
		aliases := make([]string, 0, len(p.Alias.Elements()))
		diags.Append(p.Alias.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return awsParams
		}
		awsParams.Alias = aliases[0]
	}
	if p.BypassPolicyLockoutSafetyCheck.ValueBool() {
		awsParams.BypassPolicyLockoutSafetyCheck = true
	}
	if v := p.CustomerMasterKeySpec.ValueString(); v != "" {
		awsParams.CustomerMasterKeySpec = v
	}
	if v := p.Description.ValueString(); v != "" {
		awsParams.Description = v
	}
	if v := p.KeyUsage.ValueString(); v != "" {
		awsParams.KeyUsage = v
	}
	if p.MultiRegion.ValueBool() {
		awsParams.MultiRegion = true
	}
	if len(p.Tags.Elements()) != 0 {
		tags := getTagsParam(ctx, p.Tags, diags)
		if diags.HasError() {
			return awsParams
		}
		awsParams.Tags = tags
	}
	if plan.KeyPolicy != nil && !plan.KeyPolicy.Policy.IsNull() && len(plan.KeyPolicy.Policy.ValueString()) != 0 {
		awsParams.Policy = json.RawMessage(plan.KeyPolicy.Policy.ValueString())
	}
	return awsParams
}

// getByokKeyCreateParams builds CommonAWSKeyCreatePayloadJSON from an AWSByokKeyTFSDK plan.
func (r *resourceAWSByokKey) getByokKeyCreateParams(ctx context.Context, plan *AWSByokKeyTFSDK, diags *diag.Diagnostics) CommonAWSKeyCreatePayloadJSON {
	var keyCreateParams CommonAWSKeyCreatePayloadJSON
	keyCreateParams.Region = plan.Region.ValueString()
	keyPolicyPlan := getKeyPolicyParams(ctx, plan.KeyPolicy, diags)
	if diags.HasError() {
		return keyCreateParams
	}
	keyCreateParams.ExternalAccounts = keyPolicyPlan.ExternalAccounts
	keyCreateParams.KeyAdmins = keyPolicyPlan.KeyAdmins
	keyCreateParams.KeyAdminsRoles = keyPolicyPlan.KeyAdminsRoles
	keyCreateParams.KeyUsers = keyPolicyPlan.KeyUsers
	keyCreateParams.KeyUsersRoles = keyPolicyPlan.KeyUsersRoles
	keyCreateParams.PolicyTemplate = keyPolicyPlan.PolicyTemplate
	return keyCreateParams
}

// setByokKeyState populates the full Terraform state for an AWS BYOK key from an API response JSON string.
func (r *resourceAWSByokKey) setByokKeyState(ctx context.Context, response string, state *AWSByokKeyTFSDK, diags *diag.Diagnostics) {
	// Always initialize rotation_history to a known empty list before any early-return
	// path below.
	emptyRotHistory, _ := types.ListValue(rotationHistoryByokSummaryElemType, []attr.Value{})
	state.RotationHistory = emptyRotHistory
	r.client.Log.Debug("[resource_aws_byok_key.go -> setByokKeyState][response:" + redactAWSResponse(response))
	setNativeAndByokKeyCommonState(ctx, r.client, response, &state.AWSNativeAndByokKeyCommonTFSDK, diags)
	if diags.HasError() {
		return
	}
	setPolicyTemplateTag(ctx, response, &state.PolicyTemplateTag, diags)
	existing := byokAwsParamFromObject(ctx, state.AWSParam, diags)
	_ = existing // reserved for future policy-comparison optimization
	state.MultiRegionConfiguration = setMultiRegionConfig(response, diags)
	// Only set source key fields from the API when no state value exists yet.
	// Once set (via upload-key or aws_key_material), preserve the existing state value
	if state.SourceKeyID.IsNull() || state.SourceKeyID.IsUnknown() || state.SourceKeyID.ValueString() == "" {
		state.SourceKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	}
	if state.SourceKeyTier.IsNull() || state.SourceKeyTier.IsUnknown() || state.SourceKeyTier.ValueString() == "" {
		state.SourceKeyTier = types.StringValue(gjson.Get(response, "key_source").String())
	}
	state.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	state.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	keyID := gjson.Get(response, "id").String()
	rotID := uuid.New().String()
	state.RotationHistory, _ = fetchRotationHistoryByokSummary(ctx, rotID, r.client, keyID)
	// If CurrentKeyMaterialID was not populated by the API,
	// fall back to the rotation history entry with key_material_state == "CURRENT".
	p := r.setByokKeyAwsParamState(ctx, response, diags)
	if p.CurrentKeyMaterialID.ValueString() == "" {
		for _, elem := range state.RotationHistory.Elements() {
			obj, ok := elem.(types.Object)
			if !ok {
				continue
			}
			attrs := obj.Attributes()
			matState, ok1 := attrs["key_material_state"].(types.String)
			matID, ok2 := attrs["key_material_id"].(types.String)
			if ok1 && ok2 && matState.ValueString() == "CURRENT" && matID.ValueString() != "" {
				p.CurrentKeyMaterialID = matID
				break
			}
		}
	}
	state.AWSParam = byokAwsParamToObject(ctx, p, diags)
}

// setByokKeyAwsParamState builds an AWSByokAwsParamTFSDK from the API response JSON.
// It captures the AWS-side metadata returned under the aws_param object so that users
// can reference the actual computed values (especially the computed policy JSON) via
// ciphertrust_aws_byok_key.<name>.aws_param.<field>.
func (r *resourceAWSByokKey) setByokKeyAwsParamState(ctx context.Context, response string, diags *diag.Diagnostics) *AWSByokAwsParamTFSDK {
	p := &AWSByokAwsParamTFSDK{}

	// Alias - strip the "alias/" prefix that AWS adds.
	var aliasValues []string
	for _, a := range gjson.Get(response, "aws_param.Alias").Array() {
		alias := a.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		aliasValues = append(aliasValues, alias)
	}
	aliasSet, d := types.SetValueFrom(ctx, types.StringType, aliasValues)
	diags.Append(d...)
	p.Alias = aliasSet

	p.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	p.CurrentKeyMaterialID = types.StringValue(gjson.Get(response, "aws_param.CurrentKeyMaterialId").String())
	p.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	p.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	p.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	p.Policy = types.StringValue(gjson.Get(response, "aws_param.Policy").String())
	p.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())

	// Computed-only fields from aws_param
	p.Arn = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	p.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	p.AWSKeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	p.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	p.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	p.EncryptionAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	p.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	p.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	p.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	p.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	p.MacAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.MacAlgorithmSpec").Array(), diags)
	p.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	p.ReplicaPolicy = types.StringValue(gjson.Get(response, "aws_param.ReplicaPolicy").String())
	p.ReplicaTags = types.StringValue(gjson.Get(response, "aws_param.ReplicaTags").Raw)

	// Tags - collect user-visible tags, excluding the internal policy-template tag.
	tagsMap := make(map[string]string)
	for _, tag := range gjson.Get(response, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != policyTemplateTagKey {
			tagsMap[tagKey] = tagValue
		}
	}
	tagsVal, d := types.MapValueFrom(ctx, types.StringType, tagsMap)
	diags.Append(d...)
	p.Tags = tagsVal

	return p
}
