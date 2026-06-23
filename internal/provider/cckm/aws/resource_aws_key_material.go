package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
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
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                   = &resourceAWSKeyMaterial{}
	_ resource.ResourceWithConfigure      = &resourceAWSKeyMaterial{}
	_ resource.ResourceWithImportState    = &resourceAWSKeyMaterial{}
	_ resource.ResourceWithModifyPlan     = &resourceAWSKeyMaterial{}
	_ resource.ResourceWithValidateConfig = &resourceAWSKeyMaterial{}
)

const (
	materialAlreadyExistsError      = "is already associated with KMS key"
	materialHasNotBeenImportedError = "has not been imported"
)

// NewResourceAWSKeyMaterial returns a new ciphertrust_aws_key_material resource instance.
func NewResourceAWSKeyMaterial() resource.Resource {
	return &resourceAWSKeyMaterial{}
}

type resourceAWSKeyMaterial struct {
	client *common.Client
}

func (r *resourceAWSKeyMaterial) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key_material"
}

func (r *resourceAWSKeyMaterial) ValidateConfig(ctx context.Context, _ resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	common.ValidateCMOnly(ctx, r.client, "ciphertrust_aws_key_material", resp)
}

func (r *resourceAWSKeyMaterial) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSKeyMaterial) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage key material for an existing AWS EXTERNAL (BYOK) KMS key through CipherTrust Manager.\n\n" +
			"This resource imports key material from CipherTrust Manager source keys into an AWS EXTERNAL key and manages the complete key material lifecycle, including rotation, recovery, and deletion.\n\n" +
			"Multi-region key support requires CipherTrust Manager 2.23 or later. " +
			"Single-region key support requires CipherTrust Manager 2.21 or later.\n\n" +
			"Key features:\n\n" +
			"* Import key material into AWS EXTERNAL symmetric keys.\n" +
			"* Rotate to new key material by adding additional `key_material` entries.\n" +
			"* Automatically recover key material that enters an intermediate state due to failed or out-of-band operations.\n" +
			"* Support multi-region symmetric keys, automatically keeping replica key material synchronized with the primary key.\n" +
			"* Adopt key material that was created outside Terraform by adding a matching `key_material` entry.\n\n" +
			"Terraform actively reconciles all configured key material with the live CipherTrust Manager rotation history. " +
			"If configured material enters one of the following states, Terraform automatically attempts recovery during the next apply:\n\n" +
			"* `PENDING_IMPORT`\n" +
			"* `PENDING_ROTATION`\n" +
			"* `PENDING_MULTI_REGION_IMPORT_AND_ROTATION`\n\n" +
			"For multi-region symmetric keys, key material is managed only on the primary key. " +
			"Replica keys automatically receive and maintain the same material as the primary.\n\n" +
			"Existing material may be adopted into Terraform management by adding an entry with matching input values.\n\n" +
			"When a configured `key_material` entry is removed from Terraform configuration, Terraform immediately deletes the corresponding material from the AWS key and any replica keys. " +
			"This is a destructive operation that may affect the key's material state and should be performed with care.\n\n" +
			"To delete all key material from the AWS key, provide an empty set: `key_material = []`.\n\n" +
			"To avoid drift and unexpected behaviour, all key material lifecycle operations should be performed through Terraform whenever possible.",
		Attributes: map[string]schema.Attribute{
			"aws_key_id": schema.StringAttribute{
				Required:    true,
				Description: "The AWS key ID of the target EXTERNAL symmetric key.",
			},
			"key_material": schema.SetNestedAttribute{
				Optional: true,
				Description: "Key material to manage on the AWS EXTERNAL key.\n\n" +
					"For multi-region symmetric keys, `key_material` may only be configured on the primary key. " +
					"Exactly one entry must be supplied during resource creation. Additional entries may be added later to perform key material rotations. " +
					"Each entry is uniquely identified by its `source_key_identifier`. " +
					"Changing `valid_to` or `key_material_description` updates the corresponding material metadata in CipherTrust Manager. " +
					"Identical entries are de-duplicated by Terraform's set semantics before the configuration is applied.\n\n",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						// Required attributes
						"source_key_identifier": schema.StringAttribute{
							Required:    true,
							Description: "CipherTrust Manager ID of the source key.",
						},
						"source_key_tier": schema.StringAttribute{
							Required:    true,
							Description: "Source of the key material. Current option is 'local' implying a CipherTrust Manager key.",
						},
						// Optional attributes
						"valid_to": schema.StringAttribute{
							Optional: true,
							Description: "(Updatable) Date of key material expiry in UTC time in RFC3339 format. For example, 2027-07-03T14:24:00Z. " +
								"Removing this field from the plan will clear the expiry date and set the expiration model to KEY_MATERIAL_DOES_NOT_EXPIRE. " +
								"If key material expires and enters PendingImport state, all future key-material operations (rotation, new imports) " +
								"are blocked until the entry is either removed from the set or valid_to is updated to a future date and re-applied.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(awsValidToRegEx), awsValidToFormatMsg,
								),
							},
						},
						"key_material_description": schema.StringAttribute{
							Optional:    true,
							Description: "(Updatable) Description for the key material. Removing this field from the plan will clear the description from the material.",
						},
					},
				},
			},
			// Read-only attributes
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager ID of the key.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"kms_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "CipherTrust Manager ID of the KMS to create the key in.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"kms_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the AWS KMS resource.",
			},
			"rotation_history": rotationHistoryByokFullSchemaAttribute(),
		},
	}
}

// Create imports key material into an existing AWS EXTERNAL (BYOK) key and saves Terraform state.
// It validates that the target key is EXTERNAL with SYMMETRIC_DEFAULT encryption, then delegates
// all material operations to updateKeyMaterial (passing an empty state set). The following cases
// are handled by updateKeyMaterial:
//   - No rotation history: first import via import-material (NEW_KEY_MATERIAL).
//   - History entry in PENDING_MULTI_REGION_IMPORT_AND_ROTATION: repair replica keys then activate.
//   - History entry in PENDING_ROTATION: activate the pending material via rotate-material.
//   - History entry in CURRENT or NON_CURRENT: silently adopted with no API call.
func (r *resourceAWSKeyMaterial) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> Create]["+id+"]")
	var plan AWSKeyMaterialTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve the CipherTrust Manager resource ID for the target AWS key.
	// The aws_key_id is the AWS-side identifier; we must list CM records to find the CM UUID.
	cmKeyID := findCMKeyIDByAWSKeyID(ctx, id, r.client, plan.AWSKeyID.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Fetch the full key record from CipherTrust Manager.
	keyJSON, err := r.client.GetById(ctx, id, cmKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key from CipherTrust Manager during key material create."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "cm_key_id": cmKeyID, "aws_key_id": plan.AWSKeyID.ValueString()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	// Validate that the target AWS key is an EXTERNAL (BYOK) key with SYMMETRIC_DEFAULT encryption.
	// Only EXTERNAL origin keys support key material import, and only SYMMETRIC_DEFAULT
	// keys are supported by this resource.
	keyOrigin := gjson.Get(keyJSON, "aws_param.Origin").String()
	if keyOrigin != "EXTERNAL" {
		resp.Diagnostics.AddError(
			"Target AWS key is not an EXTERNAL key",
			fmt.Sprintf("The ciphertrust_aws_key_material resource only supports AWS keys with Origin=EXTERNAL (BYOK). "+
				"Key %q has Origin=%q. Use ciphertrust_aws_key to manage non-EXTERNAL keys.",
				plan.AWSKeyID.ValueString(), keyOrigin,
			),
		)
		return
	}
	keyType := gjson.Get(keyJSON, "key_type").String()
	if keyType != "symmetric" {
		resp.Diagnostics.AddError(
			"Target AWS key is not a symmetric key",
			fmt.Sprintf("The ciphertrust_aws_key_material resource only supports symmetric EXTERNAL keys. "+
				"Key %q has key_type=%q.",
				plan.AWSKeyID.ValueString(), keyType,
			),
		)
		return
	}

	// Delegate all material operations to updateKeyMaterial, passing an empty state set
	// (no prior state on create). updateKeyMaterial handles every case:
	//   - History empty + plan entry not in history -> import-material (NEW_KEY_MATERIAL)
	//   - History has PENDING_MULTI_REGION_IMPORT_AND_ROTATION -> repair replicas
	//   - History has PENDING_ROTATION -> activate via rotate-material (empty body)
	//   - History has CURRENT/NON_CURRENT -> silently adopted (no API call)
	// Using types.Set{} (zero value) for stateKeyMaterial gives IsNull()==true, so
	// updateKeyMaterial treats prior state as empty: no removedMats, no metadataUpdates.
	r.updateKeyMaterial(ctx, id, cmKeyID, &plan, types.Set{}, keyJSON, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// No errors after this - set full state from a fresh API fetch.
	var diags diag.Diagnostics
	r.setAwsKeyMaterialState(ctx, cmKeyID, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceAWSKeyMaterial) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	var state AWSKeyMaterialTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Resolve the CipherTrust Manager resource ID from the AWS key ID stored in state.
	cmKeyID := findCMKeyIDByAWSKeyID(ctx, id, r.client, state.AWSKeyID.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Fetch the key record to verify it still exists, with proper 404 handling.
	// If the KMS is gone, preserveState is true we keep the existing state unchanged.
	_, preserveState := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), cmKeyID, "reading", &resp.Diagnostics)
	if preserveState {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Populate all computed state fields from a fresh API fetch.
	r.setAwsKeyMaterialState(ctx, cmKeyID, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update applies plan changes to an AWS BYOK key's key material.
// The update sequence is:
//  1. Resolve the CM key UUID from the plan's aws_key_id.
//  2. Verify the key exists in CM.
//  3. Guard: no more than one new key_material entry may be added per apply.
//  4. Refresh the key from AWS and wait for rotation history to reflect the refresh,
//     so that all subsequent material operations work from AWS-current state.
//  5. Apply material operations (phases 0-2 of updateKeyMaterial).
//  6. Read final state back from CM.
func (r *resourceAWSKeyMaterial) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> Update]["+id+"]")
	var (
		plan  AWSKeyMaterialTFSDK
		state AWSKeyMaterialTFSDK
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 1: resolve the CM key UUID from the AWS key ID in the plan.
	// This mirrors the Create path and handles any edge case where state.ID drifted.
	cmKeyID := findCMKeyIDByAWSKeyID(ctx, id, r.client, plan.AWSKeyID.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 2: verify the key still exists in CM and obtain its current JSON.
	// preserveState is true when the KMS is gone - we should keep existing state.
	keyJSON, preserveState := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), cmKeyID, "updating", &resp.Diagnostics)
	if preserveState {
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 3: refresh the key from AWS and wait for rotation history to reflect the
	// refresh. This ensures the provider operates on AWS-current data rather than
	// potentially stale CCKM-cached state before the material operation phases.
	var planMats []AWSByokImportMaterialTFSDK
	if !plan.KeyMaterial.IsNull() && !plan.KeyMaterial.IsUnknown() {
		resp.Diagnostics.Append(plan.KeyMaterial.ElementsAs(ctx, &planMats, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	knownSrcIDs := make([]string, 0, len(planMats))
	for _, m := range planMats {
		if v := m.SourceKeyID.ValueString(); v != "" {
			knownSrcIDs = append(knownSrcIDs, v)
		}
	}
	RefreshKeyAndWait(ctx, id, r.client, cmKeyID, keyJSON, knownSrcIDs, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 5: apply key material operations
	r.updateKeyMaterial(ctx, id, cmKeyID, &plan, state.KeyMaterial, keyJSON, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 6: read final state from a fresh CM API fetch.
	r.setAwsKeyMaterialState(ctx, cmKeyID, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *resourceAWSKeyMaterial) Delete(_ context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// Delete is a no-op

}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource.
// On create (no prior state), it also errors if more than one import_material entry is provided,
// because only the first entry is used by the upload-key API call.
func (r *resourceAWSKeyMaterial) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		// Destroy - nothing to validate.
		return
	}
	// Create path: state is null.
	if req.State.Raw.IsNull() {
		var createPlan AWSKeyMaterialTFSDK
		resp.Diagnostics.Append(req.Plan.Get(ctx, &createPlan)...)
		if resp.Diagnostics.HasError() {
			return
		}
		if !createPlan.KeyMaterial.IsNull() && !createPlan.KeyMaterial.IsUnknown() {
			var mats []AWSByokImportMaterialTFSDK
			resp.Diagnostics.Append(createPlan.KeyMaterial.ElementsAs(ctx, &mats, false)...)
			if !resp.Diagnostics.HasError() {
				if len(mats) == 0 {
					resp.Diagnostics.AddError(
						"At least one key_material entry is required on create",
						"Provide exactly one key_material block when creating this resource.",
					)
					return
				}
			}
		}
		return
	}
	var plan, state AWSKeyMaterialTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Update-path validation: decode plan and state key_material sets once so that all
	// update-time checks can use them without re-decoding.
	var updatePlanMats []AWSByokImportMaterialTFSDK
	var updateStateMats []AWSByokImportMaterialTFSDK
	if !plan.KeyMaterial.IsNull() && !plan.KeyMaterial.IsUnknown() {
		if pd := plan.KeyMaterial.ElementsAs(ctx, &updatePlanMats, false); pd.HasError() {
			updatePlanMats = nil
		}
	}
	if !state.KeyMaterial.IsNull() && !state.KeyMaterial.IsUnknown() {
		if sd := state.KeyMaterial.ElementsAs(ctx, &updateStateMats, false); sd.HasError() {
			updateStateMats = nil
		}
	}

	// Check for duplicate source_key_identifier values in the plan (update path).
	if len(updatePlanMats) > 0 {
		seen := make(map[string]bool, len(updatePlanMats))
		for _, m := range updatePlanMats {
			srcID := m.SourceKeyID.ValueString()
			if srcID == "" {
				continue // unknown at plan time - cannot check for duplicates
			}
			if _, dup := seen[srcID]; dup {
				resp.Diagnostics.AddError(
					"Duplicate source_key_identifier in key_material",
					fmt.Sprintf("source_key_identifier %q appears more than once in key_material. "+
						"Each key_material entry must have a unique source_key_identifier.", srcID),
				)
				return
			}
			seen[srcID] = true
		}
	}

	// markAttrsUnknown marks computed attributes that change when a material operation
	// runs (re-import, rotation completion, delete-material) as Unknown, causing Terraform
	// to call Update on the next apply even when only Computed attributes differ.
	markAttrsUnknown := func() {
		resp.Diagnostics.Append(
			resp.Plan.SetAttribute(ctx, path.Root("rotation_history"), types.ListUnknown(rotationHistoryByokFullElemType))...,
		)
	}

	// Trigger 1: removed key_material entries.
	// If any entry present in state.KeyMaterial is absent from plan.KeyMaterial, mark
	// rotation_history as Unknown so Terraform calls Update to delete material.
	if !state.KeyMaterial.IsNull() && !state.KeyMaterial.IsUnknown() &&
		!plan.KeyMaterial.IsNull() && !plan.KeyMaterial.IsUnknown() {
		var stateMats []AWSByokImportMaterialTFSDK
		var planMats []AWSByokImportMaterialTFSDK
		if sd := state.KeyMaterial.ElementsAs(ctx, &stateMats, false); !sd.HasError() {
			if pd := plan.KeyMaterial.ElementsAs(ctx, &planMats, false); !pd.HasError() {
				planSrcIDs := make(map[string]struct{}, len(planMats))
				for _, m := range planMats {
					if v := m.SourceKeyID.ValueString(); v != "" {
						planSrcIDs[v] = struct{}{}
					}
				}
				for _, sm := range stateMats {
					if _, inPlan := planSrcIDs[sm.SourceKeyID.ValueString()]; !inPlan {
						markAttrsUnknown()
						break
					}
				}
			}
		}
	}

	// Trigger 2: pending-state detection.
	// If any rotation history entry in state is PENDING_IMPORT, PENDING_ROTATION, or
	// PENDING_MULTI_REGION_IMPORT_AND_ROTATION for a source_key_identifier that is present
	// in plan.KeyMaterial, mark computed attributes as Unknown so Terraform calls Update.
	if !state.RotationHistory.IsNull() && !state.RotationHistory.IsUnknown() &&
		!plan.KeyMaterial.IsNull() && !plan.KeyMaterial.IsUnknown() {
		var histEntries []RotationHistoryEntryFullTFSDK
		if hd := state.RotationHistory.ElementsAs(ctx, &histEntries, false); !hd.HasError() {
			var planMats []AWSByokImportMaterialTFSDK
			if pd := plan.KeyMaterial.ElementsAs(ctx, &planMats, false); !pd.HasError() {
				planSrcIDs := make(map[string]struct{}, len(planMats))
				for _, m := range planMats {
					if v := m.SourceKeyID.ValueString(); v != "" {
						planSrcIDs[v] = struct{}{}
					}
				}
				for _, e := range histEntries {
					srcID := e.SourceKeyIdentifier.ValueString()
					if _, ok := planSrcIDs[srcID]; !ok {
						continue
					}
					if e.AWSParams.ImportState.ValueString() == "PENDING_IMPORT" ||
						e.AWSParams.KeyMaterialState.ValueString() == "PENDING_ROTATION" ||
						e.AWSParams.KeyMaterialState.ValueString() == "PENDING_MULTI_REGION_IMPORT_AND_ROTATION" {
						// Mark computed attributes as Unknown so Terraform calls Update on
						// the next apply to repair the pending state.
						markAttrsUnknown()
						break
					}
				}
			}
		}
	}

}

// ImportState imports an existing AWS BYOK key into Terraform state using its resource ID.
func (r *resourceAWSKeyMaterial) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setAwsKeyMaterialState fetches the AWS key record from CipherTrust Manager by cmKeyID and
// populates the Terraform state for the aws_key_material resource. cmKeyID must be the CM UUID
// (not the AWS key ID). All Computed fields are set from the API response; the caller is
// responsible for preserving Required/Optional input fields (aws_key_id, key_material) that are
// not returned by the key API.
func (r *resourceAWSKeyMaterial) setAwsKeyMaterialState(ctx context.Context, cmKeyID string, state *AWSKeyMaterialTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, "[resource_aws_key_material.go -> setAwsKeyMaterialState] cmKeyID: "+cmKeyID)
	if cmKeyID == "" {
		diags.AddError("setAwsKeyMaterialState called with empty cmKeyID", "Internal error: cmKeyID must not be empty.")
		return
	}
	opID := uuid.New().String()
	keyJSON, err := r.client.GetById(ctx, opID, cmKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key from CipherTrust Manager in setAwsKeyMaterialState."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "cm_key_id": cmKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	state.ID = types.StringValue(cmKeyID)
	state.KMSID = types.StringValue(gjson.Get(keyJSON, "kms_id").String())
	state.KMSName = types.StringValue(gjson.Get(keyJSON, "kms").String())
	// Initialize rotation_history to a known empty list before any early-return path.
	// If fetchFullRotationHistory fails - we return early, Terraform rejects the state
	// with "Provider returned invalid result object after apply" when the attribute is Unknown.
	emptyRotHistory, _ := types.ListValue(rotationHistoryByokFullElemType, []attr.Value{})
	state.RotationHistory = emptyRotHistory
	rotHistory, _ := fetchRotationHistoryByokFull(ctx, opID, r.client, cmKeyID)
	state.RotationHistory = rotHistory
}

// updateKeyMaterial is the orchestrator for key material operations during both Create and Update.
// It classifies plan entries against live rotation history, then runs each repair
// and import phase in order. After each phase, history is re-fetched and all
// classification slices are rebuilt from the fresh data so that subsequent phases
// always operate on current AWS state.
// On Create, stateKeyMaterial is passed as types.Set{} (null), so stateMats is empty:
// no removedMats and no metadataUpdates are produced.
func (r *resourceAWSKeyMaterial) updateKeyMaterial(ctx context.Context, id string, keyID string, plan *AWSKeyMaterialTFSDK, stateKeyMaterial types.Set, keyJSON string, diags *diag.Diagnostics) {

	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> updateKeyMaterial]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> updateKeyMaterial]["+id+"]")

	// Check for duplicate source_key_identifier values.
	if !plan.KeyMaterial.IsNull() && !plan.KeyMaterial.IsUnknown() {
		var mats []AWSByokImportMaterialTFSDK
		diags.Append(plan.KeyMaterial.ElementsAs(ctx, &mats, false)...)
		if !diags.HasError() {
			seen := make(map[string]bool, len(mats))
			for _, m := range mats {
				srcID := m.SourceKeyID.ValueString()
				if srcID == "" {
					continue // unknown at plan time - cannot check for duplicates
				}
				if _, dup := seen[srcID]; dup {
					diags.AddError(
						"Duplicate source_key_identifier in key_material",
						fmt.Sprintf("source_key_identifier %q appears more than once in key_material. "+
							"Each key_material entry must have a unique source_key_identifier.", srcID),
					)
					return
				}
				seen[srcID] = true
			}
		}
	}

	// Step 1: decode plan materials.
	var planMats []AWSByokImportMaterialTFSDK
	diags.Append(plan.KeyMaterial.ElementsAs(ctx, &planMats, false)...)
	if diags.HasError() {
		return
	}

	// Step 2: decode state materials.
	var stateMats []AWSByokImportMaterialTFSDK
	if !stateKeyMaterial.IsNull() && !stateKeyMaterial.IsUnknown() {
		diags.Append(stateKeyMaterial.ElementsAs(ctx, &stateMats, false)...)
		if diags.HasError() {
			return
		}
	}

	// Build set of plan source key IDs to identify removed entries.
	planSrcIDs := make(map[string]struct{}, len(planMats))
	for _, m := range planMats {
		if v := m.SourceKeyID.ValueString(); v != "" {
			planSrcIDs[v] = struct{}{}
		}
	}

	// Step 3: history state - rebuilt by refetchHistory and consumed by classify.
	historyBySourceKey := make(map[string]RotationHistoryEntryFullTFSDK)

	// Classification slices - reset and refilled by classify after each repair phase.
	var (
		pendingMRRepairs       []AWSByokImportMaterialTFSDK // key_material_state == PENDING_MULTI_REGION_IMPORT_AND_ROTATION
		pendingImportRepairs   []AWSByokImportMaterialTFSDK // import_state == PENDING_IMPORT
		pendingRotationRepairs []AWSByokImportMaterialTFSDK // key_material_state == PENDING_ROTATION
		metadataUpdates        []AWSByokImportMaterialTFSDK // in history, not pending, valid_to or desc changed
		newCandidates          []AWSByokImportMaterialTFSDK // not in history at all
		removed                []AWSByokImportMaterialTFSDK // in state but not in plan
	)

	// fetchHistoryAndClassify re-fetches rotation history, rebuilds historyBySourceKey,
	// and then reclassifies all plan entries into the appropriate phase slices.
	// It must be called before the first phase and after every phase that modifies
	// key material state, so that each subsequent phase operates on fresh AWS data.
	fetchHistoryAndClassify := func() {
		rotList, _ := fetchRotationHistoryByokFull(ctx, id, r.client, keyID)
		var historyEntries []RotationHistoryEntryFullTFSDK
		diags.Append(rotList.ElementsAs(ctx, &historyEntries, false)...)
		historyBySourceKey = make(map[string]RotationHistoryEntryFullTFSDK, len(historyEntries))
		for _, e := range historyEntries {
			if v := e.SourceKeyIdentifier.ValueString(); v != "" {
				historyBySourceKey[v] = e
			}
		}
		if diags.HasError() {
			return
		}

		pendingMRRepairs = pendingMRRepairs[:0]
		pendingImportRepairs = pendingImportRepairs[:0]
		pendingRotationRepairs = pendingRotationRepairs[:0]
		metadataUpdates = metadataUpdates[:0]
		newCandidates = newCandidates[:0]
		removed = removed[:0]

		// removedMats: present in state but absent from plan.
		for _, sm := range stateMats {
			if _, inPlan := planSrcIDs[sm.SourceKeyID.ValueString()]; !inPlan {
				removed = append(removed, sm)
			}
		}
		// Classify each plan entry by its current state in live rotation history.
		for _, mat := range planMats {
			srcID := mat.SourceKeyID.ValueString()
			entry, inHistory := historyBySourceKey[srcID]
			if !inHistory {
				newCandidates = append(newCandidates, mat)
				continue
			}
			matState := entry.AWSParams.KeyMaterialState.ValueString()
			impState := entry.AWSParams.ImportState.ValueString()
			switch {
			case matState == "PENDING_MULTI_REGION_IMPORT_AND_ROTATION":
				pendingMRRepairs = append(pendingMRRepairs, mat)
			case impState == "PENDING_IMPORT":
				pendingImportRepairs = append(pendingImportRepairs, mat)
			case matState == "PENDING_ROTATION":
				pendingRotationRepairs = append(pendingRotationRepairs, mat)
			default:
				// Check whether valid_to or description differ from the current live history
				// entry. Comparing against live data (not prior Terraform state) means the
				// check is self-correcting: after a successful update and re-fetch the entry
				// will match the plan and no further update is queued.
				if mat.ValidTo.ValueString() != entry.AWSParams.ValidTo.ValueString() ||
					mat.KeyMaterialDescription.ValueString() != entry.AWSParams.KeyMaterialDescription.ValueString() {
					metadataUpdates = append(metadataUpdates, mat)
				}
			}
		}
		tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> fetchHistoryAndClassify] pendingMR: %d pendingImport: %d pendingRotation: %d new: %d removed: %d keyID: %s",
			len(pendingMRRepairs), len(pendingImportRepairs), len(pendingRotationRepairs),
			len(newCandidates), len(removed), keyID))
	}

	// Initial history fetch and classification.
	fetchHistoryAndClassify()
	if diags.HasError() {
		return
	}

	// Sanity check: at most one new entry per apply.
	if len(newCandidates) > 1 {
		diags.AddError(
			"Too many new key_material entries",
			fmt.Sprintf("Only one new key_material entry may be added per apply. "+
				"Got %d new entries - add entries one at a time.",
				len(newCandidates),
			),
		)
		return
	}

	maxRetries := 5

	// Due to asynchronicity of operations it's necessary to continue to process operations until resolved.
	for retry := 0; retry < maxRetries; retry++ {

		// Initial history fetch and classification.
		fetchHistoryAndClassify()
		if diags.HasError() {
			return
		}

		numOperations := len(pendingMRRepairs) + len(pendingImportRepairs) + len(pendingRotationRepairs) +
			len(newCandidates) + len(removed) + len(metadataUpdates)
		tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> updateKeyMaterial] retry: %d num operations: %d", retry, numOperations))
		if numOperations == 0 {
			tflog.Debug(ctx, "[resource_aws_key_material.go -> updateKeyMaterial] 0 operations to process.")
			break
		}

		// Repair PENDING_MULTI_REGION_IMPORT_AND_ROTATION entries.
		// For each affected entry, import the key material to all replica keys that are
		// missing it, then wait for the primary to reach PENDING_ROTATION state.
		// rotate-material is NOT called here - handled subsequently after a fresh classify.
		if len(pendingMRRepairs) > 0 {
			r.repairPendingMultiRegionImportAndRotation(ctx, id, keyID, keyJSON, pendingMRRepairs, historyBySourceKey, diags)
			if diags.HasError() {
				return
			}
			fetchHistoryAndClassify()
			if diags.HasError() {
				return
			}
		}

		// Repair PENDING_IMPORT entries.
		// Re-importing key material for a PENDING_IMPORT entry moves import_state from
		// PENDING_IMPORT to Imported. key_material_state is unaffected (stays CURRENT or
		// NON-CURRENT). History is re-fetched and re-classified after all repairs so that
		// A later step picks up any entries that are now in PENDING_ROTATION.
		if len(pendingImportRepairs) > 0 {
			r.repairPendingImport(ctx, id, keyID, pendingImportRepairs, diags)
			if diags.HasError() {
				return
			}
			fetchHistoryAndClassify()
			if diags.HasError() {
				return
			}
		}

		// Resume PENDING_ROTATION entries.
		// For each entry whose key_material_state is PENDING_ROTATION, call rotate-material
		// with an empty body to activate the pending material. The material moves to either
		// CURRENT or NON-CURRENT. History is re-fetched and re-classified after all resumes.
		if len(pendingRotationRepairs) > 0 {
			r.repairKeyMaterialRotations(ctx, id, keyID, pendingRotationRepairs, keyJSON, diags)
			if diags.HasError() {
				return
			}
			fetchHistoryAndClassify()
			if diags.HasError() {
				return
			}
		}

		// Update metadata on existing entries whose valid_to or description changed.
		// The key material does not enter a pending state during this operation, but we
		// re-fetch history and re-classify after the loop so later steps operate on
		// fresh data (e.g. updated valid_to/expiration_model values are visible).
		if len(metadataUpdates) > 0 {
			for _, mat := range metadataUpdates {
				r.updateExistingKeyMaterialMetadata(ctx, id, keyID, mat, diags)
				if diags.HasError() {
					return
				}
			}
			fetchHistoryAndClassify()
			if diags.HasError() {
				return
			}
		}

		// Import new material.
		// A plan entry is a "new candidate" when it is not present in live rotation history.
		// Two sub-cases:
		//   a) historyBySourceKey is completely empty: the key is in PendingImport state (all
		//      material was wiped out-of-band, e.g. a PENDING_ROTATION record deleted directly
		//      in AWS). Use import-material with NEW_KEY_MATERIAL - rotate-material fails with
		//      KMSInvalidStateException on a key with no existing material.
		//   b) historyBySourceKey is non-empty: the key has existing material we are
		//      adding a new rotation entry. Use rotate-material as normal.
		// After the import/rotation, re-fetch history and re-classify so later steps operates on
		// fresh data.
		if len(newCandidates) > 0 {
			mat := newCandidates[0]
			srcID := mat.SourceKeyID.ValueString()
			if len(historyBySourceKey) == 0 {
				// No rotation history at all - key is back in PendingImport state.
				tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> updateKeyMaterial] historyBySourceKey is empty, using import-material (NEW_KEY_MATERIAL). srcID: %s keyID: %s", srcID, keyID))
				ImportByokKeyMaterial(ctx, id, r.client, keyID, srcID,
					mat.SourceKeyTier.ValueString(),
					mat.ValidTo.ValueString(),
					mat.KeyMaterialDescription.ValueString(),
					"NEW_KEY_MATERIAL", diags)
				if diags.HasError() {
					return
				}
				waitForRotationHistoryRecord(ctx, id, r.client, keyID, srcID, mat.SourceKeyTier.ValueString(), diags)
				waitForMaterialStateResolved(ctx, id, r.client, keyID, srcID, "import_state", "PENDING_IMPORT", "", diags)
				if gjson.Get(keyJSON, "aws_param.MultiRegion").Bool() {
					waitForReplicasMaterialCurrent(ctx, id, r.client, keyID, srcID, keyJSON, diags)
				}
			} else {
				tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> updateKeyMaterial] historyBySourceKey has %d entries, rotate to new material.", len(historyBySourceKey)))
				rotateToNewMaterial(ctx, id, r.client, keyID, srcID, mat.SourceKeyTier.ValueString(),
					mat.ValidTo.ValueString(), mat.KeyMaterialDescription.ValueString(), keyJSON, diags)
			}
			if diags.HasError() {
				return
			}
			fetchHistoryAndClassify()
			if diags.HasError() {
				return
			}
		}

		// Delete removed key material entries.
		// This runs regardless of whether any other phases ran - removals are always actioned.
		if len(removed) > 0 {
			r.deleteRemovedKeyMaterial(ctx, id, keyID, removed, historyBySourceKey, keyJSON, diags)
		}

		// Refresh the primary key so CM re-checks AWS.
		filters := url.Values{
			"skip":  []string{"0"},
			"limit": []string{"-1"},
			"sort":  []string{"-RotationDate"},
		}
		endpoint := "api/v1/cckm/aws/keys/" + keyID + "/rotations"
		rotationsJSON, err := r.client.ListWithFilters(ctx, id, endpoint, filters)
		if err == nil {
			resources := gjson.Get(rotationsJSON, "resources").Array()
			var sourceKeyIDs []string
			for _, item := range resources {
				if item.Get("source_key_identifier").String() != "" {
					sourceKeyIDs = append(sourceKeyIDs, item.Get("source_key_identifier").String())
				}
			}
			primaryKeyJSON, getErr := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
			if getErr == nil {
				RefreshKeyAndWait(ctx, id, r.client, keyID, primaryKeyJSON, sourceKeyIDs, diags)
			}
		}
	}
}

// updateExistingKeyMaterialMetadata updates the valid_to and/or key_material_description
// on an existing key material entry by calling import-material with EXISTING_KEY_MATERIAL.
// The key material does not enter a pending state during this operation, so no polling
// is needed after the call.
func (r *resourceAWSKeyMaterial) updateExistingKeyMaterialMetadata(ctx context.Context, id string, keyID string, mat AWSByokImportMaterialTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> updateExistingKeyMaterialMetadata]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> updateExistingKeyMaterialMetadata]["+id+"]")

	srcID := mat.SourceKeyID.ValueString()
	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> updateExistingKeyMaterialMetadata] srcID: %s keyID: %s validTo: %s desc: %s",
		srcID, keyID, mat.ValidTo.ValueString(), mat.KeyMaterialDescription.ValueString()))

	ImportByokKeyMaterial(ctx, id, r.client, keyID, srcID, mat.SourceKeyTier.ValueString(),
		mat.ValidTo.ValueString(), mat.KeyMaterialDescription.ValueString(),
		"EXISTING_KEY_MATERIAL", diags)
}

// repairPendingMultiRegionImportAndRotation repairs all primary key entries that are stuck in
// PENDING_MULTI_REGION_IMPORT_AND_ROTATION state. This happens when the background AWS
// task that distributes key material to replica keys failed or timed out after the primary
// already received the material.
//
// For each entry in pendingMRRepairs the function:
//  1. Resolves the source key ID and tier from historyBySourceKey.
//  2. Calls repairMultiRegionReplicas to import the existing key material to every replica
//     key that is still missing it (or is in PENDING_IMPORT state).
//  3. Waits for the primary key's key_material_state to reach PENDING_ROTATION. AWS
//     transitions the primary to PENDING_ROTATION automatically once all replicas have
//     confirmed receipt of the material.
//
// primaryKeyJSON is the full CM key record for keyID, already fetched by the caller.
// pendingMRRepairs contains only entries whose key_material_state is
// PENDING_MULTI_REGION_IMPORT_AND_ROTATION; the caller (updateKeyMaterial) is responsible
// for that pre-filtering.
func (r *resourceAWSKeyMaterial) repairPendingMultiRegionImportAndRotation(ctx context.Context, id string, primaryKeyID string, primaryKeyJSON string, pendingMRRepairs []AWSByokImportMaterialTFSDK, historyBySourceKey map[string]RotationHistoryEntryFullTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> repairPendingMultiRegionImportAndRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> repairPendingMultiRegionImportAndRotation]["+id+"]")

	for _, mat := range pendingMRRepairs {
		srcID := mat.SourceKeyID.ValueString()
		entry := historyBySourceKey[srcID]
		replicaSourceKeyID := entry.SourceKeyIdentifier.ValueString()
		replicaSourceKeyTier := entry.SourceKeyTier.ValueString()

		tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairPendingMultiRegionImportAndRotation] importing material to replicas keyID: %s sourceKeyID: %s", primaryKeyID, replicaSourceKeyID))

		// Step 1: import the existing key material to all replicas that are missing it.
		// repairMultiRegionReplicas also calls refresh on the primary after all imports so
		// that CM re-checks AWS and can transition the primary's state.
		r.repairMultiRegionReplicas(ctx, id, primaryKeyID, replicaSourceKeyID, replicaSourceKeyTier, mat.ValidTo.ValueString(), primaryKeyJSON, diags)

		// do I need to refresh !

		// Step 2: wait for the primary to arrive at PENDING_ROTATION. Once all replicas
		// confirm receipt of the material, AWS moves the primary from
		// PENDING_MULTI_REGION_IMPORT_AND_ROTATION to PENDING_ROTATION.
		// Seems a refresh is required here
		// waitForMaterialStateResolved(ctx, id, r.client, primaryKeyID, replicaSourceKeyID, "key_material_state", "PENDING_MULTI_REGION_IMPORT_AND_ROTATION", "PENDING_ROTATION", diags)
	}
}

// repairPendingImport repairs all key material entries that are stuck in PENDING_IMPORT
// state. This happens when key material was deleted out-of-band (e.g. by a manual
// delete-material call or by expiry), leaving the entry with no active material bytes.
//
// Re-importing a PENDING_IMPORT entry moves import_state from PENDING_IMPORT to Imported.
// key_material_state is unaffected by the re-import - it stays CURRENT or NON-CURRENT as
// it was before the material was deleted. History is re-fetched and re-classified by the
// caller after this function returns so that subsequent phases see the updated state.
//
// For each entry in pendingImportRepairs the function:
//  1. Validates that valid_to (if set) is not already in the past. An expired valid_to means
//     the material cannot be re-imported without first updating the expiry date; an error is
//     added and the entry is skipped (the loop continues to report all problems at once).
//  2. Calls ImportByokKeyMaterial with EXISTING_KEY_MATERIAL to re-upload the key material.
//     An import failure is a hard error for that entry; the loop continues to attempt remaining
//     entries, and the caller checks diags.HasError() after the call returns.
//  3. Waits for import_state to leave PENDING_IMPORT (i.e. arrive at Imported). A poll
//     timeout is a warning only because the import call itself succeeded.
func (r *resourceAWSKeyMaterial) repairPendingImport(ctx context.Context, id string, keyID string, pendingImportRepairs []AWSByokImportMaterialTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> repairPendingImport]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> repairPendingImport]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairPendingImport] keyID: %s", keyID))

	for _, mat := range pendingImportRepairs {
		srcID := mat.SourceKeyID.ValueString()

		// Step 1: reject entries whose valid_to has already passed.
		// AWS will reject the import anyway, and it signals a user action is required
		// (update valid_to to a future date) before the material can be re-imported.
		validTo := mat.ValidTo.ValueString()
		if validTo != "" {
			t, parseErr := time.Parse(time.RFC3339, validTo)
			if parseErr != nil || t.Before(time.Now().UTC()) {
				msg := fmt.Sprintf("Key material %s/%s is in PENDING_IMPORT and the configured valid_to date has already passed. "+
					"Update valid_to to a future date before Terraform can re-import this material.",
					srcID, mat.SourceKeyTier.ValueString(),
				)
				tflog.Error(ctx, msg)
				diags.AddWarning(msg, "")
				continue
			}
		}

		// Step 2: re-import the key material with EXISTING_KEY_MATERIAL.
		var importDiags diag.Diagnostics
		ImportByokKeyMaterial(ctx, id, r.client, keyID, srcID, mat.SourceKeyTier.ValueString(), validTo, mat.KeyMaterialDescription.ValueString(), "EXISTING_KEY_MATERIAL", &importDiags)
		diags.Append(importDiags...)
		if importDiags.HasError() {
			tflog.Error(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairPendingImport] ImportByokKeyMaterial failed sourceKeyID: %s keyID: %s", srcID, keyID))
			continue
		}

		// Step 3: wait for import_state to leave PENDING_IMPORT (move to Imported).
		// key_material_state is not changed by a re-import - it stays CURRENT or NON-CURRENT.
		// A timeout is a warning only - the import call already completed successfully.
		waitForMaterialStateResolved(ctx, id, r.client, keyID, srcID, "import_state", "PENDING_IMPORT", "", diags)
	}
}

// repairKeyMaterialRotations resumes all key material entries that are stuck in
// PENDING_ROTATION state. This state means the key material has been imported to the key
// (and to all replicas for multi-region keys) but the final rotate-material call that
// activates the material was never completed (e.g. due to a network interruption).
//
// For each entry in pendingRotationRepairs the function:
//  1. Calls POST rotate-material with an empty body to activate the pending material.
//     This is a hard error that stops the loop immediately on failure - a rotate-material
//     failure leaves the key in the same PENDING_ROTATION state it started in.
//  2. Waits for key_material_state to leave PENDING_ROTATION. The material arrives at
//     either CURRENT (if it is the newest rotation) or NON-CURRENT (if a newer rotation
//     was subsequently applied). A timeout is a warning only.
//  3. For multi-region primary keys, also waits for all replica keys to reach CURRENT
//     state. A timeout is a warning only.
//
// keyJSON is the full CM key record for keyID, used to detect the multi-region case.
func (r *resourceAWSKeyMaterial) repairKeyMaterialRotations(ctx context.Context, id string, keyID string, pendingRotationRepairs []AWSByokImportMaterialTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> repairKeyMaterialRotations]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> repairKeyMaterialRotations]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairKeyMaterialRotations] keyID: %s", keyID))

	isMRPrimary := gjson.Get(keyJSON, "aws_param.MultiRegion").Bool()

	for _, mat := range pendingRotationRepairs {
		srcID := mat.SourceKeyID.ValueString()
		tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairKeyMaterialRotations] rotating keyID: %s to sourceKeyID: %s", keyID, srcID))

		// Step 1: call rotate-material with an empty body to activate the pending material.
		// Hard error - stop the loop immediately if this fails.
		_, rotErr := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotate-material", []byte("{}"))
		if rotErr != nil {
			msg := "Error resuming PENDING_ROTATION for AWS BYOK key material."
			details := utils.ApiError(msg, map[string]interface{}{"error": rotErr.Error(), "key_id": keyID, "source_key_id": srcID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Info(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairKeyMaterialRotations] SUCCESS keyID: %s sourceKeyID: %s", keyID, srcID))

		// Step 2: wait for key_material_state to leave PENDING_ROTATION.
		// The material arrives at CURRENT or NON-CURRENT depending on whether a newer
		// rotation has since been applied. Timeout is a warning only.
		waitForMaterialStateResolved(ctx, id, r.client, keyID, srcID, "key_material_state", "PENDING_ROTATION", "", diags)

		// Step 3: for multi-region primary keys, also wait for all replicas to reach CURRENT.
		if isMRPrimary {
			waitForReplicasMaterialCurrent(ctx, id, r.client, keyID, srcID, keyJSON, diags)
		}
	}
}

// repairMultiRegionReplicas imports key material to each replica key that is missing it.
// This is called when the primary key's rotation history entry is in
// PENDING_MULTI_REGION_IMPORT_AND_ROTATION state. This means the background task that
// imports material to replicas failed or timed out after material was already imported to
// the primary key.
//
// primaryKeyJSON is the full JSON of the primary key (already fetched by the caller).
// sourceKeyID and sourceKeyTier identify the CM source key that was imported to the primary.
// validTo and keyMaterialDescription are used for any replica imports but are optional.
//
// For each replica in the multi-region configuration:
//   - The replica is looked up in CipherTrust Manager by AWS key ID and region.
//   - If the replica is not registered in CM, a warning is added and the replica is skipped.
//   - The replica's rotation history is checked. If the source key material is already
//     present and not in PENDING_IMPORT state, the replica is skipped.
//   - Otherwise import-material is called on the replica with EXISTING_KEY_MATERIAL.
//   - If the API returns "key material already exists", it is treated as a warning (no-op).
//   - After a successful import call the function waits for the replica's import state
//     to leave PENDING_IMPORT before proceeding to the next replica.
//
// Errors from individual replica imports are added to diags and the loop continues so the
// caller receives a full picture of which replicas need attention.
func (r *resourceAWSKeyMaterial) repairMultiRegionReplicas(ctx context.Context, id string, primaryKeyID string, sourceKeyID string, sourceKeyTier string, validTo string, primaryKeyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> repairMultiRegionReplicas]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> repairMultiRegionReplicas]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairMultiRegionReplicas] keyID: %s sourceKeyID: %s", primaryKeyID, sourceKeyID))

	replicaKeysResult := gjson.Get(primaryKeyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys")
	if !replicaKeysResult.Exists() || len(replicaKeysResult.Array()) == 0 {
		tflog.Debug(ctx, fmt.Sprintf("repairMultiRegionReplicas: no replica keys found in multi-region config for keyID: %s", primaryKeyID))
		return
	}

	for _, replicaResult := range replicaKeysResult.Array() {
		replicaARN := replicaResult.Get("Arn").String()
		replicaRegion := replicaResult.Get("Region").String()
		if replicaARN == "" || replicaRegion == "" {
			msg := "Skipping replica repair: replica entry missing Arn or Region."
			details := utils.ApiError(msg, map[string]interface{}{"arn": replicaARN, "primary_key_id": primaryKeyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			continue
		}

		// Extract the AWS key ID from the ARN (last path segment after "/").
		// ARN format: arn:aws:kms:<region>:<account>:key/<key-id>
		arnParts := strings.Split(replicaARN, ":")
		if len(arnParts) < 6 {
			msg := "Skipping replica repair: unexpected replica ARN format."
			details := utils.ApiError(msg, map[string]interface{}{"arn": replicaARN, "primary_key_id": primaryKeyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			continue
		}
		kidParts := strings.Split(arnParts[5], "/")
		if len(kidParts) < 2 {
			msg := "Skipping replica repair: could not extract key ID from replica ARN."
			details := utils.ApiError(msg, map[string]interface{}{"arn": replicaARN, "primary_key_id": primaryKeyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			continue
		}
		awsKeyID := kidParts[len(kidParts)-1]

		// Look up the replica key in CipherTrust Manager.
		filters := url.Values{}
		filters.Add("keyid", awsKeyID)
		filters.Add("region", replicaRegion)
		listJSON, listErr := r.client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
		if listErr != nil {
			msg := "Skipping replica repair: error looking up replica key in CipherTrust Manager."
			details := utils.ApiError(msg, map[string]interface{}{"error": listErr.Error(), "aws_key_id": awsKeyID, "region": replicaRegion})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			continue
		}
		total := gjson.Get(listJSON, "total").Int()
		if total == 0 {
			msg := "Skipping replica repair: replica key not found in CipherTrust Manager. Import the replica key into CM first."
			details := utils.ApiError(msg, map[string]interface{}{"aws_key_id": awsKeyID, "region": replicaRegion})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			continue
		}
		replicaCMKeyID := gjson.Get(listJSON, "resources.0.id").String()
		if replicaCMKeyID == "" {
			msg := "Skipping replica repair: could not determine CipherTrust Manager key ID for replica."
			details := utils.ApiError(msg, map[string]interface{}{"aws_key_id": awsKeyID, "region": replicaRegion})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			continue
		}

		tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairMultiRegionReplicas] replica region: %s replicaKeyID: %s", replicaRegion, replicaCMKeyID))

		// Check the replica's rotation history to see whether material already exists.
		replicaHistory, _ := fetchRotationHistoryByokFull(ctx, id, r.client, replicaCMKeyID)
		var replicaEntries []RotationHistoryEntryFullTFSDK
		if hd := replicaHistory.ElementsAs(ctx, &replicaEntries, false); !hd.HasError() {
			for ri, entry := range replicaEntries {
				tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairMultiRegionReplicas] sourceKeyID: %s history[%d] "+
					"importState: %s materialState: %v", entry.SourceKeyIdentifier.ValueString(), ri,
					entry.AWSParams.ImportState.ValueString(), entry.AWSParams.KeyMaterialState.ValueString()))
			}
			alreadyImported := false
			for _, entry := range replicaEntries {
				if entry.SourceKeyIdentifier.ValueString() == sourceKeyID && entry.AWSParams.ImportState.ValueString() != "PENDING_IMPORT" {
					// This source key material is already present and not pending import - skip.
					alreadyImported = true
					break
				}
			}
			if alreadyImported {
				tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairMultiRegionReplicas] replicaCMKeyID: %s already has material for sourceKeyID: %s (not PENDING_IMPORT), skipping", replicaCMKeyID, sourceKeyID))
				continue
			}
			tflog.Warn(ctx, fmt.Sprintf("[resource_aws_key_material.go -> repairMultiRegionReplicas] replicaCMKeyID: %s material for sourceKeyID: %s not found or in PENDING_IMPORT - will import", replicaCMKeyID, sourceKeyID))
		}

		// Import the material to the replica using EXISTING_KEY_MATERIAL.
		// Replica multi-region keys do not accept key_material_description -
		// AWS returns a 400 ValidationException if it is supplied. Omit it.
		// valid_to may be specified independently per replica and is passed through.
		// No per-replica wait: if the import-material call returns no error, the command
		// has been received by AWS and will be acted on asynchronously. We refresh the
		// primary key after all replicas are processed to trigger CM to re-check AWS state.
		importType := "EXISTING_KEY_MATERIAL"
		var importDiags diag.Diagnostics
		ImportByokKeyMaterial(ctx, id, r.client, replicaCMKeyID, sourceKeyID, sourceKeyTier, validTo, "", importType, &importDiags)
		if importDiags.HasError() {
			diags.Append(importDiags...)
			return
		}
	}
	time.Sleep(time.Duration(10*len(replicaKeysResult.Array())) * time.Second)
}

// ImportByokKeyMaterial calls the import-material API to load key material into an EXTERNAL AWS key.
// importType must be either "NEW_KEY_MATERIAL" (first-ever import on a PendingImport key with no
// rotation history) or "EXISTING_KEY_MATERIAL" (re-importing previously deleted material).
// sourceKeyID and sourceKeyTier identify the CipherTrust Manager source key.
// validTo is the expiry date string (RFC3339); pass an empty string when no expiry is configured.
// keyMaterialDescription is optional; pass an empty string to omit it from the request.
func ImportByokKeyMaterial(ctx context.Context, id string, client *common.Client, keyID string, sourceKeyID string, sourceKeyTier string, validTo string, keyMaterialDescription string, importType string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> ImportByokKeyMaterial]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> ImportByokKeyMaterial]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> ImportByokKeyMaterial] keyID: %s sourceKeyID: %s", keyID, sourceKeyID))

	payload := AWSKeyImportMaterialJSON{
		SourceKeyID:   sourceKeyID,
		SourceKeyTier: sourceKeyTier,
		KeyExpiration: validTo != "",
		ValidTo:       validTo,
		ImportType:    &importType,
	}
	if keyMaterialDescription != "" {
		payload.KeyMaterialDescription = &keyMaterialDescription
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error importing key material for AWS BYOK key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/import-material", payloadJSON)
	if err != nil {
		if !strings.Contains(err.Error(), materialAlreadyExistsError) {
			tflog.Error(ctx, fmt.Sprintf("[resource_aws_key_material.go -> ImportByokKeyMaterial] FAILED keyID: %s error: %s", keyID, err.Error()))
			msg := "Error importing key material for AWS BYOK key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Warn(ctx, fmt.Sprintf("[resource_aws_key_material.go -> ImportByokKeyMaterial] Key material already exists. sourceKeyID: %s error: %s", sourceKeyID, err.Error()))
		return
	}
	tflog.Info(ctx, fmt.Sprintf("[resource_aws_key_material.go -> ImportByokKeyMaterial] SUCCESS keyID: %s response: %s", keyID, redactAWSResponse(response)))
}

// rotateToNewMaterial calls rotate-material on cmKeyID to import new key material and
// rotate the key to it, then waits for the primary key material to reach CURRENT state.
// For multi-region PRIMARY keys it also waits for all replica keys to reach CURRENT state.
//
// srcID and srcTier identify the CipherTrust Manager source key. When both are provided,
// the CCKM rotate-material API imports the material from that source key then activates it
// (two AWS API calls). Both must be non-empty when adding new material.
// validTo is the expiry date (RFC3339); pass an empty string for no expiry (key_expiration=false).
// keyMaterialDescription is optional; pass an empty string to omit it from the request.
// keyJSON is the full CM key record for cmKeyID, used to detect the multi-region case
// without an extra API call.
//
// A rotate-material API failure is added as a hard error (rotate-material did not run, so
// the key material state is unchanged and the caller should not save state). Poll timeouts
// from the wait functions are added as warnings only - rotate-material was already called
// and work is in progress asynchronously.
// If rotate-material fails with replica pending import cannot rotate error we need to attempt to fix up
// Return true to re-calculate material states and try again
func rotateToNewMaterial(ctx context.Context, id string, client *common.Client, cmKeyID string, srcID string, srcTier string, validTo string, keyMaterialDescription string, keyJSON string, diags *diag.Diagnostics) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> rotateToNewMaterial]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> rotateToNewMaterial]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> rotateToNewMaterial] primaryKeyID: %s sourceKeyID: %s", cmKeyID, srcID))

	rotPayload := RotateMaterialPayloadJSON{
		SourceKeyID:            srcID,
		SourceKeyTier:          srcTier,
		ValidTo:                validTo,
		KeyMaterialDescription: keyMaterialDescription,
		KeyExpiration:          validTo != "",
	}
	payloadBytes, marshalErr := json.Marshal(rotPayload)
	if marshalErr != nil {
		msg := "Error building rotate-material payload for AWS BYOK key."
		details := utils.ApiError(msg, map[string]interface{}{"error": marshalErr.Error(), "key_id": cmKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	_, rotErr := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+cmKeyID+"/rotate-material", payloadBytes)
	if rotErr != nil {
		msg := "Error calling rotate-material on AWS BYOK key."
		details := utils.ApiError(msg, map[string]interface{}{"error": rotErr.Error(), "key_id": cmKeyID, "source_key_id": srcID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}

	tflog.Info(ctx, fmt.Sprintf("[resource_aws_key_material.go -> rotateToNewMaterial] SUCCESS keyID: %s sourceKeyID: %s", cmKeyID, srcID))

	// Wait for the rotation history record to appear (CCKM creates it during the import step,
	// before the rotate-material overall_status reaches "success").
	waitForRotationHistoryRecord(ctx, id, client, cmKeyID, srcID, srcTier, diags)

	// Wait for the rotate-material background task to complete.
	retryOperation := waitForMaterialRotation(ctx, id, client, cmKeyID, diags)
	if retryOperation {
		tflog.Debug(ctx, "[resource_aws_key_material.go -> rotateToNewMaterial] waiting for material rotation failed with soft error, continuing.")
		// Known errors - re-calculate material states and try again - probably should refresh here.
		return
	}
	if diags.HasError() {
		return
	}

	// Wait for the (primary) key material to reach CURRENT state.
	resolved := waitForMaterialStateResolved(ctx, id, client, cmKeyID, srcID, "key_material_state", "", "CURRENT", diags)

	// For multi-region keys, also wait for all replicas to reach CURRENT state.
	if resolved && gjson.Get(keyJSON, "aws_param.MultiRegion").Bool() {
		waitForReplicasMaterialCurrent(ctx, id, client, cmKeyID, srcID, keyJSON, diags)
	}

	return
}

// deleteRemovedKeyMaterial calls delete-material on the primary key and, for multi-region
// PRIMARY keys, on every registered replica key for each entry in removedMats.
//
// Only entries whose key_material_state is "CURRENT" are deleted; non-CURRENT entries
// (NON-CURRENT, PENDING_IMPORT, etc.) are skipped because AWS only allows deleting the
// currently active material and will reject the call otherwise.
//
// For each removed entry:
//  1. Look up the history entry by source key ID. If not found, the material was never
//     imported (or history has already been cleared) - log info and skip.
//  2. Check key_material_state. If not "CURRENT", log info and skip (no-op).
//  3. Build the list of CM key IDs to call delete-material on:
//     - Always the primary keyID.
//     - If the key is a multi-region PRIMARY (aws_param.MultiRegion == true and
//     MultiRegionConfiguration.MultiRegionKeyType == "PRIMARY"), walk the ReplicaKeys
//     array, extract the AWS key ID from each replica ARN, look up the CM UUID via
//     ListWithFilters, and add it to the list. Replica lookup failures are warnings
//     only - the delete still proceeds on the other keys.
//  4. POST /v1/cckm/aws/keys/{cmID}/delete-material with an empty body for each CM key.
//     Failure on any individual key is a hard error added to diags; the loop continues
//     so the user sees all failures at once.
//
// No polling is required after a successful delete-material call - the API is synchronous.
func (r *resourceAWSKeyMaterial) deleteRemovedKeyMaterial(
	ctx context.Context, id string, keyID string,
	removedMats []AWSByokImportMaterialTFSDK,
	historyBySourceKey map[string]RotationHistoryEntryFullTFSDK,
	keyJSON string,
	diags *diag.Diagnostics,
) {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_material.go -> deleteRemovedKeyMaterial]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_material.go -> deleteRemovedKeyMaterial]["+id+"]")

	tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> deleteRemovedKeyMaterial] keyID: %s", keyID))

	// Determine whether this is a multi-region primary key once, outside the per-mat loop.
	isMRPrimary := gjson.Get(keyJSON, "aws_param.MultiRegion").Bool() &&
		gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String() == "PRIMARY"

	for _, mat := range removedMats {
		srcID := mat.SourceKeyID.ValueString()

		// Step 1: look up the history entry.
		entry, inHistory := historyBySourceKey[srcID]
		if !inHistory {
			tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> deleteRemovedKeyMaterial] sourceKeyID: %s not in rotation history - skipping delete", srcID))
			continue
		}

		// Step 2: build the list of CM key IDs to delete from.
		// delete-material is called regardless of key_material_state:
		//   - CURRENT / NON-CURRENT: material exists and is deleted.
		//   - PENDING_IMPORT: material bytes are already gone; the API treats this as a no-op.
		//   - PENDING_ROTATION / PENDING_MULTI_REGION_IMPORT_AND_ROTATION: material exists and is deleted.
		// The only skip is when the entry is not in rotation history at all (handled above).
		matState := entry.AWSParams.KeyMaterialState.ValueString()
		tflog.Debug(ctx, fmt.Sprintf("[resource_aws_key_material.go -> deleteRemovedKeyMaterial] sourceKeyID: %s key_material_state: %s", srcID, matState))

		// Step 3: build the list of CM key IDs to delete from, together with the
		// key_material_id to use for each key. Passing the key_material_id ensures
		// we delete exactly the specific material entry we intend to remove, rather
		// than the default behaviour of deleting the CURRENT (latest) material.
		cmKeyIDs := []string{keyID}
		// cmIDToKeyMatID maps each CM key ID to the key_material_id to include in
		// the delete-material request body. An empty string means fall back to {}.
		cmIDToKeyMatID := map[string]string{
			keyID: entry.AWSParams.KeyMaterialID.ValueString(),
		}

		if isMRPrimary {
			replicaKeysResult := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys")
			for _, replicaResult := range replicaKeysResult.Array() {
				replicaARN := replicaResult.Get("Arn").String()
				replicaRegion := replicaResult.Get("Region").String()
				if replicaARN == "" || replicaRegion == "" {
					tflog.Warn(ctx, fmt.Sprintf("[resource_aws_key_material.go -> deleteRemovedKeyMaterial] replica entry missing Arn or Region for sourceKeyID: %s - skipping replica", srcID))
					continue
				}

				// Extract AWS key ID from the ARN (last segment after ":key/").
				// ARN format: arn:aws:kms:<region>:<account>:key/<key-id>
				arnParts := strings.Split(replicaARN, ":")
				if len(arnParts) < 6 {
					msg := "Skipping replica delete: unexpected replica ARN format."
					details := utils.ApiError(msg, map[string]interface{}{"arn": replicaARN, "source_key_id": srcID})
					tflog.Warn(ctx, details)
					diags.AddWarning(details, "")
					continue
				}
				kidParts := strings.Split(arnParts[5], "/")
				if len(kidParts) < 2 {
					msg := "Skipping replica delete: could not extract key ID from replica ARN."
					details := utils.ApiError(msg, map[string]interface{}{"arn": replicaARN, "source_key_id": srcID})
					tflog.Warn(ctx, details)
					diags.AddWarning(details, "")
					continue
				}
				awsKeyID := kidParts[len(kidParts)-1]

				// Look up the replica key in CipherTrust Manager.
				filters := url.Values{}
				filters.Add("keyid", awsKeyID)
				filters.Add("region", replicaRegion)
				listJSON, listErr := r.client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
				if listErr != nil {
					msg := "Skipping replica delete: error looking up replica key in CipherTrust Manager."
					details := utils.ApiError(msg, map[string]interface{}{"error": listErr.Error(), "aws_key_id": awsKeyID, "region": replicaRegion})
					tflog.Warn(ctx, details)
					diags.AddWarning(details, "")
					continue
				}
				if gjson.Get(listJSON, "total").Int() == 0 {
					msg := "Skipping replica delete: replica key not found in CipherTrust Manager."
					details := utils.ApiError(msg, map[string]interface{}{"aws_key_id": awsKeyID, "region": replicaRegion})
					tflog.Warn(ctx, details)
					diags.AddWarning(details, "")
					continue
				}
				replicaCMKeyID := gjson.Get(listJSON, "resources.0.id").String()
				if replicaCMKeyID == "" {
					msg := "Skipping replica delete: could not determine CipherTrust Manager key ID for replica."
					details := utils.ApiError(msg, map[string]interface{}{"aws_key_id": awsKeyID, "region": replicaRegion})
					tflog.Warn(ctx, details)
					diags.AddWarning(details, "")
					continue
				}
				// Look up the replica's key_material_id for this source key so that the
				// delete-material call targets the specific material entry, not the latest.
				replicaKeyMatID := ""
				replicaHist, _ := fetchRotationHistoryByokFull(ctx, id, r.client, replicaCMKeyID)
				var replicaEntries []RotationHistoryEntryFullTFSDK
				if hd := replicaHist.ElementsAs(ctx, &replicaEntries, false); !hd.HasError() {
					for _, re := range replicaEntries {
						if re.SourceKeyIdentifier.ValueString() == srcID {
							replicaKeyMatID = re.AWSParams.KeyMaterialID.ValueString()
							break
						}
					}
				}
				cmKeyIDs = append(cmKeyIDs, replicaCMKeyID)
				cmIDToKeyMatID[replicaCMKeyID] = replicaKeyMatID
			}
		}

		// Step 4: call delete-material on each CM key ID, passing the specific
		// key_material_id so that the API deletes exactly the intended material entry
		// rather than defaulting to the CURRENT (latest) material.
		for _, cmID := range cmKeyIDs {
			keyMatID := cmIDToKeyMatID[cmID]
			var deletePayload []byte
			if keyMatID != "" {
				p, mErr := json.Marshal(map[string]string{"key_material_id": keyMatID})
				if mErr == nil {
					deletePayload = p
				}
			}
			if deletePayload == nil {
				deletePayload = []byte("{}")
			}

			_, delErr := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+cmID+"/delete-material", deletePayload)
			if delErr != nil {
				msg := "Error deleting key material from AWS BYOK key."
				details := utils.ApiError(msg, map[string]interface{}{"error": delErr.Error(), "cm_key_id": cmID, "source_key_id": srcID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				// Continue to attempt remaining keys - caller sees all failures.
			} else {
				tflog.Info(ctx, fmt.Sprintf("[resource_aws_key_material.go -> deleteRemovedKeyMaterial] SUCCESS keyID: %s sourceKeyID: %s", cmID, srcID))
			}
		}
	}
}
