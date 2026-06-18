package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource               = &resourceAWSKeyImportMaterial{}
	_ resource.ResourceWithConfigure  = &resourceAWSKeyImportMaterial{}
	_ resource.ResourceWithModifyPlan = &resourceAWSKeyImportMaterial{}
)

func NewResourceAWSKeyImportMaterial() resource.Resource {
	return &resourceAWSKeyImportMaterial{}
}

type resourceAWSKeyImportMaterial struct {
	client *common.Client
}

func (r *resourceAWSKeyImportMaterial) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key_import_material"
}

func (r *resourceAWSKeyImportMaterial) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSKeyImportMaterial) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to import or re-import key material to an AWS EXTERNAL key. " +
			"If the KMS is not found during refresh, the resource is preserved in state until the KMS is recovered. " +
			"If the AWS key is not found but the KMS is reachable, an error is returned. " +
			"Use 'terraform state rm' to remove this resource from state if the key no longer exists.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS region and AWS key identifier separated by a backslash.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Description: "AWS region of the key.",
			},
			"customer_master_key_spec": schema.StringAttribute{
				Computed:    true,
				Description: "Key specification",
			},
			"key_usage": schema.StringAttribute{
				Computed:    true,
				Description: "Specifies the intended use of the key.",
			},
			"kms": schema.StringAttribute{
				Computed:    true,
				Description: "Name or ID of the KMS to be used to create the key.",
			},
			"multi_region": schema.BoolAttribute{
				Computed:    true,
				Description: "Creates or identifies a multi-region key.",
			},
			"origin": schema.StringAttribute{
				Computed:    true,
				Description: "AWS source of the key material.",
			},
			"arn": schema.StringAttribute{
				Computed:    true,
				Description: "The Amazon Resource Name (ARN) of the key.",
			},
			"aws_account_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS account ID.",
			},
			"aws_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS key ID.",
			},
			"cloud_name": schema.StringAttribute{
				Computed:    true,
				Description: "AWS cloud.",
			},
			"created_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key was created.",
			},
			"deletion_date": schema.StringAttribute{
				Computed:    true,
				Description: "Date the key is scheduled for deletion.",
			},
			"encryption_algorithms": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Encryption algorithms of an asymmetric key",
			},
			"expiration_model": schema.StringAttribute{
				Computed:    true,
				Description: "Expiration model.",
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
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager Key ID of the AWS Key.",
			},
			"key_manager": schema.StringAttribute{
				Computed:    true,
				Description: "Key manager.",
			},
			"key_material_origin": schema.StringAttribute{
				Computed:    true,
				Description: "Key material origin.",
			},
			"key_rotation_enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True if rotation is enabled in AWS for this key.",
			},
			"key_source": schema.StringAttribute{
				Computed:    true,
				Description: "Source of the key.",
			},
			"key_state": schema.StringAttribute{
				Computed:    true,
				Description: "Key state.",
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
			"kms_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the KMS",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
			},
			"local_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key identifier of the external key.",
			},
			"local_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key name of the external key.",
			},
			"multi_region_key_type": schema.StringAttribute{
				Computed:    true,
				Description: "Indicates if the key is the primary key or a replica key.",
			},
			"multi_region_primary_key": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"multi_region_replica_keys": schema.ListAttribute{
				Computed: true,
				ElementType: types.MapType{
					ElemType: types.StringType,
				},
			},
			"next_rotation_date": schema.StringAttribute{
				Computed:    true,
				Description: "Date when auto-rotation will happen next.",
			},
			"rotated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Time when this key was rotated by a scheduled rotation job.",
			},
			"rotated_from": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID from of the key this key has been rotated from by a scheduled rotation job.",
			},
			"rotated_to": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Manager key ID which this key has been rotated too by a scheduled rotation job.",
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
			"valid_to": schema.StringAttribute{
				Computed:    true,
				Description: "Date of key material expiry.",
			},
		},
		Blocks: map[string]schema.Block{
			"import_key_material": schema.ListNestedBlock{
				Description: "(Updatable) Key material parameters. Changing any field in this block triggers a re-import of key material.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"import_type": schema.StringAttribute{
							Optional: true,
							Description: "(Updatable) Options: NEW_KEY_MATERIAL, EXISTING_KEY_MATERIAL. " +
								"This parameter is optional and only usable with symmetric keys. If no key material has " +
								"ever been imported into the AWS key, and this parameter is omitted, the default is NEW_KEY_MATERIAL. " +
								"Otherwise, the default is EXISTING_KEY_MATERIAL.",
						},
						"key_expiration": schema.BoolAttribute{
							Optional:    true,
							Description: "(Updatable) Enable key material expiration. Default is false.",
						},
						"key_material_description": schema.StringAttribute{
							Optional:    true,
							Description: "(Updatable) Specify the description for the key material.",
						},
						"key_material_id": schema.StringAttribute{
							Optional:    true,
							Description: "(Updatable) Specify the key material id. This is applicable for re-import to symmetric keys only.",
						},
						"source_key_identifier": schema.StringAttribute{
							Optional: true,
							Description: "(Updatable) This parameter is optional only if the source_key_tier is local and the key is a 256 bits AES key. " +
								"If key material is being re-imported, AWS only allows re-importing the same key material therefore it's necessary " +
								"to provide the source key identifier of the same source key which was imported previously.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Default:     stringdefault.StaticString("local"),
							Description: "(Updatable) Source of the key material. Current option is 'local' implying a CipherTrust Manager key. Default is 'local'.",
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "(Updatable) Date of key material expiry in UTC time in RFC3339 format. For example, 2027-07-03T14:24:00Z.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(awsValidToRegEx), awsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
		},
	}
}

// Create imports key material into an existing EXTERNAL AWS key and sets Terraform state.
func (r *resourceAWSKeyImportMaterial) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_import_material.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_import_material.go -> Create]["+id+"]")
	var (
		plan     AWSKeyForImportMaterialTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response = r.importKeyMaterial(ctx, id, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	keyID := plan.KeyID.ValueString()
	var err error
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
	}
	var diags diag.Diagnostics
	r.setKeyState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Debug(ctx, "[resource_aws_key_import_material.go -> Create][response:"+redactAWSResponse(response))
}

// Read refreshes Terraform state for an import-material resource by reading the current AWS key from
// CipherTrust Manager.
// Returns an error if the KMS is not reachable
func (r *resourceAWSKeyImportMaterial) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_import_material.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_import_material.go -> Read]["+id+"]")
	var state AWSKeyForImportMaterialTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, preserveState := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), keyID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if preserveState {
		// KMS not found - key is hidden. Keep existing state unchanged until KMS is recovered.
		resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
		return
	}
	readKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if readKeyState == "PendingDeletion" || readKeyState == "PendingReplicaDeletion" {
		msg := "AWS key is pending deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	r.setKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading AWS key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update re-imports key material into the EXTERNAL AWS key when the import_key_material block changes.
// Returns an error if the KMS is not reachable
func (r *resourceAWSKeyImportMaterial) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_import_material.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_import_material.go -> Update]["+id+"]")
	var (
		plan  AWSKeyForImportMaterialTFSDK
		state AWSKeyForImportMaterialTFSDK
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	plan.KeyID = types.StringValue(keyID)
	response, _ := getAwsKey(ctx, id, r.client, state.KMSID.ValueString(), keyID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	updateKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if updateKeyState == "PendingDeletion" || updateKeyState == "PendingReplicaDeletion" {
		msg := "AWS key is pending deletion, removing from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	response = r.importKeyMaterial(ctx, id, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.setKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS key, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "[resource_aws_key_import_material.go -> Update][response:"+redactAWSResponse(response))
}

// Delete is a no-op; the import material resource does not delete the underlying AWS key on destroy.
func (r *resourceAWSKeyImportMaterial) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceAWSKeyImportMaterial) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state AWSKeyForImportMaterialTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string

	if plan.KeyID != state.KeyID {
		changed = append(changed, "key_id")
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

// setKeyState populates the full Terraform state for an import-material resource from an API response JSON string.
func (r *resourceAWSKeyImportMaterial) setKeyState(ctx context.Context, response string, state *AWSKeyForImportMaterialTFSDK, diags *diag.Diagnostics) {
	tflog.Debug(ctx, "[resource_aws_key_import_material.go -> setKeyState][response:"+redactAWSResponse(response))
	r.setImportMaterialState(ctx, response, &state.AWSKeyCommonImportMaterialTFSDK, diags)
	state.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	state.MultiRegionKeyType = types.StringValue(gjson.Get(response, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String())
	setMultiRegionConfiguration(ctx, response, &state.MultiRegionPrimaryKey, &state.MultiRegionReplicaKeys, diags)
	state.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
}

// importKeyMaterial sends the import-material request to CipherTrust Manager for an EXTERNAL AWS key.
func (r *resourceAWSKeyImportMaterial) importKeyMaterial(ctx context.Context, id string, plan *AWSKeyForImportMaterialTFSDK, diags *diag.Diagnostics) string {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_import_material.go -> importKeyMaterial]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_import_material.go -> importKeyMaterial]["+id+"]")
	var importMaterialPlan AWSKeyImportMaterialTFSDK
	for _, v := range plan.ImportKeyMaterial.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, v, &importMaterialPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	payload := AWSKeyImportMaterialJSON{}

	if !importMaterialPlan.ImportType.IsUnknown() && !importMaterialPlan.ImportType.IsNull() {
		payload.ImportType = importMaterialPlan.ImportType.ValueStringPointer()
	}
	if !importMaterialPlan.KeyMaterialDescription.IsUnknown() && !importMaterialPlan.KeyMaterialDescription.IsNull() {
		payload.KeyMaterialDescription = importMaterialPlan.KeyMaterialDescription.ValueStringPointer()
	}
	if !importMaterialPlan.KeyMaterialID.IsUnknown() && !importMaterialPlan.KeyMaterialID.IsNull() {
		payload.KeyMaterialID = importMaterialPlan.KeyMaterialID.ValueStringPointer()
	}
	if !importMaterialPlan.SourceKeyTier.IsUnknown() && !importMaterialPlan.SourceKeyTier.IsNull() {
		payload.SourceKeyTier = importMaterialPlan.SourceKeyTier.ValueString()
	}
	if !importMaterialPlan.SourceKeyID.IsUnknown() && !importMaterialPlan.SourceKeyID.IsNull() {
		payload.SourceKeyID = importMaterialPlan.SourceKeyID.ValueString()
	}
	if !importMaterialPlan.KeyExpiration.IsUnknown() && !importMaterialPlan.KeyExpiration.IsNull() {
		payload.KeyExpiration = importMaterialPlan.KeyExpiration.ValueBool()
	}
	if !importMaterialPlan.ValidTo.IsUnknown() && !importMaterialPlan.ValidTo.IsNull() {
		payload.ValidTo = importMaterialPlan.ValidTo.ValueString()
	}
	keyID := plan.KeyID.ValueString()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error importing key material. Failed to import key material, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Info(ctx, string(payloadJSON))
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/import-material", payloadJSON)
	if err != nil {
		msg := "Error importing key material, failed to import key material."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Debug(ctx, "[resource_aws_key_import_material.go -> importKeyMaterial][response:"+redactAWSResponse(response))
	return response
}

// setCommonKeyStateImportMaterial populates the common read-only key fields for the import-material resource from an API response.
func (r *resourceAWSKeyImportMaterial) setImportMaterialState(ctx context.Context, response string, state *AWSKeyCommonImportMaterialTFSDK, diags *diag.Diagnostics) {
	state.KeyID = types.StringValue(gjson.Get(response, "id").String())
	state.ARN = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	state.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	state.AWSKeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	state.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	state.EncryptionAlgorithms = utils.StringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	state.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	state.ExternalAccounts = utils.StringSliceJSONToSetValue(gjson.Get(response, "external_accounts").Array(), diags)
	state.KeyAdmins = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins").Array(), diags)
	state.KeyAdminsRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_admins_roles").Array(), diags)
	state.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	state.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	state.KeySource = types.StringValue(gjson.Get(response, "key_source").String())
	state.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	state.KeyType = types.StringValue(gjson.Get(response, "key_type").String())
	state.KeyUsers = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users").Array(), diags)
	state.KeyUsersRoles = utils.StringSliceJSONToSetValue(gjson.Get(response, "key_users_roles").Array(), diags)
	state.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	if state.KMS.ValueString() == "" {
		state.KMS = types.StringValue(gjson.Get(response, "kms").String())
	}
	setKeyLabels(ctx, response, state.KeyID.ValueString(), &state.Labels, diags)
	state.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	state.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	state.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	state.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	state.Region = types.StringValue(gjson.Get(response, "region").String())
	state.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	state.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_from").String())
	state.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	state.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())
}
