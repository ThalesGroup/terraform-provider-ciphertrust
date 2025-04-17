package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cm"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceAWSKey{}
	_ resource.ResourceWithConfigure = &resourceAWSKey{}
)

const (
	PolicyTemplateTagKey = "cckm_policy_template_id"
	LongAwsKeyOpSleep    = 20
	ShortAwsKeyOpSleep   = 5
	AwsValidToRegEx      = `^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$`
	AwsValidToFormatMsg  = "must conform to the following example 2024-07-03T14:24:00Z"
	Creating             = "creating"
	Updating             = "updating"
)

const (
	AWSKeysURL             = "api/v1/cckm/aws/keys"
	AddAliasURL            = "api/v1/cckm/aws/keys/%s/add-alias"
	AddTagsURL             = "api/v1/cckm/aws/keys/%s/add-tags"
	DeleteAliasURL         = "api/v1/cckm/aws/keys/%s/delete-alias"
	DisableAutoRotationURL = "api/v1/cckm/aws/keys/%s/disable-auto-rotation"
	DisableKeyURL          = "api/v1/cckm/aws/keys/%s/disable"
	EnableAutoRotationURL  = "api/v1/cckm/aws/keys/%s/enable-auto-rotation"
	EnableKeyURL           = "api/v1/cckm/aws/keys/%s/enable"
	EnableRotationJobURL   = "api/v1/cckm/aws/keys/%s/enable-rotation-job"
	ImportKeyMaterialURL   = "api/v1/cckm/aws/keys/%s/import-material"
	RemoveTagsURL          = "api/v1/cckm/aws/keys/%s/remove-tags"
	ReplicateKeyURL        = "api/v1/cckm/aws/keys/%s/replicate-key"
	ScheduleDeletionURL    = "api/v1/cckm/aws/keys/%s/schedule-deletion"
	UpdateDescriptionURL   = "api/v1/cckm/aws/keys/%s/update-description"
	UpdateKeyPolicyURL     = "api/v1/cckm/aws/keys/%s/policy"
	UpdatePrimaryRegionURL = "api/v1/cckm/aws/keys/%s/update-primary-region"
	UploadKeyURL           = "api/v1/cckm/aws/upload-key"
	DisableRotationJobURL  = "api/v1/cckm/aws/keys/%s/disable-rotation-job"
)

func NewResourceAWSKey() resource.Resource {
	return &resourceAWSKey{}
}

type resourceAWSKey struct {
	client *common.Client
}

func (r *resourceAWSKey) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key"
}

func (r *resourceAWSKey) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSKey) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create an AWS key.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "AWS region in which to create or replicate a key.",
			},
			"alias": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Alias(es) of the key. To allow for key rotation changing or removing original aliases, all aliases already assigned to another key will be ignored.",
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(
						stringvalidator.RegexMatches(
							regexp.MustCompile(`^[a-zA-Z0-9/_-]+$`),
							"must only contain alphanumeric characters, forward slashes, underscores, and dashes",
						),
					),
				},
			},
			"auto_rotate": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Enable AWS autorotation on the key. Default is false.",
				Default:     booldefault.StaticBool(false),
			},
			"auto_rotation_period_in_days": schema.Int64Attribute{
				Computed:    true,
				Optional:    true,
				Description: "Rotation period in days. Optional parameter for auto_rotate. Must be at least 90 days.",
				Validators: []validator.Int64{
					int64validator.AtLeast(90),
					int64validator.AlsoRequires(
						path.Expressions{
							path.MatchRoot("auto_rotate"),
						}...,
					),
				},
			},
			"bypass_policy_lockout_safety_check": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to bypass the key policy lockout safety check.",
			},
			"customer_master_key_spec": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"SYMMETRIC_DEFAULT",
						"RSA_2048",
						"RSA_3072",
						"RSA_4096",
						"ECC_NIST_P256",
						"ECC_NIST_P384",
						"ECC_NIST_P521",
						"ECC_SECG_P256K1",
						"HMAC_224",
						"HMAC_256",
						"HMAC_384",
						"HMAC_512"}...),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description of the AWS key.",
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable or disable the key. Default is true.",
				Computed:    true,
				Default:     booldefault.StaticBool(true),
			},
			"key_usage": schema.StringAttribute{
				Optional:    true,
				Description: "Specifies the intended use of the key. RSA key options: ENCRYPT_DECRYPT, SIGN_VERIFY. Default is ENCRYPT_DECRYPT. EC key options: SIGN_VERIFY. Default is SIGN_VERIFY. Symmetric key options: ENCRYPT_DECRYPT. Default is ENCRYPT_DECRYPT.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"ENCRYPT_DECRYPT",
						"SIGN_VERIFY",
						"GENERATE_VERIFY_MAC"}...),
				},
			},
			"kms": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name or ID of the KMS to be used to create the key. Required unless replicating a multi-region key.",
			},
			"multi_region": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Creates or identifies a multi-region key.",
			},
			"origin": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Source of the key material. Options: AWS_KMS, EXTERNAL. AWS_KMS will create a native AWS key and is the default for AWS native key creation. EXTERNAL will create an external AWS key and is the default for import operations. This parameter is not required for upload operations.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"AWS_KMS",
						"EXTERNAL"}...),
				},
			},
			"primary_region": schema.StringAttribute{
				Optional:    true,
				Description: "Updates the primary region of a multi-region key.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Computed:    true,
				Optional:    true,
				Description: "Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is 7.",
				Default:     int64default.StaticInt64(7),
				Validators: []validator.Int64{
					int64validator.AtLeast(7),
				},
			},
			"tags": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
			},
			//Read-Only Params
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
			"enabled": schema.BoolAttribute{
				Computed:    true,
				Description: "True if the key is enabled.",
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
			"external_accounts": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Other AWS accounts that have access to this key.",
			},
			"key_admins": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - users.",
			},
			"key_admins_roles": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key administrators - roles.",
			},
			"key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust Key ID.",
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
			"key_users": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - users.",
			},
			"key_users_roles": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Key users - roles.",
			},
			"kms_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the kms",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
			},
			"local_key_id": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust key identifier of the external key.",
			},
			"local_key_name": schema.StringAttribute{
				Computed:    true,
				Description: "CipherTrust key name of the external key.",
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
			"policy": schema.StringAttribute{
				Computed:    true,
				Description: "AWS key policy.",
			},
			"policy_template_tag": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "AWS key tag for an associated policy template.",
			},
			"replica_policy": schema.StringAttribute{
				Computed:    true,
				Description: "Replication policy.",
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
			"key_policy": schema.ListNestedBlock{
				Description: "Key policy parameters.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"external_accounts": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Other AWS accounts that can access to the key.",
						},
						"key_admins": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key administrators - users.",
						},
						"key_admins_roles": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key administrators - roles.",
						},
						"key_users": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key users - users.",
						},
						"key_users_roles": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key users - roles.",
						},
						"policy": schema.StringAttribute{
							Optional:    true,
							Description: "AWS key policy json.",
						},
						"policy_template": schema.StringAttribute{
							Optional:    true,
							Description: "CipherTrust policy template ID",
						},
					},
				},
			},
			"replicate_key": schema.ListNestedBlock{
				Description: "Replicate key parameters.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"key_id": schema.StringAttribute{
							Required:    true,
							Description: "CipherTrust key ID of the key to replicate.",
						},
						"import_key_material": schema.BoolAttribute{
							Optional:    true,
							Description: "Import key material to a replicated external key.",
						},
						"key_expiration": schema.BoolAttribute{
							Optional:    true,
							Description: "Enable key expiration of the replicated key. Only applies to external keys.",
						},
						"make_primary": schema.BoolAttribute{
							Optional:    true,
							Description: "Update the primary key region to the replicated key's region following replication.",
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date the key material of the replicated key expires. Only applies to external keys. Set as UTC time in RFC3339 format. For example, 2024-07-03T14:24:00Z.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(AwsValidToRegEx), AwsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"upload_key": schema.ListNestedBlock{
				Description: "Key upload parameters.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"source_key_identifier": schema.StringAttribute{
							Required:    true,
							Description: "CipherTrust key ID to upload to AWS.",
						},
						"key_expiration": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
							Description: "Enable key expiration. Default is false.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Default:     stringdefault.StaticString("local"),
							Description: "Source key tier. Current option is 'local' only. Default is 'local'",
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date of key expiry in UTC time in RFC3339 format. For example, 2024-07-03T14:24:00Z. Only valid if 'key_expiration' is true.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(AwsValidToRegEx), AwsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"import_key_material": schema.ListNestedBlock{
				Description: "Key import details.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"source_key_name": schema.StringAttribute{
							Required:    true,
							Description: "Name of the key created for key material.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Default:     stringdefault.StaticString("local"),
							Description: "Source key tier. Current option is local. Default is local.",
						},
						"key_expiration": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Description: "Enable key material expiration. Default is false.",
							Default:     booldefault.StaticBool(false),
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date of key material expiry in UTC time in RFC3339 format. For example, 2024-07-03T14:24:00Z.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(AwsValidToRegEx), AwsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"enable_rotation": schema.ListNestedBlock{
				Description: "Enable the key for scheduled rotation job.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"job_config_id": schema.StringAttribute{
							Required:    true,
							Description: "ID of the scheduler configuration job that will schedule the key rotation.",
						},
						"key_source": schema.StringAttribute{
							Required:    true,
							Description: "Key source from where the key will be uploaded. Currently, the only option is 'ciphertrust'.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"ciphertrust"}...),
							},
						},
						"disable_encrypt": schema.BoolAttribute{
							Optional:    true,
							Description: "Disable encryption on the old key.",
						},
					},
				},
			},
		},
	}
}

func (r *resourceAWSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Create]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Create]["+uid+"]")
	var plan AWSKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var response string
	if len(plan.ImportKeyMaterial.Elements()) != 0 {
		response = r.importKeyMaterial(ctx, uid, &plan, &resp.Diagnostics)
	} else if len(plan.UploadKey.Elements()) != 0 {
		response = r.uploadKey(ctx, uid, &plan, &resp.Diagnostics)
	} else if len(plan.ReplicateKey.Elements()) != 0 {
		response = r.replicateKey(ctx, uid, &plan, &resp.Diagnostics)
	} else {
		response = r.createKey(ctx, uid, &plan, &resp.Diagnostics)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
	if len(plan.Alias.Elements()) > 1 {
		response = r.addAliases(ctx, uid, &plan, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if plan.AutoRotate.ValueBool() {
		response = r.enableDisableAutoRotation(ctx, uid, &plan, response, Creating, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if len(plan.EnableRotation.Elements()) != 0 {
		response = r.enableKeyRotationJob(ctx, uid, &plan, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	response = r.enableDisableKey(ctx, uid, &plan, response, Creating, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	kid := gjson.Get(response, "aws_param.KeyID").String()
	region := gjson.Get(response, "region").String()
	plan.ID = types.StringValue(r.encodeTerraformResourceID(region, kid))
	keyID := plan.KeyID.ValueString()
	response, err := r.client.GetById(ctx, uid, keyID, AWSKeysURL)
	if err != nil {
		msg := "Error reading 'ciphertrust_aws_key'."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	setKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error creating 'ciphertrust_aws_key', failed to set resource state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> Create][response:"+response)
}

func (r *resourceAWSKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Read]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Read]["+uid+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, uid, keyID, AWSKeysURL)
	if err != nil {
		msg := "Error reading 'ciphertrust_aws_key'."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	setKeyState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading 'ciphertrust_aws_key', failed to set resource state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> Read][response:"+response)
}

func (r *resourceAWSKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Update]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Update]["+uid+"]")
	var plan AWSKeyTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	plan.KeyID = types.StringValue(keyID)
	response, err := r.client.GetById(ctx, uid, keyID, AWSKeysURL)
	if err != nil {
		msg := "Error updating 'ciphertrust_aws_key'. Failed to read key."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	response = r.updateAliases(ctx, uid, &plan, &state, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response = r.updateDescription(ctx, uid, &plan, &state, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response = r.enableDisableKey(ctx, uid, &plan, response, Updating, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response = r.enableDisableAutoRotation(ctx, uid, &plan, response, Updating, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response = r.updateKeyPolicy(ctx, uid, &plan, &state, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response = r.updateTags(ctx, uid, &plan, &state, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.PrimaryRegion.IsNull() && plan.PrimaryRegion != state.PrimaryRegion {
		response = r.updatePrimaryRegion(ctx, uid, &plan, response, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	r.enableDisableKeyRotation(ctx, uid, &plan, &state, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err = r.client.GetById(ctx, uid, keyID, AWSKeysURL)
	if err != nil {
		msg := "Error reading 'ciphertrust_aws_key'."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	setKeyState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating 'ciphertrust_aws_key', failed to set resource state."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> Update][response:"+response)
}

func (r *resourceAWSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	uid := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Delete]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Delete]["+uid+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := ScheduleForDeletionJSON{
		Days: state.ScheduleForDeletionDays.ValueInt64(),
	}
	keyID := state.KeyID.ValueString()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error deleting 'ciphertrust_aws_key', error marshaling payload."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	_, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(ScheduleDeletionURL, keyID), payloadJSON)
	if err != nil {
		msg := "Error deleting 'ciphertrust_aws_key', error posting payload."
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
}

func (r *resourceAWSKey) encodeTerraformResourceID(region, kid string) string {
	return region + "\\" + kid
}

func (r *resourceAWSKey) createKey(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> createKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> createKey]["+uid+"]")
	commonAwsParams := r.getCommonAWSParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	createKeyParams := r.getCommonAWSKeyCreateParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	payload := CreateAWSKeyPayloadJSON{
		CommonAWSKeyCreatePayloadJSON: *createKeyParams,
		AWSParam: AWSKeyParamJSON{
			CommonAWSParamsJSON: *commonAwsParams,
			Origin:              plan.Origin.ValueString(),
		},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key', error marshaling payload."
		details := map[string]interface{}{"payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err := r.client.PostDataV2(ctx, uid, AWSKeysURL, payloadJSON)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key', error posting payload."
		details := map[string]interface{}{"payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> createKey][response:"+response)
	return response
}

func /*(r *resourceAWSKey)*/ setKeyState(ctx context.Context, response string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) {
	plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
	setAliases(response, plan, diags)
	if diags.HasError() {
		return
	}
	plan.ARN = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	plan.AutoRotate = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	plan.AutoRotationPeriodInDays = types.Int64Value(gjson.Get(response, "aws_param.RotationPeriodInDays").Int())
	plan.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	plan.AWSKeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	plan.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	plan.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	plan.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	plan.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	plan.EncryptionAlgorithms = flattenStringSliceJSON(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	if diags.HasError() {
		return
	}
	plan.ExpirationModel = types.StringValue(gjson.Get(response, "").String())
	plan.ExternalAccounts = flattenStringSliceJSON(gjson.Get(response, "external_accounts").Array(), diags)
	if diags.HasError() {
		return
	}
	plan.KeyAdmins = flattenStringSliceJSON(gjson.Get(response, "key_admins").Array(), diags)
	if diags.HasError() {
		return
	}
	plan.KeyAdminsRoles = flattenStringSliceJSON(gjson.Get(response, "key_admins_roles").Array(), diags)
	if diags.HasError() {
		return
	}
	plan.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	plan.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	plan.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	plan.KeySource = types.StringValue(gjson.Get(response, "key_source").String())
	plan.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	plan.KeyType = types.StringValue(gjson.Get(response, "key_type").String())
	plan.KeyUsers = flattenStringSliceJSON(gjson.Get(response, "key_users").Array(), diags)
	if diags.HasError() {
		return
	}
	plan.KeyUsersRoles = flattenStringSliceJSON(gjson.Get(response, "key_users_roles").Array(), diags)
	if diags.HasError() {
		return
	}
	plan.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	if plan.KMS.ValueString() == "" {
		plan.KMS = types.StringValue(gjson.Get(response, "kms").String())
	}
	setKeyLabels(ctx, response, plan, diags)
	if diags.HasError() {
		return
	}
	plan.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	plan.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	plan.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	plan.MultiRegionKeyType = types.StringValue(gjson.Get(response, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String())
	setMultiRegionConfiguration(ctx, response, plan, diags)
	if diags.HasError() {
		return
	}
	plan.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
	plan.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	plan.Policy = types.StringValue(gjson.Get(response, "aws_param.Policy").String())
	setPolicyTemplateTag(ctx, response, plan, diags)
	if diags.HasError() {
		return
	}
	plan.ReplicaPolicy = types.StringValue(gjson.Get(response, "replica_policy").String())
	plan.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	plan.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_to").String())
	plan.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	plan.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	plan.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	setKeyTags(ctx, response, plan, false, diags)
	if diags.HasError() {
		return
	}
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())
}

func (r *resourceAWSKey) enableDisableAutoRotation(ctx context.Context, uid string, plan *AWSKeyTFSDK, keyJSON string, operation string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableAutoRotation]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableAutoRotation]["+uid+"]")
	planAutoRotationEnabled := plan.AutoRotate.ValueBool()
	keyAutoRotationEnabled := gjson.Get(keyJSON, "aws_param.KeyRotationEnabled").Bool()
	keyID := plan.KeyID.ValueString()
	if keyAutoRotationEnabled != planAutoRotationEnabled {
		var response string
		if planAutoRotationEnabled {
			var payload EnableAutoRotationPayloadJSON
			if !plan.AutoRotationPeriodInDays.IsNull() && !plan.AutoRotationPeriodInDays.IsUnknown() {
				payload.RotationPeriodInDays = plan.AutoRotationPeriodInDays.ValueInt64Pointer()
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := fmt.Sprintf("Error %s 'ciphertrust_aws_key'. Failed to enable auto-rotation, error marshaling payload.", operation)
				details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				if operation == Creating {
					diags.AddWarning(msg, apiDetail(details))
				} else {
					diags.AddError(msg, apiDetail(details))
				}
				return ""
			}
			response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(EnableAutoRotationURL, keyID), payloadJSON)
			if err != nil {
				msg := fmt.Sprintf("Error %s 'ciphertrust_aws_key'. Failed to enable auto-rotation for 'ciphertrust_aws_key', error posting payload.", operation)
				details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
				if operation == Creating {
					diags.AddWarning(msg, apiDetail(details))
					tflog.Warn(ctx, msg, details)
				} else {
					diags.AddError(msg, apiDetail(details))
					tflog.Error(ctx, msg, details)
				}
				return ""
			}
			numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / ShortAwsKeyOpSleep)
			nextRotationDate := gjson.Get(response, "aws_param.NextRotationDate").String()
			for retry := 0; retry < numRetries && nextRotationDate == ""; retry++ {
				time.Sleep(time.Duration(ShortAwsKeyOpSleep) * time.Second)
				response, err = r.client.GetById(ctx, uid, keyID, AWSKeysURL)
				if err != nil {
					msg := fmt.Sprintf("Error %s 'ciphertrust_aws_key'. Failed to enable auto-rotation', error reading key.", operation)
					details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
					if operation == Creating {
						tflog.Warn(ctx, msg, details)
						diags.AddWarning(msg, apiDetail(details))
					} else {
						tflog.Error(ctx, msg, details)
						diags.AddError(msg, apiDetail(details))
					}
					return ""
				}
				nextRotationDate = gjson.Get(response, "aws_param.NextRotationDate").String()
				if nextRotationDate != "" {
					break
				}
			}
			if nextRotationDate != "" {
				msg := fmt.Sprintf("Error %s 'ciphertrust_aws_key'. Failed to confirm auto-rotation is configured.' Consider extending provider configuration option 'aws_operation_timeout'.", operation)
				details := map[string]interface{}{"key_id": keyID}
				if operation == Creating {
					tflog.Warn(ctx, msg, details)
					diags.AddWarning(msg, apiDetail(details))
				} else {
					tflog.Error(ctx, msg, details)
					diags.AddError(msg, apiDetail(details))
				}
			}
			return response
		} else {
			var err error
			response, err = r.client.PostNoData(ctx, uid, fmt.Sprintf(DisableAutoRotationURL, keyID))
			if err != nil {
				msg := fmt.Sprintf("Error %s 'ciphertrust_aws_key'. Failed to disable auto-rotation for 'ciphertrust_aws_key', error posting.", operation)
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				if operation == Creating {
					diags.AddWarning(msg, apiDetail(details))
					tflog.Warn(ctx, msg, details)
				} else {
					diags.AddError(msg, apiDetail(details))
					tflog.Error(ctx, msg, details)
				}
				return ""
			}
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> enableDisableAutoRotation][response:"+response)
		return response
	}
	return keyJSON
}

func (r *resourceAWSKey) enableKeyRotationJob(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	rotationParams := make([]AWSKeyEnableRotationTFSDK, 0, len(plan.EnableRotation.Elements()))
	if !plan.EnableRotation.IsUnknown() {
		diags.Append(plan.EnableRotation.ElementsAs(ctx, &rotationParams, false)...)
		if diags.HasError() {
			return ""
		}
	}
	var response string
	for _, params := range rotationParams {
		payload := AWSEnableKeyRotationJobPayloadJSON{
			JobConfigID:              params.JobConfigID.ValueString(),
			AutoRotateDisableEncrypt: params.AutoRotateDisableEncrypt.ValueBool(),
		}
		if params.AutoRotateKeySource.ValueString() != "" {
			payload.AutoRotateKeySource = params.AutoRotateKeySource.ValueStringPointer()
		}
		keyID := plan.KeyID.ValueString()
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Failed to enable key rotation for 'ciphertrust_aws_key' " + keyID + ", error marshaling payload."
			tflog.Error(ctx, msg, map[string]interface{}{"error": err.Error()})
			diags.AddError(msg, err.Error())
			return ""
		}
		response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(EnableRotationJobURL, keyID), payloadJSON)
		if err != nil {
			msg := "Failed to enable key rotation for 'ciphertrust_aws_key' " + keyID + ", error posting payload."
			tflog.Error(ctx, msg, map[string]interface{}{"error": err.Error()})
			diags.AddError(msg, err.Error())
			return ""
		}
	}
	return response
}

func (r *resourceAWSKey) disableKeyRotationJob(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	keyID := plan.KeyID.ValueString()
	response, err := r.client.PostNoData(ctx, uid, fmt.Sprintf(DisableRotationJobURL, keyID))
	if err != nil {
		msg := fmt.Sprintf("Error updating 'ciphertrust_aws_key'. Failed to disable key rotation job for 'ciphertrust_aws_key', error posting.")
		details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
		diags.AddError(msg, apiDetail(details))
		tflog.Error(ctx, msg, details)
		return ""
	}
	return response
}

func (r *resourceAWSKey) importKeyMaterial(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> importKeyMaterial]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> importKeyMaterial]["+uid+"]")
	var importMaterialPlan AWSKeyImportKeyMaterialTFSDK
	for _, v := range plan.ImportKeyMaterial.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, v, &importMaterialPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	sourceKeyJSON := r.createKeyMaterial(ctx, uid, &importMaterialPlan, diags)
	sourceKeyID := gjson.Get(sourceKeyJSON, "id").String()
	if diags.HasError() {
		return ""
	}
	if plan.Origin.ValueString() == "" {
		plan.Origin = types.StringValue("EXTERNAL")
	}
	response := r.createKey(ctx, uid, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyID := gjson.Get(response, "id").String()
	payload := AWSKeyImportKeyPayloadJSON{
		SourceKeyID:   sourceKeyID,
		SourceKeyTier: importMaterialPlan.SourceKeyTier.ValueString(),
		KeyExpiration: importMaterialPlan.KeyExpiration.ValueBool(),
		ValidTo:       importMaterialPlan.ValidTo.String(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key'. Failed to import key material, error marshaling payload."
		details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(ImportKeyMaterialURL, keyID), payloadJSON)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key'. Failed to import key material, error posting payload."
		details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> importKeyMaterial][response:"+response)
	return response
}

func (r *resourceAWSKey) uploadKey(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> UploadKeyAWS]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> UploadKeyAWS]["+uid+"]")
	createKeyParams := r.getCommonAWSKeyCreateParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	awsParams := r.getCommonAWSParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	var uploadKeyPlan AWSUploadKeyTFSDK
	for _, uploadElement := range plan.UploadKey.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, uploadElement, &uploadKeyPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	uploadAWSParams := UploadAWSKeyParamJSON{
		CommonAWSParamsJSON: *awsParams,
		ValidTo:             uploadKeyPlan.ValidTo.ValueString(),
	}
	payload := UploadAWSKeyPayloadJSON{
		AWSParam:                      &uploadAWSParams,
		CommonAWSKeyCreatePayloadJSON: *createKeyParams,
		SourceKeyIdentifier:           uploadKeyPlan.SourceKeyID.ValueString(),
		SourceKeyTier:                 uploadKeyPlan.SourceKeyTier.ValueString(),
		KeyExpiration:                 uploadKeyPlan.KeyExpiration.ValueBool(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key'. Failed to upload, error marshaling payload."
		details := map[string]interface{}{"payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err := r.client.PostDataV2(ctx, uid, UploadKeyURL, payloadJSON)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key'. Failed to upload key, error posting payload."
		details := map[string]interface{}{"payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> uploadKey][response:"+response)
	return response
}

func (r *resourceAWSKey) replicateKey(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> replicateKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> replicateKey]["+uid+"]")
	commonParams := r.getCommonAWSParams(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyPolicy := r.getKeyPolicy(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	payload := CreateReplicaKeyPayloadJSON{
		AwsParams:        *commonParams,
		ExternalAccounts: keyPolicy.ExternalAccounts,
		KeyAdmins:        keyPolicy.KeyAdmins,
		KeyAdminsRoles:   keyPolicy.KeyAdminsRoles,
		KeyUsers:         keyPolicy.KeyUsers,
		KeyUsersRoles:    keyPolicy.KeyUsersRoles,
		PolicyTemplate:   keyPolicy.PolicyTemplate,
		ReplicaRegion:    plan.Region.ValueStringPointer(),
	}
	var replicateKeyPlan AWSReplicateKeyTFSDK
	for _, v := range plan.ReplicateKey.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, v, &replicateKeyPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	keyID := replicateKeyPlan.KeyID.ValueString()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key'. Failed to replicate key, error marshaling payload."
		details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err := r.client.PostDataV2(ctx, uid, fmt.Sprintf(ReplicateKeyURL, keyID), payloadJSON)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_key'. Failed to replicate key, error posting payload."
		details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	replicatedKeyID := gjson.Get(response, "id").String()
	keyState := gjson.Get(response, "aws_param.KeyState").String()
	numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / LongAwsKeyOpSleep)
	for retry := 0; retry < numRetries && keyState == "Creating"; retry++ {
		time.Sleep(time.Duration(LongAwsKeyOpSleep) * time.Second)
		//if err := setAuthToken(ctx, ctp); err != nil {
		//	return nil, err
		//}
		response, err = r.client.GetById(ctx, uid, replicatedKeyID, AWSKeysURL)
		if err != nil {
			msg := "Error creating 'ciphertrust_aws_key'. Failed to replicate key, error reading key."
			details := map[string]interface{}{"key_id": replicatedKeyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
	}
	if keyState != "Enabled" {
		msg := "Failed to confirm 'ciphertrust_aws_key' has been replicated in given time. Consider extending provider configuration option 'aws_operation_timeout'."
		details := map[string]interface{}{"key_id": replicatedKeyID}
		tflog.Warn(ctx, msg, details)
		diags.AddWarning(msg, apiDetail(details))
	} else {
		if replicateKeyPlan.MakePrimary.ValueBool() {
			r.makePrimaryKey(ctx, uid, keyID, plan.Region.ValueString(), Creating, diags)
			if diags.HasError() {
				return ""
			}
		}
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> uploadKey][response:"+response)
	return response
}

func (r *resourceAWSKey) makePrimaryKey(ctx context.Context, uid string, primaryKeyID string, region string, operation string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> makePrimaryKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> makePrimaryKey]["+uid+"]")
	payload := UpdatePrimaryRegionJSON{
		PrimaryRegion: &region,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := fmt.Sprintf("Error %s 'ciphertrust_aws_key'. Failed to enable auto-rotation, error marshaling payload.", operation)
		details := map[string]interface{}{"primary key_id": primaryKeyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		if operation == Creating {
			diags.AddWarning(msg, apiDetail(details))
		} else {
			diags.AddError(msg, apiDetail(details))
		}
	}
	response, err := r.client.PostDataV2(ctx, uid, fmt.Sprintf(UpdatePrimaryRegionURL, primaryKeyID), payloadJSON)
	if err != nil {
		msg := fmt.Sprintf("Error %s 'ciphertrust_aws_key'. Failed to enable auto-rotation, error posting payload.", operation)
		details := map[string]interface{}{"primary key_id": primaryKeyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		if operation == Creating {
			diags.AddWarning(msg, apiDetail(details))
		} else {
			diags.AddError(msg, apiDetail(details))
		}
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> makePrimaryKey][response:"+response)
}

func (r *resourceAWSKey) enableDisableKey(ctx context.Context, uid string, plan *AWSKeyTFSDK, keyJSON string, operation string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableKey]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableKey]["+uid+"]")
	planEnable := plan.EnableKey.ValueBool()
	keyEnabled := gjson.Get(keyJSON, "aws_param.Enabled").Bool()
	keyID := plan.KeyID.ValueString()
	if keyEnabled != planEnable {
		var response string
		var err error
		if planEnable {
			response, err = r.client.PostNoData(ctx, uid, fmt.Sprintf(EnableKeyURL, keyID))
			if err != nil {
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				msg := fmt.Sprintf("Error %s 'cipherturst_aws_key'. Failed to enable key.", operation)
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return ""
			}
			tflog.Trace(ctx, "[resource_aws_key.go -> enableDisableKey][response:"+response)
			return response
		} else {
			response, err = r.client.PostNoData(ctx, uid, fmt.Sprintf(DisableKeyURL, keyID))
			if err != nil {
				msg := fmt.Sprintf("Error %s 'cipherturst_aws_key'. Failed to disable key.", operation)
				details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
				if operation == Creating {
					tflog.Warn(ctx, msg, details)
					diags.AddWarning(msg, apiDetail(details))
				} else {
					tflog.Error(ctx, msg, details)
					diags.AddError(msg, apiDetail(details))
				}
				return ""
			}
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> enableDisableKey][response:"+response)
		return response
	}
	return keyJSON
}

func (r *resourceAWSKey) addAliases(ctx context.Context, uid string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> addAliases]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> addAliases]["+uid+"]")
	planAliases := make([]string, 0, len(plan.Alias.Elements()))
	diags.Append(plan.Alias.ElementsAs(ctx, &planAliases, false)...)
	if diags.HasError() {
		return ""
	}
	var response string
	keyID := plan.KeyID.ValueString()
	for i := 1; i < len(planAliases); i++ {
		alias := planAliases[i]
		payload := AddRemoveAliasPayloadJSON{
			Alias: alias,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error creating 'ciphertrust_aws_key'. Failed to add alias, error marshaling payload."
			details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(AddAliasURL, keyID), payloadJSON)
		if err != nil {
			msg := "Error creating 'ciphertrust_aws_key'. Failed to add alias, error posting payload."
			details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
	}
	if response != "" {
		tflog.Trace(ctx, "[resource_aws_key.go -> addAliases][response:"+response)
		return response
	}
	return keyJSON
}

func (r *resourceAWSKey) updateAliases(ctx context.Context, uid string, plan *AWSKeyTFSDK, state *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateAliases]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateAliases]["+uid+"]")
	stateAliases := make([]string, 0, len(plan.Alias.Elements()))
	diags.Append(state.Alias.ElementsAs(ctx, &stateAliases, false)...)
	if diags.HasError() {
		return ""
	}
	planAliases := make([]string, 0, len(plan.Alias.Elements()))
	if len(plan.Alias.Elements()) != 0 {
		diags.Append(plan.Alias.ElementsAs(ctx, &planAliases, false)...)
		if diags.HasError() {
			return ""
		}
	}
	var response string
	keyID := plan.KeyID.ValueString()
	for _, planAlias := range planAliases {
		add := true
		for _, stateAlias := range stateAliases {
			if stateAlias == planAlias {
				add = false
				break
			}
		}
		if add {
			payload := AddRemoveAliasPayloadJSON{
				Alias: planAlias,
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error updating 'ciphertrust_aws_key'. Failed to add alias, error marshaling payload."
				details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return ""
			}
			response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(AddAliasURL, keyID), payloadJSON)
			if err != nil {
				msg := "Error updating 'ciphertrust_aws_key'. Failed to add alias, error posting payload."
				details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return ""
			}
		}
	}

	// Remove aliases not in the plan but in the key
	for _, stateAlias := range stateAliases {
		if strings.Contains(stateAlias, "-rotated-") {
			// Dont delete these aliases
			continue
		}
		remove := true
		for _, planAlias := range planAliases {
			if planAlias == stateAlias {
				remove = false
				break
			}
		}
		if remove {
			payload := AddRemoveAliasPayloadJSON{
				Alias: stateAlias,
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error updating 'ciphertrust_aws_key'. Failed to remove alias, error marshaling payload."
				details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return ""
			}
			response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(DeleteAliasURL, keyID), payloadJSON)
			if err != nil {
				msg := "Error updating 'ciphertrust_aws_key'. Failed to remove alias, error posting payload."
				details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
				tflog.Error(ctx, msg, details)
				diags.AddError(msg, apiDetail(details))
				return ""
			}
		}
	}
	if len(response) != 0 {
		tflog.Trace(ctx, "[resource_aws_key.go -> updateAliases][response:"+response)
		return response
	}
	return keyJSON
}

func (r *resourceAWSKey) updateDescription(ctx context.Context, uid string, plan *AWSKeyTFSDK, state *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateDescription]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateDescription]["+uid+"]")
	var stateDescription string
	if !state.Description.IsNull() && !state.Description.IsUnknown() {
		stateDescription = state.Description.ValueString()
	}
	var planDescription string
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		planDescription = plan.Description.ValueString()
	}
	if planDescription == stateDescription {
		return keyJSON
	}
	keyID := plan.KeyID.ValueString()
	payload := UpdateKeyDescriptionPayloadJSON{
		Description: plan.Description.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating 'ciphertrust_aws_key'. Failed to update description, error marshaling payload."
		details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	response, err := r.client.PostDataV2(ctx, uid, fmt.Sprintf(UpdateDescriptionURL, keyID), payloadJSON)
	if err != nil {
		msg := "Error updating 'ciphertrust_aws_key'. Failed to update description, error posting payload."
		details := map[string]interface{}{"key_id": keyID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> updateDescription][response:"+response)
	return response
}

func (r *resourceAWSKey) updateTags(ctx context.Context, uid string, plan *AWSKeyTFSDK, state *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateTags]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateTags]["+uid+"]")
	var addTagsPayload AddTagsJSON
	var removeTagsPayload RemoveTagsJSON
	var response string
	keyID := plan.KeyID.ValueString()
	stateTags := make(map[string]string, len(state.Tags.Elements()))
	diags.Append(state.Tags.ElementsAs(ctx, &stateTags, false)...)
	if diags.HasError() {
		return ""
	}
	planTags := make(map[string]string, len(plan.Tags.Elements()))
	if len(plan.Tags.Elements()) != 0 {
		diags.Append(plan.Tags.ElementsAs(ctx, &planTags, false)...)
		if diags.HasError() {
			return ""
		}
	}
	for stateKey, stateValue := range stateTags {
		found := false
		for planKey, planValue := range planTags {
			if planKey == stateKey && planValue == stateValue {
				found = true
				break
			}
		}
		if !found {
			t := stateKey
			removeTagsPayload.Tags = append(removeTagsPayload.Tags, &t)
		}
	}
	if len(removeTagsPayload.Tags) != 0 {
		payloadJSON, err := json.Marshal(removeTagsPayload)
		if err != nil {
			msg := "Error updating 'ciphertrust_aws_key'. Failed to remove tags, error marshaling payload."
			details := map[string]interface{}{"key_id": keyID, "payload": removeTagsPayload, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(RemoveTagsURL, keyID), payloadJSON)
		if err != nil {
			msg := "Error updating 'ciphertrust_aws_key'. Failed to remove tags, error posting payload."
			details := map[string]interface{}{"key_id": keyID, "payload": removeTagsPayload, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
	}
	for planKey, planValue := range planTags {
		found := false
		for stateKey, stateValue := range stateTags {
			if planKey == stateKey && planValue == stateValue {
				found = true
				break
			}
		}
		if !found {
			t := AddTagPayloadJSON{
				TagKey:   planKey,
				TagValue: planValue,
			}
			addTagsPayload.Tags = append(addTagsPayload.Tags, t)
		}
	}
	if len(addTagsPayload.Tags) != 0 {
		payloadJSON, err := json.Marshal(addTagsPayload)
		if err != nil {
			msg := "Error updating 'ciphertrust_aws_key'. Failed to add tags, error marshaling payload."
			details := map[string]interface{}{"key_id": keyID, "payload": addTagsPayload, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		response, err = r.client.PostDataV2(ctx, uid, fmt.Sprintf(AddTagsURL, keyID), payloadJSON)
		if err != nil {
			msg := "Error updating 'ciphertrust_aws_key'. Failed to add tags, error marshaling payload."
			details := map[string]interface{}{"key_id": keyID, "payload": addTagsPayload, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
	}
	if response != "" {
		tflog.Trace(ctx, "[resource_aws_key.go -> updateTags][response:"+response)
		return response
	}
	return keyJSON
}

func (r *resourceAWSKey) updateKeyPolicy(ctx context.Context, uid string, plan *AWSKeyTFSDK, state *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateKeyPolicy]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateKeyPolicy]["+uid+"]")
	statePolicy := r.getKeyPolicy(ctx, state, diags)
	if diags.HasError() {
		return ""
	}
	planPolicyPayload := r.getKeyPolicy(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	if planPolicyPayload.ExternalAccounts != statePolicy.ExternalAccounts ||
		planPolicyPayload.KeyAdmins != statePolicy.KeyAdmins ||
		planPolicyPayload.KeyAdminsRoles != statePolicy.KeyAdminsRoles ||
		planPolicyPayload.KeyUsers != statePolicy.KeyUsers ||
		planPolicyPayload.KeyUsersRoles != statePolicy.KeyUsersRoles ||
		planPolicyPayload.PolicyTemplate != statePolicy.PolicyTemplate ||
		planPolicyPayload.Policy != statePolicy.Policy {
		keyID := plan.KeyID.ValueString()
		payloadJSON, err := json.Marshal(planPolicyPayload)
		if err != nil {
			msg := "Error updating 'ciphertrust_aws_key'. Failed to update key policy, error posting payload."
			details := map[string]interface{}{"key_id": keyID, "payload": planPolicyPayload, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		response, err := r.client.PostDataV2(ctx, uid, fmt.Sprintf(UpdateKeyPolicyURL, keyID), payloadJSON)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_key.go -> Create]["+uid+"]")
			diags.AddError("Failed to update key policy on "+keyID+", error posting payload.", err.Error())
			return ""
		}
		plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
		tflog.Trace(ctx, "[resource_aws_key.go -> updateKeyPolicy][response:"+response)
		return response
	}
	return keyJSON
}

func (r *resourceAWSKey) updatePrimaryRegion(ctx context.Context, uid string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updatePrimaryRegion]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updatePrimaryRegion]["+uid+"]")
	planPrimaryRegion := plan.PrimaryRegion.ValueString()
	currentPrimaryRegion := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	if plan.PrimaryRegion.ValueString() == currentPrimaryRegion {
		return keyJSON
	}
	primaryKeyID := r.getPrimaryKeyID(ctx, uid, plan, diags)
	if diags.HasError() {
		return ""
	}
	r.makePrimaryKey(ctx, uid, primaryKeyID, plan.PrimaryRegion.ValueString(), Updating, diags)
	if diags.HasError() {
		return ""
	}
	// Refresh current key until primary region is the new region
	keyID := plan.KeyID.ValueString()
	numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / ShortAwsKeyOpSleep)
	var response string
	for retry := 0; retry < numRetries && currentPrimaryRegion != planPrimaryRegion; retry++ {
		time.Sleep(time.Duration(ShortAwsKeyOpSleep) * time.Second)
		var err error
		response, err = r.client.GetById(ctx, uid, keyID, AWSKeysURL)
		if err != nil {
			msg := "Error updating 'ciphertrust_aws_key'. Error reading key."
			details := map[string]interface{}{"key_id": keyID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		currentPrimaryRegion = gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	}
	if currentPrimaryRegion != planPrimaryRegion {
		msg := "Error updating 'ciphertrust_aws_key'. Failed to confirm primary region is configured. Consider extending provider configuration option 'aws_operation_timeout'."
		details := map[string]interface{}{"key_id": keyID}
		tflog.Warn(ctx, msg, details)
		diags.AddWarning(msg, apiDetail(details))
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> updatePrimaryRegion][response:"+response)
	return response
}

func (r *resourceAWSKey) enableDisableKeyRotation(ctx context.Context, uid string, plan *AWSKeyTFSDK, state *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableKeyRotation]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableKeyRotation]["+uid+"]")
	response := keyJSON
	planParams := make([]AWSKeyEnableRotationTFSDK, 0, len(plan.EnableRotation.Elements()))
	if !plan.EnableRotation.IsUnknown() {
		diags.Append(plan.EnableRotation.ElementsAs(ctx, &planParams, false)...)
		if diags.HasError() {
			return ""
		}
	}
	stateParams := make([]AWSKeyEnableRotationTFSDK, 0, len(state.EnableRotation.Elements()))
	diags.Append(state.EnableRotation.ElementsAs(ctx, &stateParams, false)...)
	if diags.HasError() {
		return ""
	}
	if len(planParams) == 0 && len(stateParams) != 0 {
		response = r.disableKeyRotationJob(ctx, uid, plan, diags)
		if diags.HasError() {
			return ""
		}
	}
	if !reflect.DeepEqual(planParams, stateParams) {
		response = r.enableKeyRotationJob(ctx, uid, plan, diags)
		if diags.HasError() {
			return ""
		}
	}
	return response
}

func (r *resourceAWSKey) getCommonAWSParams(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) *CommonAWSParamsJSON {
	var awsParams CommonAWSParamsJSON
	if len(plan.Alias.Elements()) != 0 {
		aliases := make([]string, 0, len(plan.Alias.Elements()))
		diags.Append(plan.Alias.ElementsAs(ctx, &aliases, false)...)
		if diags.HasError() {
			return nil
		}
		awsParams.Alias = aliases[0]
	}
	if plan.BypassPolicyLockoutSafetyCheck.ValueBool() != types.BoolNull().ValueBool() {
		awsParams.BypassPolicyLockoutSafetyCheck = plan.BypassPolicyLockoutSafetyCheck.ValueBool()
	}
	if plan.CustomerMasterKeySpec.ValueString() != "" && plan.CustomerMasterKeySpec.ValueString() != types.StringNull().ValueString() {
		awsParams.CustomerMasterKeySpec = plan.CustomerMasterKeySpec.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		awsParams.Description = plan.Description.ValueString()
	}
	if plan.KeyUsage.ValueString() != "" && plan.KeyUsage.ValueString() != types.StringNull().ValueString() {
		awsParams.KeyUsage = plan.KeyUsage.ValueString()
	}
	if awsParams.KeyUsage == "" && awsParams.CustomerMasterKeySpec != "" {
		if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "ECC") {
			awsParams.KeyUsage = "SIGN_VERIFY"
		} else if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "RSA") {
			awsParams.KeyUsage = "ENCRYPT_DECRYPT"
		} else if strings.HasPrefix(awsParams.CustomerMasterKeySpec, "HMAC") {
			awsParams.KeyUsage = "GENERATE_VERIFY_MAC"
		}
	}
	if plan.MultiRegion.ValueBool() != types.BoolNull().ValueBool() {
		awsParams.MultiRegion = plan.MultiRegion.ValueBool()
	}
	if len(plan.Tags.Elements()) != 0 {
		tags := r.getTagsParam(ctx, plan, diags)
		if diags.HasError() {
			return nil
		}
		awsParams.Tags = tags
	}
	if len(plan.KeyPolicy.Elements()) != 0 {
		for _, v := range plan.KeyPolicy.Elements() {
			var keyPolicy AWSKeyPolicyTFSDK
			diags.Append(tfsdk.ValueAs(ctx, v, &keyPolicy)...)
			if diags.HasError() {
				return nil
			}
			if !keyPolicy.Policy.IsNull() && len(keyPolicy.Policy.String()) != 0 {
				policy := keyPolicy.Policy.ValueString()
				awsParams.Policy = json.RawMessage(policy)
			}
		}
	}
	return &awsParams
}

func (r *resourceAWSKey) getCommonAWSKeyCreateParams(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) *CommonAWSKeyCreatePayloadJSON {
	var keyCreateParams CommonAWSKeyCreatePayloadJSON
	keyCreateParams.KMS = plan.KMS.ValueString()
	keyCreateParams.Region = plan.Region.ValueString()
	keyPolicyPlan := r.getKeyPolicy(ctx, plan, diags)
	if diags.HasError() {
		return nil
	}
	keyCreateParams.ExternalAccounts = keyPolicyPlan.ExternalAccounts
	keyCreateParams.KeyAdmins = keyPolicyPlan.KeyAdmins
	keyCreateParams.KeyAdminsRoles = keyPolicyPlan.KeyAdminsRoles
	keyCreateParams.KeyUsers = keyPolicyPlan.KeyUsers
	keyCreateParams.KeyUsersRoles = keyPolicyPlan.KeyUsersRoles
	keyCreateParams.PolicyTemplate = keyPolicyPlan.PolicyTemplate
	return &keyCreateParams
}

func (r *resourceAWSKey) getTagsParam(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) []AWSKeyParamTagJSON {
	if len(plan.Tags.Elements()) == 0 {
		return nil
	}
	tags := make(map[string]string, len(plan.Tags.Elements()))
	diags.Append(plan.Tags.ElementsAs(ctx, &tags, false)...)
	if diags.HasError() {
		return nil
	}
	var awsTags []AWSKeyParamTagJSON
	for k, v := range tags {
		key := k
		value := v
		tag := AWSKeyParamTagJSON{
			TagKey:   key,
			TagValue: value,
		}
		awsTags = append(awsTags, tag)
	}
	return awsTags
}

func (r *resourceAWSKey) getKeyPolicy(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) *KeyPolicyPayloadJSON {
	var keyPolicy KeyPolicyPayloadJSON
	if !plan.KeyPolicy.IsNull() && len(plan.KeyPolicy.Elements()) != 0 {
		for _, v := range plan.KeyPolicy.Elements() {
			var kp AWSKeyPolicyTFSDK
			diags.Append(tfsdk.ValueAs(ctx, v, &kp)...)
			if diags.HasError() {
				return nil
			}
			if !kp.ExternalAccounts.IsNull() && len(kp.ExternalAccounts.Elements()) != 0 {
				accounts := make([]string, 0, len(kp.ExternalAccounts.Elements()))
				diags.Append(kp.ExternalAccounts.ElementsAs(ctx, &accounts, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.ExternalAccounts = &accounts
			}
			if !kp.KeyAdmins.IsNull() && len(kp.KeyAdmins.Elements()) != 0 {
				keyAdmins := make([]string, 0, len(kp.KeyAdmins.Elements()))
				diags.Append(kp.KeyAdmins.ElementsAs(ctx, &keyAdmins, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyAdmins = &keyAdmins
			}
			if !kp.KeyAdminsRoles.IsNull() && len(kp.KeyAdminsRoles.Elements()) != 0 {
				keyAdminsRoles := make([]string, 0, len(kp.KeyAdminsRoles.Elements()))
				diags.Append(kp.KeyAdminsRoles.ElementsAs(ctx, &keyAdminsRoles, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyAdminsRoles = &keyAdminsRoles
			}
			if !kp.KeyUsers.IsNull() && len(kp.KeyUsers.Elements()) != 0 {
				keyUsers := make([]string, 0, len(kp.KeyUsers.Elements()))
				diags.Append(kp.KeyUsers.ElementsAs(ctx, &keyUsers, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyUsers = &keyUsers
			}
			if !kp.KeyUsersRoles.IsNull() && len(kp.KeyUsersRoles.Elements()) != 0 {
				keyUsersRoles := make([]string, 0, len(kp.KeyUsersRoles.Elements()))
				diags.Append(kp.KeyUsersRoles.ElementsAs(ctx, &keyUsersRoles, false)...)
				if diags.HasError() {
					return nil
				}
				keyPolicy.KeyUsersRoles = &keyUsersRoles
			}
			if !kp.PolicyTemplate.IsNull() && len(kp.PolicyTemplate.String()) != 0 {
				template := kp.PolicyTemplate.ValueString()
				keyPolicy.PolicyTemplate = &template
			}
		}
	}
	return &keyPolicy
}

func flattenStringSliceJSON(jsonString []gjson.Result, diags *diag.Diagnostics) basetypes.ListValue {
	var values []attr.Value
	for _, item := range jsonString {
		values = append(values, types.StringValue(item.String()))
	}
	stringList, d := types.ListValue(types.StringType, values)
	if d.HasError() {
		diags.Append(d...)
	}
	return stringList
}

func setAliases(response string, state *AWSKeyTFSDK, diags *diag.Diagnostics) {
	var aliases []attr.Value
	aliasesJSON := gjson.Get(response, "aws_param.Alias").Array()
	for _, item := range aliasesJSON {
		alias := item.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		aliases = append(aliases, types.StringValue(alias))
	}
	var d diag.Diagnostics
	state.Alias, d = types.SetValue(types.StringType, aliases)
	if d.HasError() {
		diags.Append(d...)
		return
	}
}

func setPolicyTemplateTag(ctx context.Context, response string, state *AWSKeyTFSDK, diags *diag.Diagnostics) {
	state.PolicyTemplateTag = types.MapNull(types.StringType)
	tags := gjson.Get(response, "aws_param.Tags").Array()
	for _, tag := range tags {
		tagKey := gjson.Get(tag.String(), "TagKey").String()
		if tagKey == PolicyTemplateTagKey {
			tagValue := gjson.Get(tag.String(), "TagValue").String()
			elements := map[string]attr.Value{
				tagKey: types.StringValue(tagValue),
			}
			policyTemplateTagMap, d := types.MapValueFrom(ctx, types.StringType, elements)
			if d.HasError() {
				diags.Append(d...)
				return
			}
			state.PolicyTemplateTag = policyTemplateTagMap
			break
		}
	}
}

func setKeyTags(ctx context.Context, response string, plan *AWSKeyTFSDK, includePolicyTag bool, diags *diag.Diagnostics) {
	elements := make(map[string]string)
	for _, tag := range gjson.Get(response, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != PolicyTemplateTagKey {
			elements[tagKey] = tagValue
		} else if includePolicyTag {
			elements[tagKey] = tagValue
		}
	}
	var d diag.Diagnostics
	plan.Tags, d = types.MapValueFrom(ctx, types.StringType, elements)
	if d.HasError() {
		diags.Append(d...)
		return
	}
}

func setKeyLabels(ctx context.Context, response string, state *AWSKeyTFSDK, diags *diag.Diagnostics) {
	elements := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &elements); err != nil {
			msg := "Error unmarshaling 'ciphertrust_aws_key' labels."
			details := map[string]interface{}{"key_id": state.ID, "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return
		}
	}
	var d diag.Diagnostics
	state.Labels, d = types.MapValueFrom(ctx, types.StringType, elements)
	if d.HasError() {
		diags.Append(d...)
		return
	}
}

func setMultiRegionConfiguration(ctx context.Context, keyJSON string, state *AWSKeyTFSDK, diags *diag.Diagnostics) {
	primaryKeyJSON := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey")
	element := make(map[string]string)
	if len(primaryKeyJSON.Raw) != 0 {
		element["arn"] = gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()
		element["region"] = gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	}
	var d diag.Diagnostics
	state.MultiRegionPrimaryKey, d = types.MapValueFrom(ctx, types.StringType, element)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	replicaKeysJSON := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array()
	var replicaKeys basetypes.ListValue
	var elements []map[string]string
	for _, replicaKeyJSON := range replicaKeysJSON {
		element = map[string]string{
			"arn":    gjson.Get(replicaKeyJSON.Raw, "Arn").String(),
			"region": gjson.Get(replicaKeyJSON.Raw, "Region").String(),
		}
		elements = append(elements, element)
	}
	replicaKeys, d = types.ListValueFrom(ctx, types.MapType{ElemType: types.StringType}, elements)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	state.MultiRegionReplicaKeys, d = replicaKeys.ToListValue(ctx)
	if d.HasError() {
		diags.Append(d...)
		return
	}
}

func (r *resourceAWSKey) getPrimaryKeyID(ctx context.Context, uid string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> getPrimaryKeyID]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> getPrimaryKeyID]["+uid+"]")
	keyID := plan.KeyID.ValueString()
	response, err := r.client.GetById(ctx, uid, keyID, AWSKeysURL)
	if err != nil {
		msg := "Failed get primary key ID of 'ciphertrust_aws_key' " + keyID + ", error reading key."
		tflog.Error(ctx, msg, map[string]interface{}{"error": err.Error()})
		diags.AddError(msg, err.Error())
		return ""
	}
	primaryKeyRegion := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	primaryKeyARN := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()
	primaryKeyArnParts := strings.Split(primaryKeyARN, ":")
	if len(primaryKeyArnParts) != 6 {
		msg := "Failed get primary key of 'ciphertrust_aws_key', unexpected ARN format."
		details := map[string]interface{}{"key_id": keyID, "arn": primaryKeyARN}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	kidParts := strings.Split(primaryKeyArnParts[5], "/")
	if len(kidParts) != 2 {
		msg := "Failed get primary key of 'ciphertrust_aws_key', unexpected ARN format."
		details := map[string]interface{}{"key_id": keyID, "arn": primaryKeyArnParts[5]}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	filters := url.Values{}
	filters.Add("keyid", kidParts[1])
	filters.Add("region", primaryKeyRegion)
	response, err = r.client.ListWithFilters(ctx, uid, AWSKeysURL, filters)
	if err != nil {
		msg := "Failed to list 'ciphertrust_aws_key'."
		details := map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total != 1 {
		msg := "Failed list key, error listing single key."
		details := map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion}
		tflog.Error(ctx, msg, details)
		diags.AddError(msg, apiDetail(details))
	}
	resources := gjson.Get(response, "resources").Array()
	var primaryKeyID string
	for _, keyResourceJSON := range resources {
		primaryKeyID = gjson.Get(keyResourceJSON.Raw, "id").String()
	}
	return primaryKeyID
}

func (r *resourceAWSKey) createKeyMaterial(ctx context.Context, uid string, importMaterialPlan *AWSKeyImportKeyMaterialTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> createKeyMaterial]["+uid+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> createKeyMaterial]["+uid+"]")
	var response string
	if importMaterialPlan.SourceKeyTier.ValueString() == "local" {
		payload := cm.CMKeyJSON{
			Name:      importMaterialPlan.SourceKeyName.ValueString(),
			Algorithm: "AES",
			Size:      256,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error creating 'ciphertrust_aws_key'. Failed to create 'ciphertrust_cm_key', error marshaling payload."
			details := map[string]interface{}{"payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		response, err = r.client.PostDataV2(ctx, uid, common.URL_KEY_MANAGEMENT, payloadJSON)
		if err != nil {
			msg := "Error creating 'ciphertrust_aws_key'. Failed to create 'ciphertrust_cm_key', error posting payload."
			details := map[string]interface{}{"payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
			tflog.Error(ctx, msg, details)
			diags.AddError(msg, apiDetail(details))
			return ""
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> createKeyMaterial][response:"+response)
	}
	return response
}

func apiDetail(details map[string]interface{}) string {
	str := ""
	for k, v := range details {
		if len(str) == 0 {
			str = fmt.Sprintf("%v:%v", k, v)
		} else {
			str = str + fmt.Sprintf(", %v:%v", k, v)
		}
	}
	return str
}
