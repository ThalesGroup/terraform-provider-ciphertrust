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

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
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
	_           resource.Resource              = &resourceAWSKey{}
	_           resource.ResourceWithConfigure = &resourceAWSKey{}
	awsKeySpecs                                = []string{"SYMMETRIC_DEFAULT",
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
		"HMAC_512"}
)

const (
	policyTemplateTagKey      = "cckm_policy_template_id"
	longAwsKeyOpSleep         = 20
	shortAwsKeyOpSleep        = 5
	awsValidToRegEx           = `^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$`
	awsValidToFormatMsg       = "must conform to the following example 2027-07-03T14:24:00Z"
	refreshTokenSeconds       = 20
	cckmSyncAutoRotationDelay = 5
	disabledKeyException      = "DisabledException"
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
				Computed:    true,
				Description: "AWS region and AWS key identifier separated by a backslash.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "AWS region in which to create the AWS key.",
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
				Description: "Enable AWS autorotation of the key. Auto-Rotation only is only applicable to native symmetric keys.",
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
				Description: "Whether the KMS key contains a symmetric key or an asymmetric key pair. Valid values: " + strings.Join(awsKeySpecs, ", ") + ". Default is SYMMETRIC_DEFAULT.",
				Validators:  []validator.String{stringvalidator.OneOf(awsKeySpecs...)},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description of the AWS key. Descriptions can be updated but not removed.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"enable_key": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Enable or disable the key. Default is true.",
			},
			"key_usage": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Specifies the intended use of the key. Options are ENCRYPT_DECRYPT, SIGN_VERIFY and GENERATE_VERIFY_MAC." +
					"Default for RSA keys is ENCRYPT_DECRYPT," +
					"default for EC keys is SIGN_VERIFY, " +
					"default for symmetric keys is ENCRYPT_DECRYPT and " +
					"default for HMAC keys is GENERATE_VERIFY_MAC.",
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
				Validators:  []validator.String{stringvalidator.OneOf([]string{"AWS_KMS", "EXTERNAL"}...)},
			},
			"primary_region": schema.StringAttribute{
				Optional:    true,
				Description: "Updates the primary region of a multi-region key.",
			},
			"schedule_for_deletion_days": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Waiting period after the key is destroyed before the key is deleted. Only relevant when the resource is destroyed. Default is 7.",
				Default:     int64default.StaticInt64(7),
				Validators: []validator.Int64{
					int64validator.AtLeast(7),
				},
			},
			"tags": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				Description: "A list of tags assigned to the AWS key.",
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
				Computed:    true,
				Description: "CipherTrust Manager Key ID.",
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
						"external_accounts": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Other AWS accounts that can access to the key.",
						},
						"key_admins": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key administrators - users.",
						},
						"key_admins_roles": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key administrators - roles.",
						},
						"key_users": schema.SetAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Key users - users.",
						},
						"key_users_roles": schema.SetAttribute{
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
							Description: "CipherTrust Manager policy template ID",
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
							Description: "CipherTrust Manager key ID of the key to replicate.",
						},
						"import_key_material": schema.BoolAttribute{
							Optional:    true,
							Description: "Import primary key material to the replicated key. Applies to external AWS keys.",
						},
						"key_expiration": schema.BoolAttribute{
							Optional:    true,
							Description: "Enable key expiration of the replicated key. Applies to external AWS keys.",
						},
						"make_primary": schema.BoolAttribute{
							Optional:    true,
							Description: "Update the primary key region to the replicated key's region following replication.",
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date the key material of the replicated key expires. Applies to external AWS keys. Set as UTC time in RFC3339 format. For example, 2027-07-03T14:24:00Z.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(awsValidToRegEx), awsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"upload_key": schema.ListNestedBlock{
				Description: "Key material from the 'source_key_tier' will be uploaded to an external AWS key.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"source_key_identifier": schema.StringAttribute{
							Required:    true,
							Description: "CipherTrust Manager key ID to upload to AWS.",
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
							Description: "Source of the key material. Current option is 'local' implying a CipherTrust Manager key. Default is 'local'.",
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date of key expiry in UTC time in RFC3339 format. For example, 2027-07-03T14:24:00Z. Only valid if 'key_expiration' is true.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(awsValidToRegEx), awsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"import_key_material": schema.ListNestedBlock{
				Description: "Both a 'source_key_tier' key and an AWS external key will be created. Key material from the 'source_key_tier' key will be imported to the AWS key." +
					"The 'source_key_tier' key will not be deleted on Terraform destroy. An alternative is to use 'upload_key' parameter.",
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
							Description: "Source of the key material. Current option is 'local' implying a CipherTrust Manager key. Default is 'local'.",
						},
						"key_expiration": schema.BoolAttribute{
							Computed:    true,
							Optional:    true,
							Description: "Enable key material expiration. Default is false.",
							Default:     booldefault.StaticBool(false),
						},
						"valid_to": schema.StringAttribute{
							Optional:    true,
							Description: "Date of key material expiry in UTC time in RFC3339 format. For example, 2027-07-03T14:24:00Z.",
							Validators: []validator.String{
								stringvalidator.RegexMatches(
									regexp.MustCompile(awsValidToRegEx), awsValidToFormatMsg,
								),
							},
						},
					},
				},
			},
			"enable_rotation": schema.ListNestedBlock{
				Description: "Enable the key for scheduled rotation job. Parameters 'disable_encrypt' and 'disable_encrypt_on_all_accounts' are mutually exclusive",
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
							Validators:  []validator.String{stringvalidator.OneOf([]string{"ciphertrust"}...)},
						},
						"disable_encrypt": schema.BoolAttribute{
							Optional:    true,
							Description: "Disable encryption on the old key.",
						},
						"disable_encrypt_on_all_accounts": schema.BoolAttribute{
							Optional:    true,
							Description: "Disable encryption permissions on the old key for all the accounts",
						},
					},
				},
			},
		},
	}
}

func (r *resourceAWSKey) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Create]["+id+"]")
	var (
		plan     AWSKeyTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if len(plan.ImportKeyMaterial.Elements()) != 0 {
		response = r.importKeyMaterial(ctx, id, &plan, &resp.Diagnostics)
	} else if len(plan.UploadKey.Elements()) != 0 {
		response = r.uploadKey(ctx, id, &plan, &resp.Diagnostics)
	} else if len(plan.ReplicateKey.Elements()) != 0 {
		response = r.replicateKey(ctx, id, &plan, &resp.Diagnostics)
	} else {
		response = r.createKey(ctx, id, &plan, &resp.Diagnostics)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	kid := gjson.Get(response, "aws_param.KeyID").String()
	region := gjson.Get(response, "region").String()
	plan.ID = types.StringValue(encodeAWSKeyTerraformResourceID(region, kid))

	// Don't return errors after this
	plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
	if len(plan.Alias.Elements()) > 1 {
		var diags diag.Diagnostics
		addAliases(ctx, r.client, id, &plan.AWSKeyCommonTFSDK, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if plan.AutoRotate.ValueBool() {
		var diags diag.Diagnostics
		r.enableDisableAutoRotation(ctx, id, &plan, response, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if len(plan.EnableRotation.Elements()) != 0 {
		var diags diag.Diagnostics
		enableKeyRotationJob(ctx, id, r.client, &plan.AWSKeyCommonTFSDK, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
	if !plan.EnableKey.IsUnknown() && !plan.EnableKey.ValueBool() {
		var diags diag.Diagnostics
		keyID := gjson.Get(response, "id").String()
		disableKey(ctx, id, r.client, keyID, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}
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
	tflog.Trace(ctx, "[resource_aws_key.go -> Create][response:"+response)
}

func (r *resourceAWSKey) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Read]["+id+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
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
	tflog.Trace(ctx, "[resource_aws_key.go -> Read][response:"+response)
}

func (r *resourceAWSKey) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Update]["+id+"]")
	var (
		plan  AWSKeyTFSDK
		state AWSKeyTFSDK
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
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS key, failed to read key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	keyEnabled := gjson.Get(response, "aws_param.Enabled").Bool()
	planEnableKey := plan.EnableKey.ValueBool()
	if !keyEnabled && planEnableKey {
		enableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	updateAwsKeyCommon(ctx, id, r.client, &plan.AWSKeyCommonTFSDK, &state.AWSKeyCommonTFSDK, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	updateAliases(ctx, id, r.client, &plan.AWSKeyCommonTFSDK, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	planTags := make(map[string]string, len(plan.Tags.Elements()))
	if len(plan.Tags.Elements()) != 0 {
		resp.Diagnostics.Append(plan.Tags.ElementsAs(ctx, &planTags, false)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	updateTags(ctx, id, r.client, planTags, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.enableDisableAutoRotation(ctx, id, &plan, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.PrimaryRegion.IsNull() && plan.PrimaryRegion != state.PrimaryRegion {
		newPrimaryRegion := plan.PrimaryRegion.ValueString()
		primaryKeyJSON := r.getPrimaryKey(ctx, id, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		primaryKeyID := gjson.Get(primaryKeyJSON, "id").String()
		primaryKeyRegion := gjson.Get(primaryKeyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
		if primaryKeyRegion != newPrimaryRegion {
			r.updatePrimaryRegion(ctx, id, primaryKeyID, newPrimaryRegion, &resp.Diagnostics)
			if resp.Diagnostics.HasError() {
				return
			}
		} else {
			resp.Diagnostics.AddWarning("'primary_region' specifies the current primary region", "")
		}
	}
	if keyEnabled && !planEnableKey {
		disableKey(ctx, id, r.client, keyID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS key, failed to read key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
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
	tflog.Trace(ctx, "[resource_aws_key.go -> Update][response:"+response)
}

func updateAwsKeyCommon(ctx context.Context, id string, client *common.Client, plan *AWSKeyCommonTFSDK, state *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	updateDescription(ctx, id, client, plan, keyJSON, diags)
	if diags.HasError() {
		return
	}
	updateKeyPolicy(ctx, id, client, plan, state, diags)
	if diags.HasError() {
		return
	}
	enableDisableKeyRotation(ctx, id, client, plan, state, diags)
	if diags.HasError() {
		return
	}
}

func (r *resourceAWSKey) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> Delete]["+id+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	keyState := gjson.Get(response, "aws_param.KeyState").String()
	if keyState == "PendingDeletion" || keyState == "PendingReplicaDeletion" {
		msg := "AWS key is already pending deletion, it will be removed from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}
	removeKeyPolicyTemplateTag(ctx, id, r.client, response, &resp.Diagnostics)
	payload := ScheduleForDeletionJSON{
		Days: state.ScheduleForDeletionDays.ValueInt64(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error deleting AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
	if err != nil {
		msg := "Error deleting AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		if strings.Contains(err.Error(), "is pending deletion") {
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
		} else {
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
		}
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> Delete][response:"+response)
}

func (r *resourceAWSKey) createKey(ctx context.Context, id string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> createKey]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> createKey]["+id+"]")
	awsParam := r.getAWSParam(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams := r.getAWSKeyCreateParams(ctx, &plan.AWSKeyCommonTFSDK, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams.KMS = plan.KMS.ValueString()
	payload := CreateAWSKeyPayloadJSON{
		CommonAWSKeyCreatePayloadJSON: *keyCreateParams,
		AWSParam:                      *awsParam,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY, payloadJSON)
	if err != nil {
		msg := "Error creating AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> createKey][response:"+response)
	return response
}

func (r *resourceAWSKey) setKeyState(ctx context.Context, response string, state *AWSKeyTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, "[resource_aws_key.go -> setKeyState][response:"+response)
	setCommonKeyState(response, &state.AWSKeyCommonTFSDK, diags)
	setCommonKeyStateEx(ctx, response, &state.AWSKeyCommonTFSDK, diags)
	state.AutoRotate = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	state.AutoRotationPeriodInDays = types.Int64Value(gjson.Get(response, "aws_param.RotationPeriodInDays").Int())
	state.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	state.MultiRegionKeyType = types.StringValue(gjson.Get(response, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String())
	setMultiRegionConfiguration(ctx, response, &state.MultiRegionPrimaryKey, &state.MultiRegionReplicaKeys, diags)
	state.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
	state.ReplicaPolicy = types.StringValue(gjson.Get(response, "replica_policy").String())
}

func setCommonKeyState(response string, state *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
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
	state.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	state.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	state.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	state.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	state.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	state.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	state.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())
}

func setCommonKeyStateEx(ctx context.Context, response string, state *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	setAliases(response, &state.Alias, diags)
	setKeyLabels(ctx, response, state.KeyID.ValueString(), &state.Labels, diags)
	setKeyTags(ctx, response, &state.Tags, diags)
	state.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	state.EnableKey = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	state.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	policy := gjson.Get(response, "aws_param.Policy").String()
	if !getPoliciesAreEqual(ctx, policy, state.Policy.ValueString(), diags) {
		state.Policy = types.StringValue(policy)
	}
	setPolicyTemplateTag(ctx, response, &state.PolicyTemplateTag, diags)
}

func (r *resourceAWSKey) enableDisableAutoRotation(ctx context.Context, id string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableAutoRotation]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableAutoRotation]["+id+"]")
	var (
		err      error
		response string
	)
	planAutoRotateEnabled := plan.AutoRotate.ValueBool()
	planDays := plan.AutoRotationPeriodInDays.ValueInt64()
	keyAutoRotateEnabled := gjson.Get(keyJSON, "aws_param.KeyRotationEnabled").Bool()
	keyDays := gjson.Get(keyJSON, "aws_param.RotationPeriodInDays").Int()
	keyID := plan.KeyID.ValueString()
	updated := false
	if planAutoRotateEnabled {
		if keyAutoRotateEnabled != planAutoRotateEnabled || planDays != keyDays {
			updated = r.enableAutoRotation(ctx, id, plan, keyJSON, diags)
			if diags.HasError() {
				return
			}
		}
	} else if keyAutoRotateEnabled != planAutoRotateEnabled {
		updated = r.disableAutoRotation(ctx, id, plan, keyJSON, diags)
		if diags.HasError() {
			return
		}
	}
	if updated {
		keyAutoRotateEnabled = gjson.Get(response, "aws_param.KeyRotationEnabled").Bool()
		keyDays = gjson.Get(response, "aws_param.RotationPeriodInDays").Int()
		if keyAutoRotateEnabled != planAutoRotateEnabled || keyDays != planDays {
			time.Sleep(time.Duration(cckmSyncAutoRotationDelay+2) * time.Second)
			response, err = r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
			if err != nil {
				msg := "Error enabling/disabling auto-rotation for AWS key, error reading key."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			keyAutoRotateEnabled = gjson.Get(response, "aws_param.KeyRotationEnabled").Bool()
			keyDays = gjson.Get(response, "aws_param.RotationPeriodInDays").Int()
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> enableDisableAutoRotation][response:"+response)
	}
	if keyAutoRotateEnabled != planAutoRotateEnabled || keyDays != planDays {
		msg := "Failed to confirm auto-rotation is configured."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		diags.AddWarning(details, "")
	}
}

func (r *resourceAWSKey) enableAutoRotation(ctx context.Context, id string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) bool {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableAutoRotation]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableAutoRotation]["+id+"]")
	planDays := plan.AutoRotationPeriodInDays.ValueInt64()
	keyEnabled := gjson.Get(keyJSON, "aws_param.Enabled").Bool()
	keyID := plan.KeyID.ValueString()
	payload := EnableAutoRotationPayloadJSON{
		RotationPeriodInDays: &planDays,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error enabling auto-rotation for AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return false
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable-auto-rotation", payloadJSON)
	if err != nil {
		if strings.Contains(err.Error(), disabledKeyException) && keyEnabled {
			numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / shortAwsKeyOpSleep)
			tStart := time.Now()
			for retry := 0; retry < numRetries && err != nil; retry++ {
				time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
				if time.Since(tStart).Seconds() > refreshTokenSeconds {
					if err = r.client.RefreshToken(ctx, id); err != nil {
						msg := "Error disabling auto-rotation for AWS key. Error refreshing authentication token."
						details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
						tflog.Error(ctx, details)
						diags.AddError(details, "")
						return false
					}
					tStart = time.Now()
				}
				_, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable-auto-rotation", payloadJSON)
			}
		}
		if err != nil {
			msg := "Error enabling auto-rotation for AWS key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			diags.AddError(details, "")
			tflog.Error(ctx, details)
			return false
		}
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> enableAutoRotation][response:"+response)
	return true
}

func (r *resourceAWSKey) disableAutoRotation(ctx context.Context, id string, plan *AWSKeyTFSDK, keyJSON string, diags *diag.Diagnostics) bool {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> disableAutoRotation]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> disableAutoRotation]["+id+"]")
	keyEnabled := gjson.Get(keyJSON, "aws_param.Enabled").Bool()
	keyID := plan.KeyID.ValueString()
	response, err := r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable-auto-rotation")
	if err != nil {
		if strings.Contains(err.Error(), disabledKeyException) && keyEnabled {
			numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / shortAwsKeyOpSleep)
			tStart := time.Now()
			for retry := 0; retry < numRetries && err != nil; retry++ {
				time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
				if time.Since(tStart).Seconds() > refreshTokenSeconds {
					if err = r.client.RefreshToken(ctx, id); err != nil {
						msg := "Error disabling auto-rotation for AWS key. Error refreshing authentication token."
						details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
						tflog.Error(ctx, details)
						diags.AddError(details, "")
						return false
					}
					tStart = time.Now()
				}
				response, err = r.client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable-auto-rotation")
			}
		}
		if err != nil {
			msg := "Error disabling auto-rotation for AWS key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			diags.AddError(details, "")
			tflog.Error(ctx, details)
			return false
		}
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> disableAutoRotation][response:"+response)
	return true
}

func enableKeyRotationJob(ctx context.Context, id string, client *common.Client, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableKeyRotationJob]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableKeyRotationJob]["+id+"]")
	rotationParams := make([]AWSKeyEnableRotationTFSDK, 0, len(plan.EnableRotation.Elements()))
	if !plan.EnableRotation.IsUnknown() {
		diags.Append(plan.EnableRotation.ElementsAs(ctx, &rotationParams, false)...)
		if diags.HasError() {
			return
		}
	}
	for _, params := range rotationParams {
		payload := AWSEnableKeyRotationJobPayloadJSON{
			JobConfigID:                           params.JobConfigID.ValueString(),
			AutoRotateDisableEncrypt:              params.AutoRotateDisableEncrypt.ValueBool(),
			AutoRotateDisableEncryptOnAllAccounts: params.AutoRotateDisableEncryptOnAllAccounts.ValueBool(),
		}
		if params.AutoRotateKeySource.ValueString() != "" {
			payload.AutoRotateKeySource = params.AutoRotateKeySource.ValueStringPointer()
		}
		keyID := plan.KeyID.ValueString()
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Failed to enable key rotation for AWS key, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable-rotation-job", payloadJSON)
		if err != nil {
			msg := "Failed to enable key rotation for AWS key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> enableKeyRotationJob][response:"+response)
	}
}

func disableKeyRotationJob(ctx context.Context, id string, client *common.Client, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> disableKeyRotationJob]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> disableKeyRotationJob]["+id+"]")
	keyID := plan.KeyID.ValueString()
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable-rotation-job")
	if err != nil {
		msg := "Error updating AWS key, failed to disable key rotation job for AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> disableKeyRotationJob][response:"+response)
}

func (r *resourceAWSKey) importKeyMaterial(ctx context.Context, id string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> importKeyMaterial]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> importKeyMaterial]["+id+"]")
	var importMaterialPlan AWSKeyImportKeyMaterialTFSDK
	for _, v := range plan.ImportKeyMaterial.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, v, &importMaterialPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	if plan.Origin.ValueString() == "" {
		plan.Origin = types.StringValue("EXTERNAL")
	}
	customerMasterKeySpec := plan.CustomerMasterKeySpec.ValueString()
	response := r.createKey(ctx, id, plan, diags)
	if diags.HasError() {
		return ""
	}
	awsKeyResponse := response
	// Don't return errors after this
	keyID := gjson.Get(response, "id").String()
	var dg diag.Diagnostics
	sourceKeyJSON := r.createKeyMaterial(ctx, id, &importMaterialPlan, customerMasterKeySpec, &dg)
	if dg.HasError() {
		for _, d := range dg {
			diags.AddWarning(d.Summary(), d.Detail())
		}
		return awsKeyResponse
	}
	sourceKeyID := gjson.Get(sourceKeyJSON, "id").String()
	payload := AWSKeyImportKeyPayloadJSON{
		SourceKeyID:   sourceKeyID,
		SourceKeyTier: importMaterialPlan.SourceKeyTier.ValueString(),
		KeyExpiration: importMaterialPlan.KeyExpiration.ValueBool(),
		ValidTo:       importMaterialPlan.ValidTo.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key. Failed to import key material, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddWarning(details, "")
		return awsKeyResponse
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/import-material", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to import key material."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddWarning(details, "")
		return awsKeyResponse
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> importKeyMaterial][response:"+response)
	return response
}

func (r *resourceAWSKey) uploadKey(ctx context.Context, id string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> UploadKeyAWS]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> UploadKeyAWS]["+id+"]")
	if plan.Origin.ValueString() == "" {
		plan.Origin = types.StringValue("EXTERNAL")
	}
	keyCreateParams := r.getAWSKeyCreateParams(ctx, &plan.AWSKeyCommonTFSDK, diags)
	if diags.HasError() {
		return ""
	}
	keyCreateParams.KMS = plan.KMS.ValueString()
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
		CommonAWSKeyCreatePayloadJSON: *keyCreateParams,
		SourceKeyIdentifier:           uploadKeyPlan.SourceKeyID.ValueString(),
		SourceKeyTier:                 uploadKeyPlan.SourceKeyTier.ValueString(),
		KeyExpiration:                 uploadKeyPlan.KeyExpiration.ValueBool(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key. Failed to upload, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, "api/v1/cckm/aws/upload-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to upload key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> uploadKey][response:"+response)
	return response
}

func (r *resourceAWSKey) replicateKey(ctx context.Context, id string, plan *AWSKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> replicateKey]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> replicateKey]["+id+"]")
	var replicateKeyPlan AWSReplicateKeyTFSDK
	for _, v := range plan.ReplicateKey.Elements() {
		diags.Append(tfsdk.ValueAs(ctx, v, &replicateKeyPlan)...)
		if diags.HasError() {
			return ""
		}
	}
	response := r.replicateAwsKey(ctx, id, plan, &replicateKeyPlan, diags)
	if diags.HasError() {
		return ""
	}
	// Don't return errors after this
	replicaKeyID := gjson.Get(response, "id").String()
	var dg diag.Diagnostics
	r.waitForReplication(ctx, id, replicaKeyID, &dg)
	for _, d := range dg {
		diags.AddWarning(d.Summary(), d.Detail())
	}
	if replicateKeyPlan.ImportKeyMaterial.ValueBool() {
		var dg diag.Diagnostics
		replicaRegion := plan.Region.ValueString()
		r.importKeyMaterialToReplica(ctx, id, &replicateKeyPlan, replicaKeyID, replicaRegion, &dg)
		for _, d := range dg {
			diags.AddWarning(d.Summary(), d.Detail())
		}
	}
	primaryKeyID := replicateKeyPlan.KeyID.ValueString()
	replicaRegion := plan.Region.ValueString()
	if replicateKeyPlan.MakePrimary.ValueBool() {
		var dg diag.Diagnostics
		r.updatePrimaryRegion(ctx, id, primaryKeyID, replicaRegion, &dg)
		for _, d := range dg {
			diags.AddWarning(d.Summary(), d.Detail())
		}
	}
	response, err := r.client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error creating AWS key, failed to read replicated key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddWarning(details, "")
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> replicateKey][response:"+response)
	return response
}

func (r *resourceAWSKey) replicateAwsKey(ctx context.Context, id string, plan *AWSKeyTFSDK, replicateKeyPlan *AWSReplicateKeyTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> replicateAwsKey]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> replicateAwsKey]["+id+"]")
	replicaRegion := plan.Region.ValueString()
	awsParam := r.getAWSParam(ctx, plan, diags)
	if diags.HasError() {
		return ""
	}
	keyPolicy := getKeyPolicyPayloadJSON(ctx, &plan.AWSKeyCommonTFSDK, diags)
	if diags.HasError() {
		return ""
	}
	payload := CreateReplicaKeyPayloadJSON{
		AWSParams:        *awsParam,
		ExternalAccounts: keyPolicy.ExternalAccounts,
		KeyAdmins:        keyPolicy.KeyAdmins,
		KeyAdminsRoles:   keyPolicy.KeyAdminsRoles,
		KeyUsers:         keyPolicy.KeyUsers,
		KeyUsersRoles:    keyPolicy.KeyUsersRoles,
		PolicyTemplate:   keyPolicy.PolicyTemplate,
		ReplicaRegion:    &replicaRegion,
	}
	primaryKeyID := replicateKeyPlan.KeyID.ValueString()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS key. Failed to replicate key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/replicate-key", payloadJSON)
	if err != nil {
		msg := "Error creating AWS key, failed to replicate key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> replicateAwsKey][response:"+response)
	return response
}

func (r *resourceAWSKey) waitForReplication(ctx context.Context, id string, replicaKeyID string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> waitForReplication]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> waitForReplication]["+id+"]")
	var (
		err      error
		response string
	)
	keyState := "Creating"
	numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / longAwsKeyOpSleep)
	tStart := time.Now()
	for retry := 0; retry < numRetries && keyState == "Creating"; retry++ {
		time.Sleep(time.Duration(longAwsKeyOpSleep) * time.Second)
		if time.Since(tStart).Seconds() > refreshTokenSeconds {
			if err = r.client.RefreshToken(ctx, id); err != nil {
				msg := "Error creating AWS key. Error refreshing authentication token while waiting for key replication."
				details := utils.ApiError(msg, map[string]interface{}{
					"error":          err.Error(),
					"replica_key_id": replicaKeyID,
				})
				tflog.Error(ctx, details)
				diags.AddWarning(details, "")
				return ""
			}
			tStart = time.Now()
		}
		response, err = r.client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error creating AWS key. Error reading replicated key."
			details := utils.ApiError(msg, map[string]interface{}{
				"error":          err.Error(),
				"replica_key_id": replicaKeyID,
			})
			tflog.Error(ctx, details)
			diags.AddWarning(details, "")
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
	}
	tStart = time.Now()
	for retry := 0; retry < numRetries && keyState != "Enabled"; retry++ {
		time.Sleep(time.Duration(longAwsKeyOpSleep) * time.Second)
		if time.Since(tStart).Seconds() > refreshTokenSeconds {
			if err = r.client.RefreshToken(ctx, id); err != nil {
				msg := "Error replicating AWS key. Error refreshing authentication token."
				details := utils.ApiError(msg, map[string]interface{}{
					"error":          err.Error(),
					"replica_key_id": replicaKeyID,
				})
				tflog.Error(ctx, details)
				diags.AddWarning(details, "")
				return ""
			}
		}
		response, err = r.client.GetById(ctx, id, replicaKeyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error creating AWS key. Error reading replicated key."
			details := utils.ApiError(msg, map[string]interface{}{
				"error":          err.Error(),
				"replica_key_id": replicaKeyID,
			})
			tflog.Error(ctx, details)
			diags.AddWarning(details, "")
			return ""
		}
		keyState = gjson.Get(response, "aws_param.KeyState").String()
	}
	if keyState != "Enabled" {
		msg := "Error creating AWS key, failed to confirm replicated AWS key has been enabled in the given time. Consider extending provider configuration option 'aws_operation_timeout'."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": replicaKeyID})
		tflog.Warn(ctx, details)
		diags.AddWarning(details, "")
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> replicateKey][response:"+response)
	return response
}

func (r *resourceAWSKey) importKeyMaterialToReplica(ctx context.Context, id string, replicateKeyPlan *AWSReplicateKeyTFSDK, replicaKeyID string, replicaRegion string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> importKeyMaterialToReplica]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> importKeyMaterialToReplica]["+id+"]")
	primaryKeyID := replicateKeyPlan.KeyID.ValueString()
	response, err := r.client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error replicating AWS key. Error reading primary key."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	origin := gjson.Get(response, "aws_param.Origin").String()
	if origin == "AWS_KMS" {
		msg := "Error replicating AWS key. 'replicate_key.import_key_material' is invalid for the primary key."
		details := utils.ApiError(msg, map[string]interface{}{
			"origin":         origin,
			"primary_key_id": primaryKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	payload := AWSKeyImportKeyPayloadJSON{
		SourceKeyID:   gjson.Get(response, "local_key_id").String(),
		SourceKeyTier: gjson.Get(response, "key_source").String(),
		KeyExpiration: replicateKeyPlan.KeyExpiration.ValueBool(),
		ValidTo:       replicateKeyPlan.ValidTo.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error replicating AWS key. Failed to import key material, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+replicaKeyID+"/import-material", payloadJSON)
	if err != nil {
		msg := "Error replicating AWS key, failed to import key material."
		details := utils.ApiError(msg, map[string]interface{}{
			"error":          err.Error(),
			"primary_key_id": primaryKeyID,
			"replica_key_id": replicaKeyID,
			"region":         replicaRegion,
		})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> importKeyMaterialToReplica][response:"+response)
}

func (r *resourceAWSKey) updatePrimaryRegion(ctx context.Context, id string, primaryKeyID string, newPrimaryRegion string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updatePrimaryRegion]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updatePrimaryRegion]["+id+"]")
	response, err := r.client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error updating AWS key, failed to read key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": primaryKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
	}
	currentPrimaryRegion := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	payload := UpdatePrimaryRegionPayloadJSON{
		PrimaryRegion: &newPrimaryRegion,
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating primary region, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "primary key_id": primaryKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+primaryKeyID+"/update-primary-region", payloadJSON)
	if err != nil {
		msg := "Error updating primary region."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "primary key_id": primaryKeyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	numRetries := int(r.client.CCKMConfig.AwsOperationTimeout / shortAwsKeyOpSleep)
	tStart := time.Now()
	for retry := 0; retry < numRetries && currentPrimaryRegion != newPrimaryRegion; retry++ {
		time.Sleep(time.Duration(shortAwsKeyOpSleep) * time.Second)
		if time.Since(tStart).Seconds() > refreshTokenSeconds {
			if err = r.client.RefreshToken(ctx, id); err != nil {
				msg := "Error disabling auto-rotation for AWS key. Error refreshing authentication token."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": primaryKeyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			tStart = time.Now()
		}
		response, err = r.client.GetById(ctx, id, primaryKeyID, common.URL_AWS_KEY)
		if err != nil {
			msg := "Error updating AWS key, failed to read key."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": primaryKeyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		currentPrimaryRegion = gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	}
	if currentPrimaryRegion != newPrimaryRegion {
		msg := "Error updating AWS key. Failed to confirm primary region is set. Consider extending provider configuration option 'aws_operation_timeout'."
		details := utils.ApiError(msg, map[string]interface{}{
			"current primary region":    currentPrimaryRegion,
			"configured primary region": newPrimaryRegion,
		})
		tflog.Warn(ctx, details)
		diags.AddWarning(details, "")
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> updatePrimaryRegion][response:"+response)
}

func enableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableKey]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableKey]["+id+"]")
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/enable")
	if err != nil {
		msg := "Error enabling AWS key"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> enableKey][response:"+response)
}

func disableKey(ctx context.Context, id string, client *common.Client, keyID string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> disableKey]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> disableKey]["+id+"]")
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/disable")
	if err != nil {
		msg := "Error disabling AWS key"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> disableKey][response:"+response)
}

func addAliases(ctx context.Context, client *common.Client, id string, plan *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> addAliases]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> addAliases]["+id+"]")
	planAliases := make([]string, 0, len(plan.Alias.Elements()))
	diags.Append(plan.Alias.ElementsAs(ctx, &planAliases, false)...)
	if diags.HasError() {
		return
	}
	response := keyJSON
	keyID := plan.KeyID.ValueString()
	for i := 1; i < len(planAliases); i++ {
		alias := planAliases[i]
		payload := AddRemoveAliasPayloadJSON{
			Alias: alias,
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error creating AWS key. Failed to add alias, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/add-alias", payloadJSON)
		if err != nil {
			msg := "Error creating AWS key, failed to add alias."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> addAliases][response:"+response)
}

func updateAliases(ctx context.Context, id string, client *common.Client, plan *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateAliases]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateAliases]["+id+"]")
	var (
		keyAliases []string
		response   string
	)
	for _, a := range gjson.Get(keyJSON, "aws_param.Alias").Array() {
		alias := a.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		keyAliases = append(keyAliases, alias)
	}
	planAliases := make([]string, 0, len(plan.Alias.Elements()))
	if len(plan.Alias.Elements()) != 0 {
		diags.Append(plan.Alias.ElementsAs(ctx, &planAliases, false)...)
		if diags.HasError() {
			return
		}
	}
	keyID := plan.KeyID.ValueString()
	for _, planAlias := range planAliases {
		add := true
		for _, keyAlias := range keyAliases {
			if keyAlias == planAlias {
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
				msg := "Error updating AWS key. Failed to add alias, invalid data input."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			response, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/add-alias", payloadJSON)
			if err != nil {
				msg := "Error updating AWS key, failed to add alias."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			tflog.Trace(ctx, "[resource_aws_key.go -> updateAliases][response:"+response)
		}
	}

	// Remove aliases not in the plan but in the key
	for _, keyAlias := range keyAliases {
		if strings.Contains(keyAlias, "-rotated-") {
			// Dont delete these aliases
			continue
		}
		remove := true
		for _, planAlias := range planAliases {
			if planAlias == keyAlias {
				remove = false
				break
			}
		}
		if remove {
			payload := AddRemoveAliasPayloadJSON{
				Alias: keyAlias,
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				msg := "Error updating AWS key. Failed to remove alias, invalid data input."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			response, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/delete-alias", payloadJSON)
			if err != nil {
				msg := "Error updating AWS key, failed to remove alias."
				details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
				return
			}
			tflog.Trace(ctx, "[resource_aws_key.go -> updateAliases][response:"+response)
		}
	}
}

func updateDescription(ctx context.Context, id string, client *common.Client, plan *AWSKeyCommonTFSDK, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateDescription]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateDescription]["+id+"]")
	var (
		keyDescription  string
		planDescription string
	)
	if gjson.Get(keyJSON, "aws_param.Description").Exists() && gjson.Get(keyJSON, "aws_param.Description").String() != "" {
		keyDescription = gjson.Get(keyJSON, "aws_param.Description").String()
	}
	if !plan.Description.IsNull() && !plan.Description.IsUnknown() {
		planDescription = plan.Description.ValueString()
	}
	if planDescription == keyDescription {
		return
	}
	keyID := plan.KeyID.ValueString()
	payload := UpdateKeyDescriptionPayloadJSON{
		Description: plan.Description.ValueString(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating AWS key. Failed to update description, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/update-description", payloadJSON)
	if err != nil {
		msg := "Error updating AWS key, failed to update description."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> updateDescription][response:"+response)
}

func updateTags(ctx context.Context, id string, client *common.Client, planTags map[string]string, keyJSON string, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateTags]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateTags]["+id+"]")
	var (
		addTagsPayload    AddTagsJSON
		removeTagsPayload RemoveTagsJSON
	)
	keyID := gjson.Get(keyJSON, "id").String()
	keyTags := make(map[string]string)
	for _, tag := range gjson.Get(keyJSON, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != policyTemplateTagKey {
			keyTags[tagKey] = tagValue
		}
	}
	for keyTagKey, keyTagValue := range keyTags {
		found := false
		for planKey, planValue := range planTags {
			if planKey == keyTagKey && planValue == keyTagValue {
				found = true
				break
			}
		}
		if !found {
			t := keyTagKey
			removeTagsPayload.Tags = append(removeTagsPayload.Tags, &t)
		}
	}
	if len(removeTagsPayload.Tags) != 0 {
		payloadJSON, err := json.Marshal(removeTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to remove tags, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/remove-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to remove tags."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> updateTags][response:"+response)
	}
	for planKey, planValue := range planTags {
		found := false
		for keyTagKey, keyTagValue := range keyTags {
			if planKey == keyTagKey && planValue == keyTagValue {
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
			msg := "Error updating AWS key. Failed to add tags, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/add-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to add tags."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> updateTags][response:"+response)
	}
}

func updateKeyPolicy(ctx context.Context, id string, client *common.Client, plan *AWSKeyCommonTFSDK, state *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> updateKeyPolicy]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> updateKeyPolicy]["+id+"]")
	statePolicy := getKeyPolicyPayloadJSON(ctx, state, diags)
	if diags.HasError() {
		return
	}
	planPolicyPayload := getKeyPolicyPayloadJSON(ctx, plan, diags)
	if diags.HasError() {
		return
	}
	if keyPolicyHasChanged(planPolicyPayload, statePolicy) {
		keyID := plan.KeyID.ValueString()
		payloadJSON, err := json.Marshal(planPolicyPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to update key policy, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/policy", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to update key policy."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		plan.KeyID = types.StringValue(gjson.Get(response, "id").String())
		tflog.Trace(ctx, "[resource_aws_key.go -> updateKeyPolicy][response:"+response)
	}
}

func enableDisableKeyRotation(ctx context.Context, id string, client *common.Client, plan *AWSKeyCommonTFSDK, state *AWSKeyCommonTFSDK, diags *diag.Diagnostics) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> enableDisableKeyRotation]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> enableDisableKeyRotation]["+id+"]")
	planParams := make([]AWSKeyEnableRotationTFSDK, 0, len(plan.EnableRotation.Elements()))
	if !plan.EnableRotation.IsUnknown() {
		diags.Append(plan.EnableRotation.ElementsAs(ctx, &planParams, false)...)
		if diags.HasError() {
			return
		}
	}
	stateParams := make([]AWSKeyEnableRotationTFSDK, 0, len(state.EnableRotation.Elements()))
	diags.Append(state.EnableRotation.ElementsAs(ctx, &stateParams, false)...)
	if diags.HasError() {
		return
	}
	if len(planParams) == 0 && len(stateParams) != 0 {
		disableKeyRotationJob(ctx, id, client, plan, diags)
		if diags.HasError() {
			return
		}
	}
	if !reflect.DeepEqual(planParams, stateParams) {
		enableKeyRotationJob(ctx, id, client, plan, diags)
		if diags.HasError() {
			return
		}
	}
}

func (r *resourceAWSKey) getAWSParam(ctx context.Context, plan *AWSKeyTFSDK, diags *diag.Diagnostics) *AWSKeyParamJSON {
	commonAwsParams := r.getCommonAWSParams(ctx, plan, diags)
	if diags.HasError() {
		return nil
	}
	awsParam := AWSKeyParamJSON{
		CommonAWSParamsJSON: *commonAwsParams,
		Origin:              plan.Origin.ValueString(),
	}
	return &awsParam
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
		} else if awsParams.CustomerMasterKeySpec == "SYMMETRIC_DEFAULT" {
			awsParams.KeyUsage = "ENCRYPT_DECRYPT"
		}
	}
	if plan.MultiRegion.ValueBool() != types.BoolNull().ValueBool() {
		awsParams.MultiRegion = plan.MultiRegion.ValueBool()
	}
	if len(plan.Tags.Elements()) != 0 {
		tags := getTagsParam(ctx, &plan.AWSKeyCommonTFSDK, diags)
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

func (r *resourceAWSKey) getAWSKeyCreateParams(ctx context.Context, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) *CommonAWSKeyCreatePayloadJSON {
	var keyCreateParams CommonAWSKeyCreatePayloadJSON
	keyCreateParams.Region = plan.Region.ValueString()
	keyPolicyPlan := getKeyPolicyPayloadJSON(ctx, plan, diags)
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

func getTagsParam(ctx context.Context, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) []AWSKeyParamTagJSON {
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

func getKeyPolicyPayloadJSON(ctx context.Context, plan *AWSKeyCommonTFSDK, diags *diag.Diagnostics) *KeyPolicyPayloadJSON {
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
			if !kp.PolicyTemplate.IsNull() && len(kp.PolicyTemplate.ValueString()) != 0 {
				keyPolicy.PolicyTemplate = kp.PolicyTemplate.ValueStringPointer()
			}
			if !kp.Policy.IsNull() && len(kp.Policy.ValueString()) != 0 {
				policy := kp.Policy.ValueString()
				policyBytes := json.RawMessage([]byte(policy))
				keyPolicy.Policy = &policyBytes
			}
		}
	}
	return &keyPolicy
}

func setAliases(response string, stateAlias *types.Set, diags *diag.Diagnostics) {
	var aliases []attr.Value
	aliasesJSON := gjson.Get(response, "aws_param.Alias").Array()
	for _, item := range aliasesJSON {
		alias := item.String()
		if strings.Contains(alias, "alias/") {
			alias = alias[len("alias/"):]
		}
		aliases = append(aliases, types.StringValue(alias))
	}
	aliasSet, d := types.SetValue(types.StringType, aliases)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateAlias = aliasSet
}

func setPolicyTemplateTag(ctx context.Context, response string, statePolicyTemplateTag *types.Map, diags *diag.Diagnostics) {
	statePolicyTemplateTagMap := types.MapNull(types.StringType)
	tags := gjson.Get(response, "aws_param.Tags").Array()
	for _, tag := range tags {
		tagKey := gjson.Get(tag.String(), "TagKey").String()
		if tagKey == policyTemplateTagKey {
			tagValue := gjson.Get(tag.String(), "TagValue").String()
			elements := map[string]attr.Value{
				tagKey: types.StringValue(tagValue),
			}
			policyTemplateTagMap, d := types.MapValueFrom(ctx, types.StringType, elements)
			if d.HasError() {
				diags.Append(d...)
				return
			}
			statePolicyTemplateTagMap = policyTemplateTagMap
			break
		}
	}
	*statePolicyTemplateTag = statePolicyTemplateTagMap
}

func setKeyTags(ctx context.Context, response string, planTags *types.Map, diags *diag.Diagnostics) {
	tags := make(map[string]string)
	for _, tag := range gjson.Get(response, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		tagValue := gjson.Get(tag.Raw, "TagValue").String()
		if tagKey != policyTemplateTagKey {
			tags[tagKey] = tagValue
		}
	}
	tagMap, d := types.MapValueFrom(ctx, types.StringType, tags)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*planTags = tagMap
}

func setKeyLabels(ctx context.Context, response string, keyID string, stateLabels *types.Map, diags *diag.Diagnostics) {
	labels := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			msg := "Error setting state for key labels, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
	}
	labelMap, d := types.MapValueFrom(ctx, types.StringType, labels)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateLabels = labelMap
}

func setMultiRegionConfiguration(ctx context.Context, keyJSON string, stateMultiRegionPrimaryKey *types.Map, stateMultiRegionReplicaKeys *types.List, diags *diag.Diagnostics) {
	primaryKeyJSON := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey")
	primaryKey := make(map[string]string)
	if len(primaryKeyJSON.Raw) != 0 {
		primaryKey["arn"] = gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()
		primaryKey["region"] = gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	}
	stateMultiRegionPrimaryKeyMap, d := types.MapValueFrom(ctx, types.StringType, primaryKey)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateMultiRegionPrimaryKey = stateMultiRegionPrimaryKeyMap
	replicaKeysJSON := gjson.Get(keyJSON, "aws_param.MultiRegionConfiguration.ReplicaKeys").Array()
	var replicaKeys basetypes.ListValue
	var replicas []map[string]string
	for _, replicaKeyJSON := range replicaKeysJSON {
		primaryKey = map[string]string{
			"arn":    gjson.Get(replicaKeyJSON.Raw, "Arn").String(),
			"region": gjson.Get(replicaKeyJSON.Raw, "Region").String(),
		}
		replicas = append(replicas, primaryKey)
	}
	replicaKeys, d = types.ListValueFrom(ctx, types.MapType{ElemType: types.StringType}, replicas)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	stateMultiRegionReplicaKeysList, d := replicaKeys.ToListValue(ctx)
	if d.HasError() {
		diags.Append(d...)
		return
	}
	*stateMultiRegionReplicaKeys = stateMultiRegionReplicaKeysList
}

func (r *resourceAWSKey) getPrimaryKey(ctx context.Context, id string, keyID string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> getPrimaryKey]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> getPrimaryKey]["+id+"]")
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Failed get primary key ID of AWS key " + keyID + ", error reading key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	primaryKeyRegion := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Region").String()
	primaryKeyARN := gjson.Get(response, "aws_param.MultiRegionConfiguration.PrimaryKey.Arn").String()
	primaryKeyArnParts := strings.Split(primaryKeyARN, ":")
	if len(primaryKeyArnParts) != 6 {
		msg := "Failed get primary key of AWS key, unexpected primary key ARN format."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "arn": primaryKeyARN})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	kidParts := strings.Split(primaryKeyArnParts[5], "/")
	if len(kidParts) != 2 {
		msg := "Failed get primary key of AWS key, unexpected primary key  ARN format."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID, "arn": primaryKeyArnParts[5]})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	filters := url.Values{}
	filters.Add("keyid", kidParts[1])
	filters.Add("region", primaryKeyRegion)
	response, err = r.client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Error reading AWS primary key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kid": kidParts[1], "region": primaryKeyRegion})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total == 0 {
		msg := "Error reading AWS primary key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	if total != 1 {
		msg := "Error reading AWS primary key, failed to list just one key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kidParts[1], "region": primaryKeyRegion})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	resources := gjson.Get(response, "resources").Array()
	for _, keyResourceJSON := range resources {
		response = keyResourceJSON.Raw
	}
	tflog.Trace(ctx, "[resource_aws_key.go -> getPrimaryKey][response:"+response)
	return response
}

func (r *resourceAWSKey) createKeyMaterial(ctx context.Context, id string, importMaterialPlan *AWSKeyImportKeyMaterialTFSDK, customerMasterKeySpec string, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key.go -> createKeyMaterial]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key.go -> createKeyMaterial]["+id+"]")
	var response string
	if importMaterialPlan.SourceKeyTier.ValueString() == "local" || importMaterialPlan.SourceKeyTier.ValueString() == "" {
		payload := cm.CMKeyJSON{
			Name:              importMaterialPlan.SourceKeyName.ValueString(),
			AssignSelfAsOwner: true,
		}
		switch customerMasterKeySpec {
		case "SYMMETRIC_DEFAULT":
		case "":
			payload.Algorithm = "aes"
			payload.Size = 256
		case "RSA_2048":
			payload.Algorithm = "rsa"
			payload.Size = 2048
		case "RSA_3072":
			payload.Algorithm = "rsa"
			payload.Size = 3072
		case "RSA_4096":
			payload.Algorithm = "rsa"
			payload.Size = 4096
		case "ECC_NIST_P384":
			payload.Algorithm = "ec"
			payload.Curveid = "secp384r1"
		case "ECC_NIST_P521":
			payload.Algorithm = "ec"
			payload.Curveid = "secp521r1"
		case "ECC_SECG_P256K1":
			payload.Algorithm = "ec"
			payload.Curveid = "secp256k1"
		case "HMAC_256":
			payload.Algorithm = "hmac-sha256"
		case "HMAC_384":
			payload.Algorithm = "hmac-sha384"
		case "HMAC_512":
			payload.Algorithm = "hmac-sha512"
		default:
			msg := "Invalid 'customer_master_key_spec' for import key material from 'source_key_tier' of 'local'."
			details := utils.ApiError(msg, map[string]interface{}{"customer_master_key_spec": customerMasterKeySpec})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return ""
		}
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Error creating CipherTrust Manager key, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return ""
		}
		response, err = r.client.PostDataV2(ctx, id, common.URL_KEY_MANAGEMENT, payloadJSON)
		if err != nil {
			msg := "Error creating CipherTrust Manager key."
			details := utils.ApiError(msg, map[string]interface{}{
				"error":     err.Error(),
				"name":      payload.Name,
				"algorithm": payload.Algorithm,
			})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return ""
		}
		tflog.Trace(ctx, "[resource_aws_key.go -> createKeyMaterial][response:"+response)
	}
	return response
}

//nolint:unused
func (r *resourceAWSKey) decodeKeyTerraformResourceID(resourceID string) (region string, kid string, err error) {
	idParts := strings.Split(resourceID, "\\")
	if len(idParts) == 1 {
		kid = idParts[0]
	} else if len(idParts) == 2 {
		region = idParts[0]
		kid = idParts[1]
	} else {
		err = fmt.Errorf("%s is not a valid aws key resource id", resourceID)
	}
	return
}

//nolint:unused
func (r *resourceAWSKey) getKeyByTerraformID(ctx context.Context, id string, terraformID string, diags *diag.Diagnostics) string {
	region, kid, err := r.decodeKeyTerraformResourceID(terraformID)
	if err != nil {
		diags.AddError("Failed to decode terraform ID "+terraformID+".", err.Error())
		return ""
	}
	filters := url.Values{}
	filters.Add("keyid", kid)
	filters.Add("region", region)
	response, err := r.client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Failed to read AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kid": kid, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total == 0 {
		msg := "Failed to read AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kid, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	if total != 1 {
		msg := "Error reading AWS key, failed to list just one key."
		details := utils.ApiError(msg, map[string]interface{}{"kid": kid, "region": region})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	resources := gjson.Get(response, "resources").Array()
	var keyJSON string
	for _, keyResourceJSON := range resources {
		keyJSON = keyResourceJSON.String()
	}
	return keyJSON
}

func removeKeyPolicyTemplateTag(ctx context.Context, id string, client *common.Client, keyJSON string, diags *diag.Diagnostics) {
	var policyTemplateID string
	for _, tag := range gjson.Get(keyJSON, "aws_param.Tags").Array() {
		tagKey := gjson.Get(tag.Raw, "TagKey").String()
		if tagKey == policyTemplateTagKey {
			policyTemplateID = tagKey
			break
		}
	}
	if policyTemplateID != "" {
		var removeTagsPayload RemoveTagsJSON
		keyID := gjson.Get(keyJSON, "id").String()
		tagKey := policyTemplateTagKey
		removeTagsPayload.Tags = append(removeTagsPayload.Tags, &tagKey)
		payloadJSON, err := json.Marshal(removeTagsPayload)
		if err != nil {
			msg := "Error updating AWS key. Failed to remove policy template tag, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
			return
		}
		_, err = client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/remove-tags", payloadJSON)
		if err != nil {
			msg := "Error updating AWS key, failed to remove policy template tag."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
			tflog.Warn(ctx, details)
			diags.AddWarning(details, "")
		}
	}
}

func encodeAWSKeyTerraformResourceID(region, kid string) string {
	return region + "\\" + kid
}

func decodeAwsKeyResourceID(resourceID string) (region string, kid string, err error) {
	idParts := strings.Split(resourceID, "\\")
	if len(idParts) == 1 {
		kid = idParts[0]
	} else if len(idParts) == 2 {
		region = idParts[0]
		kid = idParts[1]
	} else {
		err = fmt.Errorf("%s is not a valid aws key resource id", resourceID)
	}
	return
}

func keyPolicyHasChanged(a *KeyPolicyPayloadJSON, b *KeyPolicyPayloadJSON) bool {
	if !utils.SlicesAreEqual(a.ExternalAccounts, b.ExternalAccounts) ||
		!utils.SlicesAreEqual(a.KeyAdmins, b.KeyAdmins) ||
		!utils.SlicesAreEqual(a.KeyAdminsRoles, b.KeyAdminsRoles) ||
		!utils.SlicesAreEqual(a.KeyUsers, b.KeyUsers) ||
		!utils.SlicesAreEqual(a.KeyUsersRoles, b.KeyUsersRoles) ||
		!utils.StringsEqual(a.PolicyTemplate, b.PolicyTemplate) ||
		!utils.BytesAreEqual(a.Policy, b.Policy) {
		return true
	}
	return false
}
