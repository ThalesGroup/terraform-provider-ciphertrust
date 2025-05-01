package cckm

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSKey{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSKey{}
)

func NewDataSourceAWSKeys() datasource.DataSource {
	return &dataSourceAWSKey{}
}

func (d *dataSourceAWSKey) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

type dataSourceAWSKey struct {
	client *common.Client
}

type AWSKey struct {
	AWSKeyDataSourceTFSDK
}

func (d *dataSourceAWSKey) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key"
}
func (d *dataSourceAWSKey) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve the AWS key by id.",
		Attributes: map[string]schema.Attribute{
			// Optional input parameters
			"region": schema.StringAttribute{
				Optional:    true,
				Description: "AWS region to which the key belongs.",
			},
			"id": schema.StringAttribute{
				Optional: true,
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
			"arn": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "The Amazon Resource Name (ARN) of the key.",
			},
			// Read only parameters
			"auto_rotate": schema.BoolAttribute{
				Computed:    true,
				Description: "Enable AWS autorotation on the key.",
			},
			"auto_rotation_period_in_days": schema.Int64Attribute{
				Computed:    true,
				Description: "Rotation period in days.",
			},
			"customer_master_key_spec": schema.StringAttribute{
				Computed:    true,
				Description: "Key specification",
			},
			"description": schema.StringAttribute{
				Computed:    true,
				Description: "Description of the AWS key.",
			},
			"enable_key": schema.BoolAttribute{
				Computed:    true,
				Description: "Enable or disable the key.",
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
				Description: "Source of the key material.",
			},
			"tags": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"aws_account_id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS account ID.",
			},
			"aws_key_id": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
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
				Description: "Encryption algorithms of the AWS key.",
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
				Optional:    true,
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
				Description: "CipherTrust Manager key ID which this key has been rotated to by a scheduled rotation job.",
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
	}
}

func (d *dataSourceAWSKey) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_key.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_key.go -> Read]")
	var state AWSKeyDataSourceTFSDK
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}
	filters := url.Values{}
	if state.KeyID.ValueString() != "" {
		filters.Add("id", state.KeyID.ValueString())
	} else if state.ID.ValueString() != "" {
		region, kid, err := decodeAwsKeyResourceID(state.ID.ValueString())
		if err != nil {
			msg := "Error decoding AWS XKS key resource ID, failed to set resource state."
			details := apiError(msg, map[string]interface{}{"error": err.Error(), "id": state.ID.ValueString()})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		filters.Add("region", region)
		filters.Add("keyid", kid)
	} else if state.ARN.ValueString() != "" {
		arnParts := strings.Split(state.ARN.ValueString(), ":")
		if len(arnParts) != 6 {
			msg := "Unexpected AWS ARN format."
			details := apiError(msg, map[string]interface{}{"arn": state.ARN.ValueString()})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		kidParts := strings.Split(arnParts[5], "/")
		if len(kidParts) != 2 {
			msg := "Unexpected AWS ARN format, unable to extract AWS KID."
			details := apiError(msg, map[string]interface{}{"arn": state.ARN.ValueString()})
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		filters.Add("region", arnParts[3])
		filters.Add("keyid", kidParts[1])
	} else {
		if !state.Alias.IsNull() && !state.Alias.IsUnknown() && len(state.Alias.Elements()) != 0 {
			if len(state.Alias.Elements()) != 0 {
				aliases := make([]string, 0, len(state.Alias.Elements()))
				resp.Diagnostics.Append(state.Alias.ElementsAs(ctx, &aliases, false)...)
				if resp.Diagnostics.HasError() {
					return
				}
				filters.Add("alias", aliases[0])
			}
		}
		if state.AWSKeyID.ValueString() != "" {
			filters.Add("keyid", state.AWSKeyID.ValueString())
		}
		if state.Region.ValueString() != "" {
			filters.Add("region", state.Region.ValueString())
		}
	}
	response := listAwsKeys(ctx, id, d.client, filters, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	d.setKeyDataSourceState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	kid := gjson.Get(response, "aws_param.KeyID").String()
	region := gjson.Get(response, "region").String()
	state.ID = types.StringValue(encodeAWSKeyTerraformResourceID(region, kid))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func listAwsKeys(ctx context.Context, id string, client *common.Client, filters url.Values, diags *diag.Diagnostics) string {
	response, err := client.ListWithFilters(ctx, id, common.URL_AWS_KEY, filters)
	if err != nil {
		msg := "Failed to list AWS key."
		details := apiError(msg, map[string]interface{}{"error": err.Error(), "filters": fmt.Sprintf("%v", filters)})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	total := gjson.Get(response, "total").Int()
	if total != 1 {
		msg := "Failed list key, error listing single key."
		tflog.Error(ctx, msg)
		details := apiError(msg, map[string]interface{}{"filters": fmt.Sprintf("%v", filters), "Number of keys listed": fmt.Sprintf("%d", gjson.Get(response, "total").Int())})
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

func (d *dataSourceAWSKey) setKeyDataSourceState(ctx context.Context, response string, state *AWSKeyDataSourceTFSDK, diags *diag.Diagnostics) {
	setCommonKeyDataSourceState(ctx, response, &state.AWSKeyDataSourceCommonTFSDK, diags)
	setAliases(response, &state.Alias, diags)
	setKeyTags(ctx, response, &state.Tags, diags)
	state.AutoRotate = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	state.AutoRotationPeriodInDays = types.Int64Value(gjson.Get(response, "aws_param.RotationPeriodInDays").Int())
	state.Description = types.StringValue(gjson.Get(response, "aws_param.Description").String())
	state.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	if state.KMS.ValueString() == "" {
		state.KMS = types.StringValue(gjson.Get(response, "kms").String())
	}
	state.MultiRegion = types.BoolValue(gjson.Get(response, "aws_param.MultiRegion").Bool())
	state.MultiRegionKeyType = types.StringValue(gjson.Get(response, "aws_param.MultiRegionConfiguration.MultiRegionKeyType").String())
	setMultiRegionConfiguration(ctx, response, &state.MultiRegionPrimaryKey, &state.MultiRegionReplicaKeys, diags)
	state.NextRotationDate = types.StringValue(gjson.Get(response, "aws_param.NextRotationDate").String())
	state.ReplicaPolicy = types.StringValue(gjson.Get(response, "replica_policy").String())
}

func setCommonKeyDataSourceState(ctx context.Context, response string, state *AWSKeyDataSourceCommonTFSDK, diags *diag.Diagnostics) {
	state.KeyID = types.StringValue(gjson.Get(response, "id").String())
	state.ARN = types.StringValue(gjson.Get(response, "aws_param.Arn").String())
	state.AWSAccountID = types.StringValue(gjson.Get(response, "aws_param.AWSAccountId").String())
	state.AWSKeyID = types.StringValue(gjson.Get(response, "aws_param.KeyID").String())
	state.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.CustomerMasterKeySpec = types.StringValue(gjson.Get(response, "aws_param.CustomerMasterKeySpec").String())
	state.DeletionDate = types.StringValue(gjson.Get(response, "deletion_date").String())
	state.Enabled = types.BoolValue(gjson.Get(response, "aws_param.Enabled").Bool())
	state.EncryptionAlgorithms = stringSliceJSONToListValue(gjson.Get(response, "aws_param.EncryptionAlgorithms").Array(), diags)
	state.ExpirationModel = types.StringValue(gjson.Get(response, "aws_param.ExpirationModel").String())
	state.ExternalAccounts = stringSliceJSONToSetValue(gjson.Get(response, "external_accounts").Array(), diags)
	state.KeyAdmins = stringSliceJSONToSetValue(gjson.Get(response, "key_admins").Array(), diags)
	state.KeyAdminsRoles = stringSliceJSONToSetValue(gjson.Get(response, "key_admins_roles").Array(), diags)
	state.KeyManager = types.StringValue(gjson.Get(response, "aws_param.KeyManager").String())
	state.KeyMaterialOrigin = types.StringValue(gjson.Get(response, "key_material_origin").String())
	state.KeyRotationEnabled = types.BoolValue(gjson.Get(response, "aws_param.KeyRotationEnabled").Bool())
	state.KeySource = types.StringValue(gjson.Get(response, "key_source").String())
	state.KeyState = types.StringValue(gjson.Get(response, "aws_param.KeyState").String())
	state.KeyType = types.StringValue(gjson.Get(response, "key_type").String())
	state.KeyUsers = stringSliceJSONToSetValue(gjson.Get(response, "key_users").Array(), diags)
	state.KeyUsersRoles = stringSliceJSONToSetValue(gjson.Get(response, "key_users_roles").Array(), diags)
	setKeyLabels(ctx, response, state.KeyID.ValueString(), &state.Labels, diags)
	state.LocalKeyID = types.StringValue(gjson.Get(response, "local_key_id").String())
	state.LocalKeyName = types.StringValue(gjson.Get(response, "local_key_name").String())
	state.KeyUsage = types.StringValue(gjson.Get(response, "aws_param.KeyUsage").String())
	state.Origin = types.StringValue(gjson.Get(response, "aws_param.Origin").String())
	policy := gjson.Get(response, "aws_param.Policy").String()
	if !getPoliciesAreEqual(ctx, policy, state.Policy.ValueString(), diags) {
		state.Policy = types.StringValue(policy)
	}
	setPolicyTemplateTag(ctx, response, &state.PolicyTemplateTag, diags)
	state.RotatedAt = types.StringValue(gjson.Get(response, "rotated_at").String())
	state.RotatedFrom = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.RotationStatus = types.StringValue(gjson.Get(response, "rotation_status").String())
	state.RotatedTo = types.StringValue(gjson.Get(response, "rotated_to").String())
	state.SyncedAt = types.StringValue(gjson.Get(response, "synced_at").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.ValidTo = types.StringValue(gjson.Get(response, "aws_param.ValidTo").String())
}
