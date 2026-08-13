package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

const urlAWSIAMRoles = "api/v1/cckm/aws/get-iam-roles"

var (
	_ datasource.DataSource              = &dataSourceAWSIAMRolesList{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSIAMRolesList{}
)

func NewDataSourceAWSIAMRoles() datasource.DataSource {
	return &dataSourceAWSIAMRolesList{}
}

type dataSourceAWSIAMRolesList struct {
	client *common.Client
}

func (d *dataSourceAWSIAMRolesList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// AWSIAMRolesDataSourceModel is the Terraform state model for this data source.
type AWSIAMRolesDataSourceModel struct {
	KmsID       types.String      `tfsdk:"kms_id"`
	Marker      types.String      `tfsdk:"marker"`
	MaxItems    types.Int64       `tfsdk:"max_items"`
	PathPrefix  types.String      `tfsdk:"path_prefix"`
	IsTruncated types.Bool        `tfsdk:"is_truncated"`
	NextMarker  types.String      `tfsdk:"next_marker"`
	Roles       []AWSIAMRoleTFSDK `tfsdk:"roles"`
}

// AWSIAMRoleTFSDK represents a single IAM role in Terraform state.
type AWSIAMRoleTFSDK struct {
	Arn                      types.String `tfsdk:"arn"`
	AssumeRolePolicyDocument types.String `tfsdk:"assume_role_policy_document"`
	CreateDate               types.String `tfsdk:"create_date"`
	Description              types.String `tfsdk:"description"`
	MaxSessionDuration       types.Int64  `tfsdk:"max_session_duration"`
	Path                     types.String `tfsdk:"path"`
	RoleID                   types.String `tfsdk:"role_id"`
	RoleName                 types.String `tfsdk:"role_name"`
}

// awsIAMRolesRequest is the JSON body sent to the navic API.
type awsIAMRolesRequest struct {
	KmsID      string `json:"kms"`
	Marker     string `json:"marker"`
	MaxItems   int64  `json:"max_items"`
	PathPrefix string `json:"path_prefix"`
}

func (d *dataSourceAWSIAMRolesList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_iam_roles_list"
}

func (d *dataSourceAWSIAMRolesList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve the list of AWS IAM roles for a given CipherTrust Manager AWS KMS.",
		Attributes: map[string]schema.Attribute{
			"kms_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the CipherTrust Manager AWS KMS whose IAM roles are to be listed.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"marker": schema.StringAttribute{
				Optional:    true,
				Description: "Pagination marker from a previous response. Use this to retrieve the next page of results.",
			},
			"max_items": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of IAM roles to return. If omitted, all roles are returned.",
			},
			"path_prefix": schema.StringAttribute{
				Optional:    true,
				Description: "Path prefix for filtering IAM roles (e.g. /division_abc/).",
			},
			"is_truncated": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether the results were truncated. If true, use next_marker to retrieve the next page.",
			},
			"next_marker": schema.StringAttribute{
				Computed:    true,
				Description: "Marker to use in the next request to retrieve the next page of results.",
			},
			"roles": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of IAM roles.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"arn": schema.StringAttribute{
							Computed:    true,
							Description: "Amazon Resource Name (ARN) of the IAM role.",
						},
						"assume_role_policy_document": schema.StringAttribute{
							Computed:    true,
							Description: "Trust policy document that grants an entity permission to assume the role.",
						},
						"create_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the IAM role was created.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Description of the IAM role.",
						},
						"max_session_duration": schema.Int64Attribute{
							Computed:    true,
							Description: "Maximum session duration (in seconds) for the role.",
						},
						"path": schema.StringAttribute{
							Computed:    true,
							Description: "Path of the IAM role.",
						},
						"role_id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique ID for the IAM role.",
						},
						"role_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the IAM role.",
						},
					},
				},
			},
		},
	}
}

// Read fetches AWS IAM roles for the given KMS. Use max_items and marker to control pagination.
func (d *dataSourceAWSIAMRolesList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_aws_iam_roles_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_aws_iam_roles_list.go -> Read][" + id + "]")

	var state AWSIAMRolesDataSourceModel
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}

	payload := awsIAMRolesRequest{
		KmsID: state.KmsID.ValueString(),
	}
	if !state.Marker.IsNull() && !state.Marker.IsUnknown() {
		payload.Marker = state.Marker.ValueString()
	}
	if !state.MaxItems.IsNull() && !state.MaxItems.IsUnknown() {
		payload.MaxItems = state.MaxItems.ValueInt64()
	}
	if !state.PathPrefix.IsNull() && !state.PathPrefix.IsUnknown() {
		payload.PathPrefix = state.PathPrefix.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		d.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [data_source_aws_iam_roles_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Error building request for AWS IAM roles", err.Error())
		return
	}

	response, err := d.client.PostDataV2(ctx, id, urlAWSIAMRoles, payloadJSON)
	if err != nil {
		d.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [data_source_aws_iam_roles_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Error reading AWS IAM roles from CipherTrust Manager", err.Error())
		return
	}

	var roles []AWSIAMRoleTFSDK
	for _, r := range gjson.Get(response, "Roles").Array() {
		roles = append(roles, AWSIAMRoleTFSDK{
			Arn:                      types.StringValue(r.Get("Arn").String()),
			AssumeRolePolicyDocument: types.StringValue(r.Get("AssumeRolePolicyDocument").String()),
			CreateDate:               types.StringValue(r.Get("CreateDate").String()),
			Description:              types.StringValue(r.Get("Description").String()),
			MaxSessionDuration:       types.Int64Value(r.Get("MaxSessionDuration").Int()),
			Path:                     types.StringValue(r.Get("Path").String()),
			RoleID:                   types.StringValue(r.Get("RoleId").String()),
			RoleName:                 types.StringValue(r.Get("RoleName").String()),
		})
	}
	state.IsTruncated = types.BoolValue(gjson.Get(response, "IsTruncated").Bool())
	state.NextMarker = types.StringValue(gjson.Get(response, "Marker").String())
	state.Roles = roles
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
