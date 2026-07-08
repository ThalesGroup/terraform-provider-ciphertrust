package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

const urlAWSIAMUsers = "api/v1/cckm/aws/get-iam-users"

var (
	_ datasource.DataSource              = &dataSourceAWSIAMUsersList{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSIAMUsersList{}
)

func NewDataSourceAWSIAMUsers() datasource.DataSource {
	return &dataSourceAWSIAMUsersList{}
}

type dataSourceAWSIAMUsersList struct {
	client *common.Client
}

func (d *dataSourceAWSIAMUsersList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// AWSIAMUsersDataSourceModel is the Terraform state model for this data source.
type AWSIAMUsersDataSourceModel struct {
	KmsID      types.String      `tfsdk:"kms_id"`
	MaxItems   types.Int64       `tfsdk:"max_items"`
	PathPrefix types.String      `tfsdk:"path_prefix"`
	Users      []AWSIAMUserTFSDK `tfsdk:"users"`
}

// AWSIAMUserTFSDK represents a single IAM user in Terraform state.
type AWSIAMUserTFSDK struct {
	Arn               types.String `tfsdk:"arn"`
	CreateDate        types.String `tfsdk:"create_date"`
	Path              types.String `tfsdk:"path"`
	UserID            types.String `tfsdk:"user_id"`
	UserName          types.String `tfsdk:"user_name"`
	PasswordLastUsed  types.String `tfsdk:"password_last_used"`
}

// awsIAMUsersRequest is the JSON body sent to the navic API.
type awsIAMUsersRequest struct {
	KmsID      string `json:"kms"`
	Marker     string `json:"marker"`
	MaxItems   int64  `json:"max_items"`
	PathPrefix string `json:"path_prefix"`
}

func (d *dataSourceAWSIAMUsersList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_iam_users_list"
}

func (d *dataSourceAWSIAMUsersList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve the list of AWS IAM users for a given CipherTrust Manager AWS KMS.",
		Attributes: map[string]schema.Attribute{
			"kms_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the CipherTrust Manager AWS KMS whose IAM users are to be listed.",
			},
			"max_items": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of IAM users to return. If omitted, all users are returned.",
			},
			"path_prefix": schema.StringAttribute{
				Optional:    true,
				Description: "Path prefix for filtering IAM users (e.g. /division_abc/).",
			},
			"users": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of IAM users.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"arn": schema.StringAttribute{
							Computed:    true,
							Description: "Amazon Resource Name (ARN) of the IAM user.",
						},
						"create_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the IAM user was created.",
						},
						"path": schema.StringAttribute{
							Computed:    true,
							Description: "Path of the IAM user.",
						},
						"user_id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique ID for the IAM user.",
						},
						"user_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the IAM user.",
						},
						"password_last_used": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the user's password was last used to sign in.",
						},
					},
				},
			},
		},
	}
}

// Read fetches all AWS IAM users, paginating via IsTruncated/Marker until all results are collected.
func (d *dataSourceAWSIAMUsersList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[data_source_aws_iam_users_list.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[data_source_aws_iam_users_list.go -> Read]["+id+"]")

	var state AWSIAMUsersDataSourceModel
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}

	var maxItems int64
	if !state.MaxItems.IsNull() && !state.MaxItems.IsUnknown() {
		maxItems = state.MaxItems.ValueInt64()
	}

	var allUsers []AWSIAMUserTFSDK
	marker := ""

	for {
		payload := awsIAMUsersRequest{
			KmsID:  state.KmsID.ValueString(),
			Marker: marker,
		}
		if maxItems > 0 {
			remaining := maxItems - int64(len(allUsers))
			payload.MaxItems = remaining
		}
		if !state.PathPrefix.IsNull() && !state.PathPrefix.IsUnknown() {
			payload.PathPrefix = state.PathPrefix.ValueString()
		}

		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_iam_users_list.go -> Read]["+id+"]")
			resp.Diagnostics.AddError("Error building request for AWS IAM users", err.Error())
			return
		}

		response, err := d.client.PostDataV2(ctx, id, urlAWSIAMUsers, payloadJSON)
		if err != nil {
			tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_iam_users_list.go -> Read]["+id+"]")
			resp.Diagnostics.AddError("Error reading AWS IAM users from CipherTrust Manager", err.Error())
			return
		}

		for _, u := range gjson.Get(response, "Users").Array() {
			allUsers = append(allUsers, AWSIAMUserTFSDK{
				Arn:              types.StringValue(u.Get("Arn").String()),
				CreateDate:       types.StringValue(u.Get("CreateDate").String()),
				Path:             types.StringValue(u.Get("Path").String()),
				UserID:           types.StringValue(u.Get("UserId").String()),
				UserName:         types.StringValue(u.Get("UserName").String()),
				PasswordLastUsed: types.StringValue(u.Get("PasswordLastUsed").String()),
			})
			if maxItems > 0 && int64(len(allUsers)) >= maxItems {
				break
			}
		}

		isTruncated := gjson.Get(response, "IsTruncated").Bool()
		nextMarker := gjson.Get(response, "Marker").String()

		if !isTruncated || nextMarker == "" {
			break
		}
		if maxItems > 0 && int64(len(allUsers)) >= maxItems {
			break
		}
		marker = nextMarker
	}

	state.Users = allUsers
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
