package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceAWSConnection{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSConnection{}
)

func NewDataSourceAWSConnection() datasource.DataSource {
	return &dataSourceAWSConnection{}
}

type dataSourceAWSConnection struct {
	client *common.Client
}

type AWSConnectionDataSourceModel struct {
	Filters types.Map                 `tfsdk:"filters"`
	AWS     []AWSConnectionModelTFSDK `tfsdk:"aws"`
}

func (d *dataSourceAWSConnection) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_connection_list"
}

func (d *dataSourceAWSConnection) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"aws": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed: true,
						},
						"name": schema.StringAttribute{
							Required:    true,
							Description: "Unique connection name",
						},
						"access_key_id": schema.StringAttribute{
							Optional:    true,
							Description: "Key ID of the AWS user",
						},
						"assume_role_arn": schema.StringAttribute{
							Optional:    true,
							Description: "AWS IAM role ARN",
						},
						"assume_role_external_id": schema.StringAttribute{
							Optional:    true,
							Description: "Specify AWS Role external ID",
						},
						"aws_region": schema.StringAttribute{
							Optional: true,
							Description: "AWS region. only used when aws_sts_regional_endpoints is equal to regional otherwise, it takes default values according to Cloud Name given." +
								"Default values are: \n" +
								"for aws, default region will be \"us-east-1\" \n" +
								"for aws-us-gov, default region will be \"us-gov-east-1\" \n" +
								"for aws-cn, default region will be \"cn-north-1\"",
						},
						"aws_sts_regional_endpoints": schema.StringAttribute{
							Optional: true,
							Description: "By default, AWS Security Token Service (AWS STS) is available as a global service, and all AWS STS requests go to a single endpoint at https://sts.amazonaws.com. Global requests map to the US East (N. Virginia) Region. AWS recommends using Regional AWS STS endpoints instead of the global endpoint to reduce latency, build in redundancy, and increase session token validity. valid values are: \n" +
								"legacy (default): Uses the global AWS STS endpoint, sts.amazonaws.com \n" +
								"regional: The SDK or tool always uses the AWS STS endpoint for the currently configured Region. \n",
						},
						"cloud_name": schema.StringAttribute{
							Optional: true,
							Description: "Name of the cloud. Options are: \n" +
								"aws (default) \n" +
								"aws-us-gov \n" +
								"aws-cn",
						},
						"description": schema.StringAttribute{
							Optional:    true,
							Description: "Description about the connection",
						},
						"iam_role_anywhere": schema.SingleNestedAttribute{
							Optional: true,
							Attributes: map[string]schema.Attribute{
								"anywhere_role_arn": schema.StringAttribute{
									Required:    true,
									Description: "Specify AWS IAM Anywhere Role ARN",
								},
								"certificate": schema.StringAttribute{
									Required:    true,
									Description: "Upload the external certificate for AWS IAM Anywhere Cloud connections. This option is used when \"role_anywhere\" is set to \"true\".",
								},
								"profile_arn": schema.StringAttribute{
									Required:    true,
									Description: "Specify AWS IAM Anywhere Profile ARN",
								},
								"trust_anchor_arn": schema.StringAttribute{
									Required:    true,
									Description: "Specify AWS IAM Anywhere Trust Anchor ARN",
								},
								"private_key": schema.StringAttribute{
									Optional:    true,
									Description: "The private key associated with the certificate",
								},
							},
						},
						"is_role_anywhere": schema.BoolAttribute{
							Optional:    true,
							Description: "Set the parameter to true to create connections of type AWS IAM Anywhere with temporary credentials.",
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Optional:    true,
							Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.",
						},
						"meta": schema.MapAttribute{
							ElementType: types.StringType,
							Optional:    true,
							Description: "Optional end-user or service data stored with the connection.",
						},
						"products": schema.ListAttribute{
							Optional:    true,
							ElementType: types.StringType,
							Description: "Array of the CipherTrust products associated with the connection",
						},
						"secret_access_key": schema.StringAttribute{
							Optional:    true,
							Description: "Secret associated with the access key ID of the AWS user",
						},
						//common response parameters (optional)
						"uri":                   schema.StringAttribute{Computed: true},
						"account":               schema.StringAttribute{Computed: true},
						"created_at":            schema.StringAttribute{Computed: true},
						"updated_at":            schema.StringAttribute{Computed: true},
						"service":               schema.StringAttribute{Computed: true},
						"category":              schema.StringAttribute{Computed: true},
						"resource_url":          schema.StringAttribute{Computed: true},
						"last_connection_ok":    schema.BoolAttribute{Computed: true},
						"last_connection_error": schema.StringAttribute{Computed: true},
						"last_connection_at":    schema.StringAttribute{Computed: true},
						"dev_account": schema.StringAttribute{
							Description: "The developer account which owns this resource's application.",
							Computed:    true,
						},
						"application": schema.StringAttribute{
							Description: "The application this resource belongs to.",
							Computed:    true,
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceAWSConnection) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_aws_connection.go -> Read]["+id+"]")
	var state AWSConnectionDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(ctx, id, common.URL_AWS_CONNECTION+"/?"+strings.Join(kvs, "")+"skip=0&limit=-1")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read AWS connections from CM",
			err.Error(),
		)
		return
	}

	awsConnections := []AWSConnectionModelJSON{}
	err = json.Unmarshal([]byte(jsonStr), &awsConnections)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read AWS connections from CM",
			err.Error(),
		)
		return
	}

	for _, aws := range awsConnections {
		awsConn := AWSConnectionModelTFSDK{
			CMCreateConnectionResponseCommonTFSDK: CMCreateConnectionResponseCommonTFSDK{
				URI:                 types.StringValue(aws.URI),
				Account:             types.StringValue(aws.Account),
				CreatedAt:           types.StringValue(aws.CreatedAt),
				UpdatedAt:           types.StringValue(aws.UpdatedAt),
				Service:             types.StringValue(aws.Service),
				Category:            types.StringValue(aws.Category),
				ResourceURL:         types.StringValue(aws.ResourceURL),
				LastConnectionOK:    types.BoolValue(aws.LastConnectionOK),
				LastConnectionError: types.StringValue(aws.LastConnectionError),
				LastConnectionAt:    types.StringValue(aws.LastConnectionAt),
			},
			ID:                      types.StringValue(aws.ID),
			Name:                    types.StringValue(aws.Name),
			Description:             types.StringValue(aws.Description),
			AccessKeyID:             types.StringValue(aws.AccessKeyID),
			AssumeRoleARN:           types.StringValue(aws.AssumeRoleARN),
			AssumeRoleExternalID:    types.StringValue(aws.AssumeRoleExternalID),
			AWSRegion:               types.StringValue(aws.AWSRegion),
			AWSSTSRegionalEndpoints: types.StringValue(aws.AWSSTSRegionalEndpoints),
			CloudName:               types.StringValue(aws.CloudName),
			IsRoleAnywhere:          types.BoolValue(aws.IsRoleAnywhere),
			SecretAccessKey:         types.StringValue(aws.SecretAccessKey),
			Products: func() []types.String {
				var products []types.String
				for _, product := range aws.Products {
					products = append(products, types.StringValue(product))
				}
				return products
			}(),
		}

		if !reflect.DeepEqual((*IAMRoleAnywhereTFSDK)(nil), aws.IAMRoleAnywhere) {
			iamRoleAnywhere := IAMRoleAnywhereTFSDK{
				AnywhereRoleARN: types.StringValue(aws.IAMRoleAnywhere.AnywhereRoleARN),
				Certificate:     types.StringValue(aws.IAMRoleAnywhere.Certificate),
				ProfileARN:      types.StringValue(aws.IAMRoleAnywhere.ProfileARN),
				TrustAnchorARN:  types.StringValue(aws.IAMRoleAnywhere.TrustAnchorARN),
				PrivateKey:      types.StringValue(aws.IAMRoleAnywhere.PrivateKey),
			}
			awsConn.IAMRoleAnywhere = &iamRoleAnywhere
		}

		if aws.Labels != nil {
			// Create the map to store attr.Value
			labelsMap := make(map[string]attr.Value)
			for key, value := range aws.Labels {
				// Ensure value is a string and handle if it's not
				if strVal, ok := value.(string); ok {
					labelsMap[key] = types.StringValue(strVal) // types.String is an attr.Value
				} else {
					// If not a string, set a default or skip the key-value pair
					labelsMap[key] = types.StringValue(fmt.Sprintf("%v", value))
				}
			}
			// Set labels as a MapValue
			awsConn.Labels, _ = types.MapValue(types.StringType, labelsMap)
		} else {
			// If Labels are missing, assign an empty map
			labelsMap := make(map[string]attr.Value)
			awsConn.Labels, _ = types.MapValue(types.StringType, labelsMap)
		}

		if aws.Meta != nil {
			// Create the map to store attr.Value for Meta
			metaMap := make(map[string]attr.Value)
			for key, value := range aws.Meta.(map[string]interface{}) {
				// Convert each value in meta to the corresponding attr.Value
				switch v := value.(type) {
				case string:
					metaMap[key] = types.StringValue(v)
				case int64:
					metaMap[key] = types.Int64Value(v)
				case bool:
					metaMap[key] = types.BoolValue(v)
				default:
					// For unknown types, convert them to a string representation
					metaMap[key] = types.StringValue(fmt.Sprintf("%v", v))
				}
			}
			awsConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		} else {
			// If Meta is missing, assign an empty map
			metaMap := make(map[string]attr.Value)
			awsConn.Meta, _ = types.MapValue(types.StringType, metaMap)
		}

		state.AWS = append(state.AWS, awsConn)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_aws_connection.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceAWSConnection) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
