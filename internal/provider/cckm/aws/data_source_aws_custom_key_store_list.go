package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ datasource.DataSource              = &dataSourceAWSCustomKeyStoreList{}
	_ datasource.DataSourceWithConfigure = &dataSourceAWSCustomKeyStoreList{}
)

func NewDataSourceAWSCustomKeyStore() datasource.DataSource {
	return &dataSourceAWSCustomKeyStoreList{}
}

type dataSourceAWSCustomKeyStoreList struct {
	client *common.Client
}

func (d *dataSourceAWSCustomKeyStoreList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceAWSCustomKeyStoreList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_custom_keystore_list"
}

func (d *dataSourceAWSCustomKeyStoreList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of CipherTrust Manager AWS custom key stores.\n\n" +
			"Give a filter of 'limit=-1' to list all custom key stores that match the filter. Default is 10 matches.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A list of key:value pairs where the 'key' is any of the filters available in CipherTrust Manager's API playground for listing custom key stores.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of custom key stores which matched the filters.",
			},
			"custom_key_stores": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager ID of the custom key store.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the custom key store was created.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date and time the custom key store was last updated.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Unique name for the custom key store.",
						},
						"kms": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the AWS KMS account container associated with this key store.",
						},
						"region": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the available AWS region.",
						},
						"type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of the custom key store.",
						},
						"credential_version": schema.Int64Attribute{
							Computed:    true,
							Description: "Version number of the current credentials.",
						},
						"kms_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager ID of the KMS account container.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the cloud provider.",
						},
						"version_count": schema.Int64Attribute{
							Computed:    true,
							Description: "Number of credential versions available.",
						},
						"gone": schema.BoolAttribute{
							Computed:    true,
							Description: "True if the custom key store no longer exists in AWS.",
						},
						"enable_success_audit_event": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether audit recording of successful operations within an external key store is enabled.",
						},
						"aws_param": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "AWS-side parameters for the custom key store.",
							Attributes: map[string]schema.Attribute{
								"custom_key_store_name": schema.StringAttribute{
									Computed:    true,
									Description: "Name of the custom key store in AWS KMS.",
								},
								"cloud_hsm_cluster_id": schema.StringAttribute{
									Computed:    true,
									Description: "ID of the CloudHSM cluster backing this key store.",
								},
								"trust_anchor_certificate": schema.StringAttribute{
									Computed:    true,
									Description: "CA certificate for the CloudHSM cluster.",
								},
								"number_of_hsms_in_cloudhsm_cluster": schema.Int64Attribute{
									Computed:    true,
									Description: "Number of HSMs in the CloudHSM cluster.",
								},
								"xks_proxy_uri_endpoint": schema.StringAttribute{
									Computed:    true,
									Description: "HTTPS endpoint of the XKS proxy.",
								},
								"xks_proxy_vpc_endpoint_service_name": schema.StringAttribute{
									Computed:    true,
									Description: "VPC endpoint service name for the XKS proxy.",
								},
								"xks_proxy_uri_path": schema.StringAttribute{
									Computed:    true,
									Description: "URI path used by the XKS proxy.",
								},
								"custom_key_store_type": schema.StringAttribute{
									Computed:    true,
									Description: "Type of the custom key store (AWS_CLOUDHSM or EXTERNAL_KEY_STORE).",
								},
								"custom_key_store_id": schema.StringAttribute{
									Computed:    true,
									Description: "AWS-assigned ID for the custom key store.",
								},
								"xks_proxy_connectivity": schema.StringAttribute{
									Computed:    true,
									Description: "Connectivity type for the XKS proxy.",
								},
								"connection_state": schema.StringAttribute{
									Computed:    true,
									Description: "Current connection state of the custom key store in AWS.",
								},
								"connection_error_details": schema.StringAttribute{
									Computed:    true,
									Description: "Details about the last connection error, if any.",
								},
								"aws_account_id": schema.StringAttribute{
									Computed:    true,
									Description: "AWS account ID that owns this key store.",
								},
								"arn": schema.StringAttribute{
									Computed:    true,
									Description: "Amazon Resource Name (ARN) of the custom key store.",
								},
							},
						},
						"local_hosted_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Parameters related to local hosting of the custom key store.",
							Attributes: map[string]schema.Attribute{
								"blocked": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the custom key store is in a blocked state.",
								},
								"source_container_id": schema.StringAttribute{
									Computed:    true,
									Description: "ID of the source container used for key material.",
								},
								"source_container_type": schema.StringAttribute{
									Computed:    true,
									Description: "Type of the source container.",
								},
								"linked_state": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the custom key store is linked with AWS.",
								},
								"partition_label": schema.StringAttribute{
									Computed:    true,
									Description: "Label of the Luna HSM partition.",
								},
								"partition_id": schema.StringAttribute{
									Computed:    true,
									Description: "ID of the Luna HSM partition.",
								},
								"health_check_key_id": schema.StringAttribute{
									Computed:    true,
									Description: "ID of the key used for health checks.",
								},
								"health_check_ciphertext": schema.StringAttribute{
									Computed:    true,
									Description: "Ciphertext used for health check operations.",
								},
								"max_credentials": schema.Int64Attribute{
									Computed:    true,
									Description: "Maximum number of credentials allowed for the key store.",
								},
								"source_key_tier": schema.StringAttribute{
									Computed:    true,
									Description: "Key tier used as the source for cryptographic keys.",
								},
								"health_check_uri_path": schema.StringAttribute{
									Computed:    true,
									Description: "URI path used by AWS KMS to perform health checks.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// customKeyStoreItemJSON is used to unmarshal a single entry from the list API response.
type customKeyStoreItemJSON struct {
	ID                string `json:"id"`
	CreatedAt         string `json:"createdAt"`
	UpdatedAt         string `json:"updatedAt"`
	Name              string `json:"name"`
	Kms               string `json:"kms"`
	Region            string `json:"region"`
	Type              string `json:"type"`
	CredentialVersion int64  `json:"credential_version"`
	KmsID             string `json:"kms_id"`
	CloudName         string `json:"cloud_name"`
	VersionCount      int64  `json:"version_count"`
	Gone              bool   `json:"gone"`
	EnableAuditEvent  *bool  `json:"enable_success_audit_event,omitempty"`
	AwsParam          struct {
		CustomKeyStoreName             string `json:"custom_key_store_name"`
		CloudHSMClusterID              string `json:"cloud_hsm_cluster_id"`
		TrustAnchorCertificate         string `json:"trust_anchor_certificate"`
		NumberOfHSMsInCloudHSMCluster  *int64 `json:"number_of_hsms_in_cloudhsm_cluster"`
		XKSProxyURIEndpoint            string `json:"xks_proxy_uri_endpoint"`
		XKSProxyVPCEndpointServiceName string `json:"xks_proxy_vpc_endpoint_service_name"`
		XKSProxyURIPath                string `json:"xks_proxy_uri_path"`
		CustomKeyStoreType             string `json:"custom_key_store_type"`
		CustomKeyStoreID               string `json:"custom_key_store_id"`
		XKSProxyConnectivity           string `json:"xks_proxy_connectivity"`
		ConnectionState                string `json:"connection_state"`
		ConnectionErrorDetails         string `json:"connection_error_details"`
		AWSAccountID                   string `json:"aws_account_id"`
		Arn                            string `json:"arn"`
	} `json:"aws_param"`
	LocalHostedParams struct {
		Blocked               *bool  `json:"blocked,omitempty"`
		SourceContainerID     string `json:"source_container_id"`
		SourceContainerType   string `json:"source_container_type"`
		LinkedState           *bool  `json:"linked_state,omitempty"`
		PartitionLabel        string `json:"partition_label"`
		PartitionID           string `json:"partition_id"`
		HealthCheckKeyID      string `json:"health_check_key_id"`
		HealthCheckCiphertext string `json:"health_check_ciphertext"`
		MaxCredentials        *int64 `json:"max_credentials,omitempty"`
		SourceKeyTier         string `json:"source_key_tier"`
		HealthCheckURIPath    string `json:"health_check_uri_path"`
	} `json:"local_hosted_params"`
}

// customKeyStoreListJSON is used to unmarshal the list API response envelope.
type customKeyStoreListJSON struct {
	Resources []customKeyStoreItemJSON `json:"resources"`
}

// Read lists custom key stores matching the given filters and populates Terraform state.
func (d *dataSourceAWSCustomKeyStoreList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[data_source_aws_custom_key_store.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[data_source_aws_custom_key_store.go -> Read]["+id+"]")

	var state AWSCustomKeyStoreListDataSourceModel
	diags := req.Config.Get(ctx, &state)
	if diags.HasError() {
		resp.Diagnostics = append(resp.Diagnostics, diags...)
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		if val, ok := v.(types.String); ok {
			filters.Add(k, val.ValueString())
		}
	}

	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_AWS_XKS+"/", filters)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_custom_key_store.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read AWS custom key stores from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var list customKeyStoreListJSON
	if err := json.Unmarshal([]byte(jsonStr), &list); err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_aws_custom_key_store.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to parse AWS custom key stores response",
			err.Error(),
		)
		return
	}

	for _, item := range list.Resources {
		awsParam := &CustomKeyStoreAwsParamTFSDK{
			CustomKeyStoreName:             types.StringValue(item.AwsParam.CustomKeyStoreName),
			CloudHSMClusterID:              types.StringValue(item.AwsParam.CloudHSMClusterID),
			TrustAnchorCertificate:         types.StringValue(item.AwsParam.TrustAnchorCertificate),
			XKSProxyURIEndpoint:            types.StringValue(item.AwsParam.XKSProxyURIEndpoint),
			XKSProxyVPCEndpointServiceName: types.StringValue(item.AwsParam.XKSProxyVPCEndpointServiceName),
			XKSProxyURIPath:                types.StringValue(item.AwsParam.XKSProxyURIPath),
			CustomKeyStoreType:             types.StringValue(item.AwsParam.CustomKeyStoreType),
			CustomKeyStoreID:               types.StringValue(item.AwsParam.CustomKeyStoreID),
			XKSProxyConnectivity:           types.StringValue(item.AwsParam.XKSProxyConnectivity),
			ConnectionState:                types.StringValue(item.AwsParam.ConnectionState),
			ConnectionErrorDetails:         types.StringValue(item.AwsParam.ConnectionErrorDetails),
			AWSAccountID:                   types.StringValue(item.AwsParam.AWSAccountID),
			Arn:                            types.StringValue(item.AwsParam.Arn),
		}
		if item.AwsParam.NumberOfHSMsInCloudHSMCluster != nil {
			awsParam.NumberOfHSMsInCloudHSMCluster = types.Int64Value(*item.AwsParam.NumberOfHSMsInCloudHSMCluster)
		} else {
			awsParam.NumberOfHSMsInCloudHSMCluster = types.Int64Value(0)
		}

		lhp := &CustomKeyStoreLocalHostedParamsTFSDK{
			SourceContainerID:     types.StringValue(item.LocalHostedParams.SourceContainerID),
			SourceContainerType:   types.StringValue(item.LocalHostedParams.SourceContainerType),
			PartitionLabel:        types.StringValue(item.LocalHostedParams.PartitionLabel),
			PartitionID:           types.StringValue(item.LocalHostedParams.PartitionID),
			HealthCheckKeyID:      types.StringValue(item.LocalHostedParams.HealthCheckKeyID),
			HealthCheckCiphertext: types.StringValue(item.LocalHostedParams.HealthCheckCiphertext),
			SourceKeyTier:         types.StringValue(item.LocalHostedParams.SourceKeyTier),
			HealthCheckURIPath:    types.StringValue(item.LocalHostedParams.HealthCheckURIPath),
		}
		if item.LocalHostedParams.Blocked != nil {
			lhp.Blocked = types.BoolValue(*item.LocalHostedParams.Blocked)
		} else {
			lhp.Blocked = types.BoolValue(false)
		}
		if item.LocalHostedParams.LinkedState != nil {
			lhp.LinkedState = types.BoolValue(*item.LocalHostedParams.LinkedState)
		} else {
			lhp.LinkedState = types.BoolValue(false)
		}
		if item.LocalHostedParams.MaxCredentials != nil {
			lhp.MaxCredentials = types.Int64Value(*item.LocalHostedParams.MaxCredentials)
		} else {
			lhp.MaxCredentials = types.Int64Value(0)
		}

		enableAudit := false
		if item.EnableAuditEvent != nil {
			enableAudit = *item.EnableAuditEvent
		}

		entry := CustomKeyStoreListItemTFSDK{
			ID:                      types.StringValue(item.ID),
			CreatedAt:               types.StringValue(item.CreatedAt),
			UpdatedAt:               types.StringValue(item.UpdatedAt),
			Name:                    types.StringValue(item.Name),
			Kms:                     types.StringValue(item.Kms),
			Region:                  types.StringValue(item.Region),
			Type:                    types.StringValue(item.Type),
			CredentialVersion:       types.Int64Value(item.CredentialVersion),
			KmsID:                   types.StringValue(item.KmsID),
			CloudName:               types.StringValue(item.CloudName),
			VersionCount:            types.Int64Value(item.VersionCount),
			Gone:                    types.BoolValue(item.Gone),
			EnableSuccessAuditEvent: types.BoolValue(enableAudit),
			AwsParam:                awsParam,
			LocalHostedParams:       lhp,
		}
		state.CustomKeyStores = append(state.CustomKeyStores, entry)
	}

	state.Matched = types.Int64Value(gjson.Get(jsonStr, "total").Int())
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
