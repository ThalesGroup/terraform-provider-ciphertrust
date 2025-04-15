package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &datasourceAWSCustomKeyStoreDataSource{}
	_ datasource.DataSourceWithConfigure = &datasourceAWSCustomKeyStoreDataSource{}
)

func NewDataSourceAWSCustomKeyStore() datasource.DataSource {
	return &datasourceAWSCustomKeyStoreDataSource{}
}

func (d *datasourceAWSCustomKeyStoreDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type datasourceAWSCustomKeyStoreDataSource struct {
	client *common.Client
}

func (d *datasourceAWSCustomKeyStoreDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_custom_keystore"
}
func (d *datasourceAWSCustomKeyStoreDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Required: true,
			},
			"access_key_id": schema.StringAttribute{
				Computed: true,
			},
			"cloud_name": schema.StringAttribute{
				Computed: true,
			},
			"created_at": schema.StringAttribute{
				Computed: true,
			},
			"credential_version": schema.StringAttribute{
				Computed: true,
			},
			"kms_id": schema.StringAttribute{
				Computed: true,
			},
			"secret_access_key": schema.StringAttribute{
				Computed: true,
			},
			"type": schema.StringAttribute{
				Computed: true,
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
			},
			"kms": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Name or ID of the AWS Account container in which to create the key store.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Unique name for the custom key store.",
			},
			"region": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Name of the available AWS regions.",
			},
			"enable_success_audit_event": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Enable or disable audit recording of successful operations within an external key store. Default value is false. Recommended value is false as enabling it can affect performance.",
			},
			"linked_state": schema.BoolAttribute{
				Optional:    true,
				Description: "Indicates whether the custom key store is linked with AWS. Applicable to a custom key store of type EXTERNAL_KEY_STORE. Default value is false. When false, creating a custom key store in the CCKM does not trigger the AWS KMS to create a new key store. Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked.",
			},
			"connect_disconnect_keystore": schema.StringAttribute{
				Computed: true,
				Optional: true,
			},
		},
		Blocks: map[string]schema.Block{
			"aws_param": schema.ListNestedBlock{
				Description: "Parameters related to AWS interaction with a custom key store.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"cloud_hsm_cluster_id": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Description: "ID of a CloudHSM cluster for a custom key store. Enter cluster ID of an active CloudHSM cluster that is not already associated with a custom key store. Required field for a custom key store of type AWS_CLOUDHSM.",
						},
						"connection_state": schema.StringAttribute{
							Computed: true,
						},
						"custom_key_store_id": schema.StringAttribute{
							Computed: true,
						},
						"custom_key_store_name": schema.StringAttribute{
							Computed: true,
						},
						"custom_key_store_type": schema.StringAttribute{
							Optional:    true,
							Description: "Specifies the type of custom key store. The default value is EXTERNAL_KEY_STORE. For a custom key store backed by an AWS CloudHSM cluster, the key store type is AWS_CLOUDHSM. For a custom key store backed by an HSM or key manager outside of AWS, the key store type is EXTERNAL_KEY_STORE.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"EXTERNAL_KEY_STORE", "AWS_CLOUDHSM"}...),
							},
						},
						"key_store_password": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Description: "The password of the kmsuser crypto user (CU) account configured in the specified CloudHSM cluster. This parameter does not change the password in the CloudHSM cluster. User needs to configure the credentials on the CloudHSM cluster separately. Required field for custom key store of type AWS_CLOUDHSM.",
						},
						"trust_anchor_certificate": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Description: "The contents of a CA certificate or a self-signed certificate file created during the initialization of a CloudHSM cluster. Required field for a custom key store of type AWS_CLOUDHSM",
						},
						"xks_proxy_connectivity": schema.StringAttribute{
							Optional:    true,
							Description: "Indicates how AWS KMS communicates with the Ciphertrust Manager. This field is required for a custom key store of type EXTERNAL_KEY_STORE. Default value is PUBLIC_ENDPOINT.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"VPC_ENDPOINT_SERVICE", "PUBLIC_ENDPOINT"}...),
							},
						},
						"xks_proxy_uri_endpoint": schema.StringAttribute{
							Optional:    true,
							Description: "Specifies the protocol (always HTTPS) and DNS hostname to which KMS will send XKS API requests. The DNS hostname is for either for a load balancer directing to the CipherTrust Manager or the CipherTrust Manager itself. This field is required for a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"xks_proxy_uri_path": schema.StringAttribute{
							Computed: true,
						},
						"xks_proxy_vpc_endpoint_service_name": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Description: "Indicates the VPC endpoint service name the custom key store uses. This field is required when the xks_proxy_connectivity is VPC_ENDPOINT_SERVICE.",
						},
					},
				},
			},
			"local_hosted_params": schema.ListNestedBlock{
				Description: "Parameters related to AWS interaction with a custom key store.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"blocked": schema.BoolAttribute{
							Optional:    true,
							Description: "This field indicates whether the custom key store is in a blocked or unblocked state. Default value is false, which indicates the key store is in an unblocked state. Applicable to a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"health_check_ciphertext": schema.StringAttribute{
							Computed: true,
						},
						"health_check_key_id": schema.StringAttribute{
							Optional:    true,
							Description: "ID of an existing LUNA key (if source key tier is 'hsm-luna') or CipherTrust key (if source key tier is 'local') to use for health check of the custom key store. Crypto operation would be performed using this key before creating a custom key store. Required field for custom key store of type EXTERNAL_KEY_STORE.",
						},
						"linked_state": schema.BoolAttribute{
							Computed: true,
						},
						"max_credentials": schema.Int32Attribute{
							Optional:    true,
							Description: "Max number of credentials that can be associated with custom key store (min value 2. max value 20). Required field for a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"mtls_enabled": schema.BoolAttribute{
							Optional:    true,
							Description: "Set it to true to enable tls client-side certificate verification — where cipher trust manager authenticates the AWS KMS client . Default value is false.",
						},
						"partition_id": schema.StringAttribute{
							Computed:    true,
							Optional:    true,
							Description: "ID of Luna HSM partition. Required field, if custom key store is of type EXTERNAL_KEY_STORE and source key tier is 'hsm-luna'.",
						},
						"partition_label": schema.StringAttribute{
							Computed: true,
						},
						"source_container_id": schema.StringAttribute{
							Computed: true,
						},
						"source_container_type": schema.StringAttribute{
							Computed: true,
						},
						"source_key_tier": schema.StringAttribute{
							Optional:    true,
							Description: "This field indicates whether to use Luna HSM (luna-hsm) or Ciphertrust Manager (local) as source for cryptographic keys in this key store. Default value is luna-hsm. The only value supported by the service is 'local'.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"local", "luna-hsm"}...),
							},
						},
					},
				},
			},
		},
	}
}

func (d *datasourceAWSCustomKeyStoreDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[datasource_aws_custom_key_store.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[datasource_aws_custom_key_store.go -> Read]["+id+"]")
	var state AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err := d.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AWS_XKS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [datasource_aws_custom_key_store.go -> Read]["+state.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error reading AWS Custom Key Store on CipherTrust Manager: ",
			"Could not read AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
	d.setCustomKeyStoreState(response, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *datasourceAWSCustomKeyStoreDataSource) setCustomKeyStoreState(response string, plan *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	plan.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	plan.CredentialVersion = types.StringValue(gjson.Get(response, "credential_version").String())
	plan.KMS = types.StringValue(gjson.Get(response, "kms").String())
	plan.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	plan.Type = types.StringValue(gjson.Get(response, "type").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Name = types.StringValue(gjson.Get(response, "name").String())
	plan.Region = types.StringValue(gjson.Get(response, "region").String())
	plan.EnableSuccessAuditEvent = types.BoolValue(gjson.Get(response, "enable_success_audit_event").Bool())
	plan.LinkedState = types.BoolValue(gjson.Get(response, "local_hosted_params.linked_state").Bool())
	plan.ConnectDisconnectKeystore = types.StringValue(attr.NullValueString)

	var awsParamJSONResponse AWSParamJSONResponse
	err := json.Unmarshal([]byte(gjson.Get(response, "aws_param").String()), &awsParamJSONResponse)
	if err != nil {
		diags.AddError(
			"Error Unmarshaling JSON Response",
			fmt.Sprintf("Could not unmarshal JSON response: %v", err),
		)
		return
	}
	attributeTypes := map[string]attr.Type{
		"cloud_hsm_cluster_id":                types.StringType,
		"connection_state":                    types.StringType,
		"custom_key_store_id":                 types.StringType,
		"custom_key_store_name":               types.StringType,
		"custom_key_store_type":               types.StringType,
		"key_store_password":                  types.StringType,
		"trust_anchor_certificate":            types.StringType,
		"xks_proxy_connectivity":              types.StringType,
		"xks_proxy_uri_endpoint":              types.StringType,
		"xks_proxy_uri_path":                  types.StringType,
		"xks_proxy_vpc_endpoint_service_name": types.StringType,
	}
	itemObjectType := types.ObjectType{
		AttrTypes: attributeTypes,
	}
	terraformList := make([]attr.Value, 0)
	attributeValues := map[string]attr.Value{
		"cloud_hsm_cluster_id":                types.StringValue(awsParamJSONResponse.CloudHSMClusterID),
		"connection_state":                    types.StringValue(awsParamJSONResponse.ConnectionState),
		"custom_key_store_id":                 types.StringValue(awsParamJSONResponse.CustomKeystoreID),
		"custom_key_store_name":               types.StringValue(awsParamJSONResponse.CustomKeystoreName),
		"custom_key_store_type":               types.StringValue(awsParamJSONResponse.CustomKeystoreType),
		"key_store_password":                  types.StringValue(awsParamJSONResponse.KeyStorePassword),
		"trust_anchor_certificate":            types.StringValue(awsParamJSONResponse.TrustAnchorCertificate),
		"xks_proxy_connectivity":              types.StringValue(awsParamJSONResponse.XKSProxyConnectivity),
		"xks_proxy_uri_endpoint":              types.StringValue(awsParamJSONResponse.XKSProxyURIEndpoint),
		"xks_proxy_uri_path":                  types.StringValue(awsParamJSONResponse.XKSProxyURIPath),
		"xks_proxy_vpc_endpoint_service_name": types.StringValue(awsParamJSONResponse.XKSProxyVPCEndpointServiceName),
	}
	objectValue, newDiags := types.ObjectValue(attributeTypes, attributeValues)
	diags.Append(newDiags...)
	terraformList = append(terraformList, objectValue)

	listValue, newDiags := types.ListValue(itemObjectType, terraformList)
	diags.Append(newDiags...)

	plan.AWSParams = listValue
	if diags.HasError() {
		return
	}

	var _LocalHostedParamsJSONResponse LocalHostedParamsJSONResponse
	if err := json.Unmarshal([]byte(gjson.Get(response, "local_hosted_params").String()), &_LocalHostedParamsJSONResponse); err != nil {
		diags.AddError(
			"Error Unmarshaling JSON Response",
			fmt.Sprintf("Could not unmarshal JSON response: %v", err),
		)
		return
	}
	attributeTypesLocalHostedParams := map[string]attr.Type{
		"blocked":                 types.BoolType,
		"health_check_ciphertext": types.StringType,
		"health_check_key_id":     types.StringType,
		"linked_state":            types.BoolType,
		"max_credentials":         types.Int32Type,
		"mtls_enabled":            types.BoolType,
		"partition_id":            types.StringType,
		"partition_label":         types.StringType,
		"source_container_id":     types.StringType,
		"source_container_type":   types.StringType,
		"source_key_tier":         types.StringType,
	}
	itemObjectTypeLocalHostedParams := types.ObjectType{
		AttrTypes: attributeTypesLocalHostedParams,
	}
	terraformListLocalHostedParams := make([]attr.Value, 0)
	attributeValuesLocalHostedParams := map[string]attr.Value{
		"blocked":                 types.BoolValue(_LocalHostedParamsJSONResponse.Blocked),
		"health_check_ciphertext": types.StringValue(_LocalHostedParamsJSONResponse.HealthCheckCiphertext),
		"health_check_key_id":     types.StringValue(_LocalHostedParamsJSONResponse.HealthCheckKeyID),
		"linked_state":            types.BoolValue(_LocalHostedParamsJSONResponse.LinkedState),
		"max_credentials":         types.Int32Value(_LocalHostedParamsJSONResponse.MaxCredentials),
		"mtls_enabled":            types.BoolValue(_LocalHostedParamsJSONResponse.MTLSEnabled),
		"partition_id":            types.StringValue(_LocalHostedParamsJSONResponse.PartitionID),
		"partition_label":         types.StringValue(_LocalHostedParamsJSONResponse.PartitionLabel),
		"source_container_id":     types.StringValue(_LocalHostedParamsJSONResponse.SourceContainerID),
		"source_container_type":   types.StringValue(_LocalHostedParamsJSONResponse.SourceContainerType),
		"source_key_tier":         types.StringValue(_LocalHostedParamsJSONResponse.SourceKeyTier),
	}
	objectValueLocalHostedParams, newDiagsLocalHostedParams := types.ObjectValue(attributeTypesLocalHostedParams, attributeValuesLocalHostedParams)
	diags.Append(newDiagsLocalHostedParams...)
	terraformListLocalHostedParams = append(terraformListLocalHostedParams, objectValueLocalHostedParams)

	listValueLocalHostedParams, newDiagsLocalHostedParams := types.ListValue(itemObjectTypeLocalHostedParams, terraformListLocalHostedParams)
	diags.Append(newDiagsLocalHostedParams...)

	plan.LocalHostedParams = listValueLocalHostedParams
	if diags.HasError() {
		return
	}
}
