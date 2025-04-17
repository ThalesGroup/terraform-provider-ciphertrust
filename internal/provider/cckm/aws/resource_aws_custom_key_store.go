package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceAWSCustomKeyStore{}
	_ resource.ResourceWithConfigure = &resourceAWSCustomKeyStore{}
)

const (
	StateConnectKeystore    = "CONNECT_KEYSTORE"
	StateDisconnectKeystore = "DISCONNECT_KEYSTORE"

	CustomKeystoreTypeAWSCloudHSM = "AWS_CLOUDHSM"
	StateConnected                = "CONNECTED"
	StateDisConnected             = "DISCONNECTED"
	StateFailed                   = "FAILED"
	operationRetryDelay           = 20
)

func NewResourceAWSCustomKeyStore() resource.Resource {
	return &resourceAWSCustomKeyStore{}
}

type resourceAWSCustomKeyStore struct {
	client *common.Client
}

func (r *resourceAWSCustomKeyStore) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_custom_keystore"
}

// Schema defines the schema for the resource.
func (r *resourceAWSCustomKeyStore) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"access_key_id": schema.StringAttribute{
				Computed: true,
			},
			"secret_access_key": schema.StringAttribute{
				Computed: true,
			},
			"cloud_name": schema.StringAttribute{
				Computed: true,
			},
			"credential_version": schema.StringAttribute{
				Computed: true,
			},
			"kms": schema.StringAttribute{
				Required:    true,
				Description: "Name or ID of the AWS Account container in which to create the key store.",
			},
			"kms_id": schema.StringAttribute{
				Computed: true,
			},
			"type": schema.StringAttribute{
				Computed: true,
			},
			"created_at": schema.StringAttribute{
				Computed: true,
			},
			"updated_at": schema.StringAttribute{
				Computed: true,
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique name for the custom key store.",
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "Name of the available AWS regions.",
			},
			"enable_success_audit_event": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Enable or disable audit recording of successful operations within an external key store. Default value is false. Recommended value is false as enabling it can affect performance.",
			},
			"linked_state": schema.BoolAttribute{
				Computed:    true,
				Optional:    true,
				Default:     booldefault.StaticBool(false),
				Description: "Indicates whether the custom key store is linked with AWS. Applicable to a custom key store of type EXTERNAL_KEY_STORE. Default value is false. When false, creating a custom key store in the CCKM does not trigger the AWS KMS to create a new key store. Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked.",
			},
			"connect_disconnect_keystore": schema.StringAttribute{
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
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
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
							Computed:    true,
							Optional:    true,
							Default:     booldefault.StaticBool(false),
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

// Create creates the resource and sets the initial Terraform state.
func (r *resourceAWSCustomKeyStore) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Create]["+id+"]")
	var plan AWSCustomKeyStoreTFSDK
	var payload AWSCustomKeyStoreJSON
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.KMS.ValueString() != "" && plan.KMS.ValueString() != types.StringNull().ValueString() {
		payload.KMS = common.TrimString(plan.KMS.String())
	} else {
		tflog.Debug(ctx, "kms is a mandatory parameter for this operation")
		resp.Diagnostics.AddError(
			"Missing Mandatory Parameter",
			"KMS name is a mandatory field in the create Custom Key Store Operation",
		)
		return
	}
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = common.TrimString(plan.Name.String())
	} else {
		tflog.Debug(ctx, "name is a mandatory parameter for this operation")
		resp.Diagnostics.AddError(
			"Missing Mandatory Parameter",
			"Name is a mandatory field in the create Custom Key Store Operation",
		)
		return
	}
	if plan.Region.ValueString() != "" && plan.Region.ValueString() != types.StringNull().ValueString() {
		payload.Region = common.TrimString(plan.Region.String())
	} else {
		tflog.Debug(ctx, "region is a mandatory parameter for this operation")
		resp.Diagnostics.AddError(
			"Missing Mandatory Parameter",
			"AWS Region is a mandatory field in the create Custom Key Store Operation",
		)
		return
	}
	if plan.EnableSuccessAuditEvent.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableSuccessAuditEvent = plan.EnableSuccessAuditEvent.ValueBool()
	}
	if plan.LinkedState.ValueBool() != types.BoolNull().ValueBool() {
		payload.LinkedState = plan.LinkedState.ValueBool()
	}
	var awsParamJSON AWSParamJSON
	var planAWSParamTFSDK AWSParamTFSDK
	for _, v := range plan.AWSParams.Elements() {
		resp.Diagnostics.Append(tfsdk.ValueAs(ctx, v, &planAWSParamTFSDK)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if planAWSParamTFSDK.CloudHSMClusterID.ValueString() != "" && planAWSParamTFSDK.CloudHSMClusterID.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.CloudHSMClusterID = planAWSParamTFSDK.CloudHSMClusterID.ValueString()
	}
	if planAWSParamTFSDK.CustomKeystoreType.ValueString() != "" && planAWSParamTFSDK.CustomKeystoreType.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.CustomKeystoreType = planAWSParamTFSDK.CustomKeystoreType.ValueString()
	}
	if planAWSParamTFSDK.KeyStorePassword.ValueString() != "" && planAWSParamTFSDK.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.KeyStorePassword = planAWSParamTFSDK.KeyStorePassword.ValueString()
	}
	if planAWSParamTFSDK.TrustAnchorCertificate.ValueString() != "" && planAWSParamTFSDK.TrustAnchorCertificate.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.TrustAnchorCertificate = planAWSParamTFSDK.TrustAnchorCertificate.ValueString()
	}
	if planAWSParamTFSDK.XKSProxyConnectivity.ValueString() != "" && planAWSParamTFSDK.XKSProxyConnectivity.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.XKSProxyConnectivity = planAWSParamTFSDK.XKSProxyConnectivity.ValueString()
	}
	if planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != "" && planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.XKSProxyURIEndpoint = planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString()
	}
	if planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != "" && planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.XKSProxyVPCEndpointServiceName = planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString()
	}
	payload.AWSParams = &awsParamJSON

	var LocalHostedParams LocalHostedParamsJSON
	var planLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	for _, v := range plan.LocalHostedParams.Elements() {
		resp.Diagnostics.Append(tfsdk.ValueAs(ctx, v, &planLocalHostedParamsTFSDK)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if planLocalHostedParamsTFSDK.Blocked.ValueBool() != types.BoolNull().ValueBool() {
		LocalHostedParams.Blocked = planLocalHostedParamsTFSDK.Blocked.ValueBool()
	}
	if planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != "" && planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != types.StringNull().ValueString() {
		LocalHostedParams.HealthCheckKeyID = planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString()
	}
	if !planLocalHostedParamsTFSDK.MaxCredentials.IsNull() {
		LocalHostedParams.MaxCredentials = planLocalHostedParamsTFSDK.MaxCredentials.ValueInt32()
	}
	if planLocalHostedParamsTFSDK.MTLSEnabled.ValueBool() != types.BoolNull().ValueBool() {
		LocalHostedParams.MTLSEnabled = planLocalHostedParamsTFSDK.MTLSEnabled.ValueBool()
	}
	if planLocalHostedParamsTFSDK.PartitionID.ValueString() != "" && planLocalHostedParamsTFSDK.PartitionID.ValueString() != types.StringNull().ValueString() {
		LocalHostedParams.PartitionID = planLocalHostedParamsTFSDK.PartitionID.ValueString()
	}
	if planLocalHostedParamsTFSDK.SourceKeyTier.ValueString() != "" && planLocalHostedParamsTFSDK.SourceKeyTier.ValueString() != types.StringNull().ValueString() {
		LocalHostedParams.SourceKeyTier = planLocalHostedParamsTFSDK.SourceKeyTier.ValueString()
	}
	payload.LocalHostedParams = &LocalHostedParams
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Custom Key Store Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_XKS, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating AWS Custom Key Store on CipherTrust Manager: ",
			"Could not create AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	r.setCustomKeyStoreState(ctx, response, &plan, nil, &resp.Diagnostics)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Create]["+id+"]")

	if plan.ConnectDisconnectKeystore.ValueString() != "" &&
		plan.ConnectDisconnectKeystore.ValueString() != types.StringNull().ValueString() {
		state := plan
		operationTimeOutInSeconds := 2 * 60
		if plan.ConnectDisconnectKeystore.ValueString() == StateConnectKeystore {
			if planAWSParamTFSDK.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM {
				operationTimeOutInSeconds = 21 * 60
			}
			maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay

			var payload AWSCustomKeyStoreJSON
			var awsParamJSON AWSParamJSON
			if planAWSParamTFSDK.KeyStorePassword.ValueString() != "" && planAWSParamTFSDK.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
				awsParamJSON.KeyStorePassword = common.TrimString(planAWSParamTFSDK.KeyStorePassword.String())
			}
			payload.AWSParams = &awsParamJSON
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddWarning(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
			}
			if err == nil {
				_, err = r.client.PostDataV2(
					ctx,
					plan.ID.ValueString(),
					common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/connect",
					payloadJSON)
				if err != nil {
					tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
					resp.Diagnostics.AddWarning(
						"Error updating AWS Custom Key Store on CipherTrust Manager: ",
						"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
					)
				}

				if err == nil {
					response, err = retryOperation(ctx, StateConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries, time.Duration(operationRetryDelay)*time.Second)
					if err != nil {
						resp.Diagnostics.AddWarning(
							"Error updating AWS Custom Key Store on CipherTrust Manager: ",
							"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
						)
					}
					if err == nil {
						r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
					}
				}
			}
		}
		if plan.ConnectDisconnectKeystore.ValueString() == StateDisconnectKeystore {
			var payload []byte
			if planAWSParamTFSDK.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM {
				operationTimeOutInSeconds = 11 * 60
			}
			maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay
			_, err := r.client.PostDataV2(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/disconnect",
				payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddWarning(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
			}
			if err == nil {
				response, err = retryOperation(ctx, StateDisConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries, time.Duration(operationRetryDelay)*time.Second)
				if err != nil {
					resp.Diagnostics.AddWarning(
						"Error updating AWS Custom Key Store on CipherTrust Manager: ",
						"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
					)
				}
				if err == nil {
					r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
				}
			}
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceAWSCustomKeyStore) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Read]["+id+"]")

	var state AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AWS_XKS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Read]["+state.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error reading AWS Custom Key Store on CipherTrust Manager: ",
			"Could not read AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
	r.setCustomKeyStoreState(ctx, response, &state, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceAWSCustomKeyStore) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	var plan AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var state AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var payload AWSCustomKeyStoreJSON

	var toBeUpdated bool
	if state.Name.ValueString() != plan.Name.ValueString() ||
		state.EnableSuccessAuditEvent.ValueBool() != plan.EnableSuccessAuditEvent.ValueBool() {
		toBeUpdated = true
	}
	if plan.Name.ValueString() != "" &&
		plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = common.TrimString(plan.Name.String())
	}
	if plan.EnableSuccessAuditEvent.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableSuccessAuditEvent = plan.EnableSuccessAuditEvent.ValueBool()
	}

	var awsParamJSON AWSParamJSON
	var planAWSParamTFSDK AWSParamTFSDK
	for _, v := range plan.AWSParams.Elements() {
		resp.Diagnostics.Append(tfsdk.ValueAs(ctx, v, &planAWSParamTFSDK)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	var stateAWSParamTFSDK AWSParamTFSDK
	for _, v := range state.AWSParams.Elements() {
		resp.Diagnostics.Append(tfsdk.ValueAs(ctx, v, &stateAWSParamTFSDK)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	if stateAWSParamTFSDK.CloudHSMClusterID.ValueString() != planAWSParamTFSDK.CloudHSMClusterID.ValueString() ||
		stateAWSParamTFSDK.KeyStorePassword.ValueString() != planAWSParamTFSDK.KeyStorePassword.ValueString() ||
		stateAWSParamTFSDK.XKSProxyConnectivity.ValueString() != planAWSParamTFSDK.XKSProxyConnectivity.ValueString() ||
		stateAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() ||
		stateAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() {
		toBeUpdated = true
	}

	if planAWSParamTFSDK.CloudHSMClusterID.ValueString() != "" &&
		planAWSParamTFSDK.CloudHSMClusterID.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.CloudHSMClusterID = planAWSParamTFSDK.CloudHSMClusterID.ValueString()
	}
	if planAWSParamTFSDK.KeyStorePassword.ValueString() != "" &&
		planAWSParamTFSDK.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.KeyStorePassword = planAWSParamTFSDK.KeyStorePassword.ValueString()
	}
	if planAWSParamTFSDK.XKSProxyConnectivity.ValueString() != "" &&
		planAWSParamTFSDK.XKSProxyConnectivity.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.XKSProxyConnectivity = planAWSParamTFSDK.XKSProxyConnectivity.ValueString()
	}
	if planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != "" &&
		planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.XKSProxyURIEndpoint = planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString()
	}
	if planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != "" &&
		planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.XKSProxyVPCEndpointServiceName = planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString()
	}
	payload.AWSParams = &awsParamJSON

	var planLocalHostedParams LocalHostedParamsJSON
	var planLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	for _, v := range plan.LocalHostedParams.Elements() {
		resp.Diagnostics.Append(tfsdk.ValueAs(ctx, v, &planLocalHostedParamsTFSDK)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	var stateLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	for _, v := range state.LocalHostedParams.Elements() {
		resp.Diagnostics.Append(tfsdk.ValueAs(ctx, v, &stateLocalHostedParamsTFSDK)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	if stateLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() ||
		stateLocalHostedParamsTFSDK.MTLSEnabled.ValueBool() != planLocalHostedParamsTFSDK.MTLSEnabled.ValueBool() {
		toBeUpdated = true
	}
	if planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != "" && planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != types.StringNull().ValueString() {
		planLocalHostedParams.HealthCheckKeyID = planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString()
	}
	if planLocalHostedParamsTFSDK.MTLSEnabled.ValueBool() != types.BoolNull().ValueBool() {
		planLocalHostedParams.MTLSEnabled = planLocalHostedParamsTFSDK.MTLSEnabled.ValueBool()
	}
	payload.LocalHostedParams = &planLocalHostedParams
	if toBeUpdated {
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Invalid data input: AWS Custom Key Store Update",
				err.Error(),
			)
			return
		}

		response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_AWS_XKS, payloadJSON)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Error creating AWS Custom Key Store on CipherTrust Manager: ",
				"Could not create AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
		r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
	} else if stateLocalHostedParamsTFSDK.Blocked.ValueBool() != planLocalHostedParamsTFSDK.Blocked.ValueBool() {
		if toBeBlock := planLocalHostedParamsTFSDK.Blocked.ValueBool(); toBeBlock {
			var payload []byte
			response, err := r.client.PostDataV2(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/block",
				payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		} else {
			var payload []byte
			response, err := r.client.PostDataV2(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/unblock",
				payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		}
	} else if plan.LinkedState.ValueBool() &&
		state.LinkedState.ValueBool() != plan.LinkedState.ValueBool() {
		var payload AWSCustomKeyStoreJSON
		var awsParamJSON AWSParamJSON
		if planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != "" && planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() {
			awsParamJSON.XKSProxyURIEndpoint = planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString()
		}
		if planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != types.StringNull().ValueString() {
			awsParamJSON.XKSProxyVPCEndpointServiceName = planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString()
		}
		payload.AWSParams = &awsParamJSON
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Invalid data input: AWS Custom Key Store Update",
				err.Error(),
			)
			return
		}
		response, err := r.client.PostDataV2(
			ctx,
			plan.ID.ValueString(),
			common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/link",
			payloadJSON)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Error updating AWS Custom Key Store on CipherTrust Manager: ",
				"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
		r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
	} else if plan.ConnectDisconnectKeystore.ValueString() != "" &&
		plan.ConnectDisconnectKeystore.ValueString() != types.StringNull().ValueString() &&
		plan.ConnectDisconnectKeystore.ValueString() != state.ConnectDisconnectKeystore.ValueString() {
		operationTimeOutInSeconds := 2 * 60
		if plan.ConnectDisconnectKeystore.ValueString() == StateConnectKeystore {
			if planAWSParamTFSDK.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM {
				operationTimeOutInSeconds = 21 * 60
			}
			maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay

			var payload AWSCustomKeyStoreJSON
			var awsParamJSON AWSParamJSON
			if planAWSParamTFSDK.KeyStorePassword.ValueString() != "" && planAWSParamTFSDK.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
				awsParamJSON.KeyStorePassword = common.TrimString(planAWSParamTFSDK.KeyStorePassword.String())
			}
			payload.AWSParams = &awsParamJSON
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: AWS Custom Key Store Update",
					err.Error(),
				)
				return
			}
			_, err = r.client.PostDataV2(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/connect",
				payloadJSON)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}

			response, err := retryOperation(ctx, StateConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries, time.Duration(operationRetryDelay)*time.Second)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		}
		if plan.ConnectDisconnectKeystore.ValueString() == StateDisconnectKeystore {
			var payload []byte
			if planAWSParamTFSDK.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM {
				operationTimeOutInSeconds = 11 * 60
			}
			maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay
			_, err := r.client.PostDataV2(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/disconnect",
				payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			response, err := retryOperation(ctx, StateDisConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries, time.Duration(operationRetryDelay)*time.Second)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceAWSCustomKeyStore) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AWSCustomKeyStoreTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AWS_XKS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting AWS Custom Key Store",
			"Could not delete AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceAWSCustomKeyStore) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

	d.client = client
}

func (r *resourceAWSCustomKeyStore) setCustomKeyStoreState(ctx context.Context, response string, plan *AWSCustomKeyStoreTFSDK, state *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	var (
		planAWSParamTFSDK          AWSParamTFSDK
		planLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	)
	if plan != nil {
		for _, v := range plan.AWSParams.Elements() {
			diags.Append(tfsdk.ValueAs(ctx, v, &planAWSParamTFSDK)...)
			if diags.HasError() {
				return
			}
		}
		for _, v := range plan.LocalHostedParams.Elements() {
			diags.Append(tfsdk.ValueAs(ctx, v, &planLocalHostedParamsTFSDK)...)
			if diags.HasError() {
				return
			}
		}
	}

	var (
		stateAWSParamTFSDK          AWSParamTFSDK
		stateLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	)
	if state != nil {
		for _, v := range state.AWSParams.Elements() {
			diags.Append(tfsdk.ValueAs(ctx, v, &stateAWSParamTFSDK)...)
			if diags.HasError() {
				return
			}
		}
		for _, v := range state.LocalHostedParams.Elements() {
			diags.Append(tfsdk.ValueAs(ctx, v, &stateLocalHostedParamsTFSDK)...)
			if diags.HasError() {
				return
			}
		}
	}

	plan.AccessKeyID = types.StringValue(gjson.Get(response, "access_key_id").String())
	plan.SecretAccessKey = types.StringValue(gjson.Get(response, "secret_access_key").String())
	if state != nil {
		plan.AccessKeyID = state.AccessKeyID
		plan.SecretAccessKey = state.SecretAccessKey
	}
	plan.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	plan.CredentialVersion = types.StringValue(gjson.Get(response, "credential_version").String())
	plan.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	plan.Type = types.StringValue(gjson.Get(response, "type").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

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
		"custom_key_store_type":               types.StringType,
		"key_store_password":                  types.StringType,
		"trust_anchor_certificate":            types.StringType,
		"xks_proxy_connectivity":              types.StringType,
		"xks_proxy_uri_endpoint":              types.StringType,
		"xks_proxy_vpc_endpoint_service_name": types.StringType,

		"connection_state":      types.StringType,
		"custom_key_store_id":   types.StringType,
		"custom_key_store_name": types.StringType,
		"xks_proxy_uri_path":    types.StringType,
	}
	itemObjectType := types.ObjectType{
		AttrTypes: attributeTypes,
	}
	terraformList := make([]attr.Value, 0)

	attributeValues := map[string]attr.Value{
		"cloud_hsm_cluster_id":                types.StringValue(planAWSParamTFSDK.CloudHSMClusterID.ValueString()),
		"custom_key_store_type":               types.StringValue(planAWSParamTFSDK.CustomKeystoreType.ValueString()),
		"key_store_password":                  types.StringValue(planAWSParamTFSDK.KeyStorePassword.ValueString()),
		"trust_anchor_certificate":            types.StringValue(planAWSParamTFSDK.TrustAnchorCertificate.ValueString()),
		"xks_proxy_connectivity":              types.StringValue(planAWSParamTFSDK.XKSProxyConnectivity.ValueString()),
		"xks_proxy_uri_endpoint":              types.StringValue(planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString()),
		"xks_proxy_vpc_endpoint_service_name": types.StringValue(planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString()),

		"connection_state":      types.StringValue(awsParamJSONResponse.ConnectionState),
		"custom_key_store_id":   types.StringValue(awsParamJSONResponse.CustomKeystoreID),
		"custom_key_store_name": types.StringValue(awsParamJSONResponse.CustomKeystoreName),
		"xks_proxy_uri_path":    types.StringValue(awsParamJSONResponse.XKSProxyURIPath),
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
		"blocked":             types.BoolType,
		"health_check_key_id": types.StringType,
		"max_credentials":     types.Int32Type,
		"mtls_enabled":        types.BoolType,
		"partition_id":        types.StringType,
		"source_key_tier":     types.StringType,

		"health_check_ciphertext": types.StringType,
		"linked_state":            types.BoolType,
		"partition_label":         types.StringType,
		"source_container_id":     types.StringType,
		"source_container_type":   types.StringType,
	}
	itemObjectTypeLocalHostedParams := types.ObjectType{
		AttrTypes: attributeTypesLocalHostedParams,
	}
	terraformListLocalHostedParams := make([]attr.Value, 0)
	attributeValuesLocalHostedParams := map[string]attr.Value{
		"blocked":             types.BoolValue(planLocalHostedParamsTFSDK.Blocked.ValueBool()),
		"health_check_key_id": types.StringValue(planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString()),
		"max_credentials":     types.Int32Value(planLocalHostedParamsTFSDK.MaxCredentials.ValueInt32()),
		"mtls_enabled":        types.BoolValue(planLocalHostedParamsTFSDK.MTLSEnabled.ValueBool()),
		"partition_id":        types.StringValue(planLocalHostedParamsTFSDK.PartitionID.ValueString()),
		"source_key_tier":     types.StringValue(planLocalHostedParamsTFSDK.SourceKeyTier.ValueString()),

		"health_check_ciphertext": types.StringValue(_LocalHostedParamsJSONResponse.HealthCheckCiphertext),
		"linked_state":            types.BoolValue(_LocalHostedParamsJSONResponse.LinkedState),
		"partition_label":         types.StringValue(_LocalHostedParamsJSONResponse.PartitionLabel),
		"source_container_id":     types.StringValue(_LocalHostedParamsJSONResponse.SourceContainerID),
		"source_container_type":   types.StringValue(_LocalHostedParamsJSONResponse.SourceContainerType),
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

func retryOperation(ctx context.Context, wantState string, operation func() (string, error), maxRetries int, retryDelay time.Duration) (string, error) {
	var (
		response string
		err      error
	)

	for attempt := 1; attempt <= maxRetries; attempt++ {
		response, err = operation()
		if err != nil {
			return "", err
		}
		var awsParamJSONResponse AWSParamJSONResponse
		if err := json.Unmarshal([]byte(gjson.Get(response, "aws_param").String()), &awsParamJSONResponse); err != nil {
			return "", err
		}
		if awsParamJSONResponse.ConnectionState == wantState {
			return response, nil
		}
		if awsParamJSONResponse.ConnectionState == StateFailed {
			break
		}
		tflog.Debug(ctx, fmt.Sprintf("Operation failed (attempt %d/%d): %v", attempt, maxRetries, err))
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
	}

	return "", fmt.Errorf("operation failed after %d retries: %v", maxRetries, err)
}

func (r *resourceAWSCustomKeyStore) customKeyStoreById(ctx context.Context, id string, state *AWSCustomKeyStoreTFSDK) (string, error) {
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AWS_XKS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Read]["+state.ID.ValueString()+"]")
		return "", err
	}
	return response, nil
}
