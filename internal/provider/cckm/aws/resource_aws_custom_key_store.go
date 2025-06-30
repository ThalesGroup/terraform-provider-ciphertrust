package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceAWSCustomKeyStore{}
	_ resource.ResourceWithConfigure   = &resourceAWSCustomKeyStore{}
	_ resource.ResourceWithImportState = &resourceAWSCustomKeyStore{}
)

const (
	StateConnectKeystore          = "CONNECT_KEYSTORE"
	StateDisconnectKeystore       = "DISCONNECT_KEYSTORE"
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
func (r *resourceAWSCustomKeyStore) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage Custom Key Stores in CipherTrust Manager." +
			"CipherTrust Manager provides the integration of Custom Key Stores proxy service for Amazon Web Services.\n\n" +
			"Custom Key Stores type are External Key Stores (XKS) and CloudHSM Key Stores.\n\n" +
			"AWS_CLOUDHSM key stores will have keys backed by a CloudHSM cluster in AWS.\n\n" +
			"EXTERNAL_KEY_STORE key stores will have keys backed by a Luna HSM or CipherTrust Manager.",
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
				Description: "(Updatable) Unique name for the custom key store.",
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "Name of the available AWS regions.",
			},
			"enable_success_audit_event": schema.BoolAttribute{
				Computed: true,
				Optional: true,
				Default:  booldefault.StaticBool(false),
				Description: "(Updatable) Enable or disable audit recording of successful operations within an external key store. " +
					"Default value is false. Recommended value is false as enabling it can affect performance.",
			},
			"linked_state": schema.BoolAttribute{
				Computed: true,
				Optional: true,
				Default:  booldefault.StaticBool(false),
				Description: "(Updatable) Indicates whether the custom key store is linked with AWS. " +
					"Applicable to a custom key store of type EXTERNAL_KEY_STORE. Default value is false. " +
					"When false, creating a custom key store in the CCKM does not trigger the AWS KMS to create a new key store. " +
					"Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked.",
			},
			"connect_disconnect_keystore": schema.StringAttribute{
				Optional:    true,
				Validators:  []validator.String{stringvalidator.OneOf([]string{StateConnectKeystore, StateDisconnectKeystore}...)},
				Description: "(Updatable) Indicates whether to connect or disconnect the custom key store.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
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
							Computed: true,
							Optional: true,
							MarkdownDescription: "(Updatable) ID of a CloudHSM cluster for a custom key store. " +
								"Enter cluster ID of an active CloudHSM cluster that is not already associated with a custom key store. " +
								"**Required** field for a custom key store of type AWS_CLOUDHSM.",
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
							Required: true,
							Description: "Specifies the type of custom key store. " +
								"For a custom key store backed by an AWS CloudHSM cluster, the key store type is AWS_CLOUDHSM. " +
								"For a custom key store backed by an HSM or key manager outside of AWS, the key store type is EXTERNAL_KEY_STORE.",
							Validators: []validator.String{stringvalidator.OneOf([]string{"EXTERNAL_KEY_STORE", "AWS_CLOUDHSM"}...)},
						},
						"key_store_password": schema.StringAttribute{
							Computed: true,
							Optional: true,
							MarkdownDescription: "(Updatable) The password of the kmsuser crypto user (CU) account configured in the specified CloudHSM cluster. " +
								"This parameter does not change the password in the CloudHSM cluster. " +
								"User needs to configure the credentials on the CloudHSM cluster separately. " +
								"**Required** field for custom key store of type AWS_CLOUDHSM.",
						},
						"trust_anchor_certificate": schema.StringAttribute{
							Computed: true,
							Optional: true,
							MarkdownDescription: "The contents of a CA certificate or a self-signed certificate file created during the initialization of a CloudHSM cluster. " +
								"**Required** field for a custom key store of type AWS_CLOUDHSM",
						},
						"xks_proxy_connectivity": schema.StringAttribute{
							Optional: true,
							Computed: true,
							MarkdownDescription: "(Updatable) Indicates how AWS KMS communicates with the Ciphertrust Manager. " +
								"**Required** field for a custom key store of type EXTERNAL_KEY_STORE. " +
								"Default value is PUBLIC_ENDPOINT.",
							Validators: []validator.String{stringvalidator.OneOf([]string{"VPC_ENDPOINT_SERVICE", "PUBLIC_ENDPOINT"}...)},
						},
						"xks_proxy_uri_endpoint": schema.StringAttribute{
							Optional: true,
							Computed: true,
							MarkdownDescription: "(Updatable) Specifies the protocol (always HTTPS) and DNS hostname to which KMS will send XKS API requests. " +
								"The DNS hostname is for either for a load balancer directing to the CipherTrust Manager or the CipherTrust Manager itself. " +
								"**Required** field for a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"xks_proxy_uri_path": schema.StringAttribute{
							Computed: true,
						},
						"xks_proxy_vpc_endpoint_service_name": schema.StringAttribute{
							Computed: true,
							Optional: true,
							MarkdownDescription: "(Updatable) Indicates the VPC endpoint service name the custom key store uses. " +
								"**Required** field when the xks_proxy_connectivity is VPC_ENDPOINT_SERVICE.",
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
							Computed: true,
							Optional: true,
							Default:  booldefault.StaticBool(false),
							Description: "(Updatable) This field indicates whether the custom key store is in a blocked or unblocked state. " +
								"Default value is false, which indicates the key store is in an unblocked state. " +
								"Applicable to a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"health_check_ciphertext": schema.StringAttribute{
							Computed: true,
						},
						"health_check_key_id": schema.StringAttribute{
							Optional: true,
							Computed: true,
							MarkdownDescription: "(Updatable) ID of an existing LUNA key (if source key tier is 'hsm-luna') or CipherTrust Manager key (if source key tier is 'local') to use for health check of the custom key store. " +
								"Crypto operation would be performed using this key before creating a custom key store. " +
								"**Required** field for custom key store of type EXTERNAL_KEY_STORE.",
						},
						"linked_state": schema.BoolAttribute{
							Computed: true,
						},
						"max_credentials": schema.Int32Attribute{
							Optional: true,
							MarkdownDescription: "Max number of credentials that can be associated with custom key store (min value 2. max value 20). " +
								"**Required** field for a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"mtls_enabled": schema.BoolAttribute{
							Computed: true,
							Optional: true,
							Default:  booldefault.StaticBool(false),
							Description: "(Updatable) Set it to true to enable tls client-side certificate verification — where CipherTrust manager authenticates the AWS KMS client. +" +
								"Default value is false.",
						},
						"partition_id": schema.StringAttribute{
							Computed: true,
							Optional: true,
							MarkdownDescription: "ID of Luna HSM partition. " +
								"**Required** field, if custom key store is of type EXTERNAL_KEY_STORE and source key tier is 'hsm-luna'.",
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
							Optional: true,
							Computed: true,
							Description: "This field indicates whether to use Luna HSM (luna-hsm) or Ciphertrust Manager (local) as source for cryptographic keys in this key store. " +
								"Default value is luna-hsm. The only value supported by the service is 'local'.",
							Validators: []validator.String{stringvalidator.OneOf([]string{"local", "luna-hsm"}...)},
						},
					},
				},
			},
			"enable_credential_rotation": schema.ListNestedBlock{
				Description: "(Updatable) Enable the custom key store for scheduled credential rotation job.",
				Validators: []validator.List{
					listvalidator.SizeAtMost(1),
				},
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"job_config_id": schema.StringAttribute{
							Required:    true,
							Description: "(Updatable) ID of the scheduler configuration job that will schedule the AWS XKS credential rotation.",
						},
					},
				},
			},
			"timeouts": timeouts.Block(ctx, timeouts.Opts{
				Create: true,
				Update: true,
				Delete: true,
				Read:   true,
			}),
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
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeouts, diags := plan.Timeouts.Create(ctx, 30*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeouts)
	defer cancel()

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
	var planAWSParamTFSDK AWSCustomKeyStoreParamTFSDK
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
		cert := planAWSParamTFSDK.TrustAnchorCertificate.ValueString()
		cert = strings.Replace(cert, "\r\n", "\n", -1)
		awsParamJSON.TrustAnchorCertificate = cert
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

	if len(plan.EnableCredentialRotation.Elements()) != 0 {
		var diags diag.Diagnostics
		r.enableCredentialRotation(ctx, id, &plan, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
	}

	var warningDiags diag.Diagnostics
	r.setCustomKeyStoreState(ctx, response, &plan, nil, &warningDiags)
	for _, d := range warningDiags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}

	if plan.ConnectDisconnectKeystore.ValueString() != "" &&
		plan.ConnectDisconnectKeystore.ValueString() != types.StringNull().ValueString() {
		state := plan
		operationTimeOutInSeconds := 2 * 60
		if plan.ConnectDisconnectKeystore.ValueString() == StateConnectKeystore {
			if planAWSParamTFSDK.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM {
				operationTimeOutInSeconds = 21 * 60
			}
			maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay

			payload := AWSCustomKeyStoreConnectPayloadJSON{
				KeyStorePassword: common.TrimString(awsParamJSON.KeyStorePassword),
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> connect]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddWarning(
					"Error connecting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not connect AWS Custom Key Store, unexpected error: "+err.Error(),
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
						"Error connecting AWS Custom Key Store on CipherTrust Manager: ",
						"Could not connect AWS Custom Key Store, unexpected error: "+err.Error(),
					)
				}

				if err == nil {
					response, err = r.retryOperation(ctx, id, StateConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries)
					if err != nil {
						resp.Diagnostics.AddWarning(
							"Error connecting AWS Custom Key Store on CipherTrust Manager: ",
							"Could not connect AWS Custom Key Store, unexpected error: "+err.Error(),
						)
					}
					if err == nil {
						var warningDiags diag.Diagnostics
						r.setCustomKeyStoreState(ctx, response, &plan, &state, &warningDiags)
						for _, d := range warningDiags {
							resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
						}
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
					"Error disconnecting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not disconnect AWS Custom Key Store, unexpected error: "+err.Error(),
				)
			}
			if err == nil {
				response, err = r.retryOperation(ctx, id, StateDisConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries)
				if err != nil {
					resp.Diagnostics.AddWarning(
						"Error disconnecting AWS Custom Key Store on CipherTrust Manager: ",
						"Could not disconnect AWS Custom Key Store, unexpected error: "+err.Error(),
					)
				}
				if err == nil {
					var warningDiags diag.Diagnostics
					r.setCustomKeyStoreState(ctx, response, &plan, &state, &warningDiags)
					for _, d := range warningDiags {
						resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
					}
				}
			}
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
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
	tflog.Trace(ctx, "[resource_aws_custom_key_store.go -> Read][response:"+response)
	r.setCustomKeyStoreState(ctx, response, &state, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *resourceAWSCustomKeyStore) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go.go -> ImportState]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)

	keyStoreID := req.ID
	response, err := r.client.GetById(ctx, id, keyStoreID, common.URL_AWS_XKS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> ImportState]["+keyStoreID+"]")
		resp.Diagnostics.AddError(
			"Error reading AWS Custom Key Store on CipherTrust Manager: ",
			"Could not read AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
	var state AWSCustomKeyStoreTFSDK
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.KMS = types.StringValue(gjson.Get(response, "kms_id").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Region = types.StringValue(gjson.Get(response, "region").String())
	state.KMS = types.StringValue(gjson.Get(response, "kms").String())

	var plan AWSCustomKeyStoreTFSDK
	r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	state.Labels = plan.Labels
	state.LocalHostedParams = plan.LocalHostedParams
	state.AWSParams = plan.AWSParams

	var timeoutAttribs = map[string]attr.Type{
		"create": types.StringType,
		"update": types.StringType,
		"read":   types.StringType,
		"delete": types.StringType,
	}
	type timeout struct {
		Create types.String `tfsdk:"create"`
		Update types.String `tfsdk:"update"`
		Read   types.String `tfsdk:"read"`
		Delete types.String `tfsdk:"delete"`
	}
	timeoutValues := timeout{
		types.StringValue("30m"),
		types.StringValue("30m"),
		types.StringValue("5m"),
		types.StringValue("5m"),
	}
	var diags diag.Diagnostics
	var timeoutObjectValue basetypes.ObjectValue
	timeoutObjectValue, diags = types.ObjectValueFrom(ctx, timeoutAttribs, &timeoutValues)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	var timeoutObject types.Object
	timeoutObject, diags = timeoutObjectValue.ToObjectValue(ctx)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	state.Timeouts = timeouts.Value{Object: timeoutObject}

	var credRotationAttribs = map[string]attr.Type{
		"job_config_id": types.StringType,
	}
	type credRotationTFSDK struct {
		JobConfigId types.String `tfsdk:"job_config_id"`
	}
	credRotationValues := []credRotationTFSDK{{
		JobConfigId: types.StringValue(""),
	}}
	var credRotationListValue basetypes.ListValue
	credRotationListValue, diags = types.ListValueFrom(ctx, types.ObjectType{AttrTypes: credRotationAttribs}, &credRotationValues)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	state.EnableCredentialRotation, diags = credRotationListValue.ToListValue(ctx)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceAWSCustomKeyStore) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go.go -> Update]["+id+"]")
	var plan AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeouts, diags := plan.Timeouts.Update(ctx, 30*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeouts)
	defer cancel()

	var state AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var payload AWSCustomKeyStoreJSON

	var toBeUpdated bool
	var toBeUpdatedOps bool
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
	var planAWSParamTFSDK AWSCustomKeyStoreParamTFSDK
	for _, v := range plan.AWSParams.Elements() {
		resp.Diagnostics.Append(tfsdk.ValueAs(ctx, v, &planAWSParamTFSDK)...)
		if resp.Diagnostics.HasError() {
			return
		}
	}
	var stateAWSParamTFSDK AWSCustomKeyStoreParamTFSDK
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
				"Error updating AWS Custom Key Store on CipherTrust Manager: ",
				"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
		r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
	} else if stateLocalHostedParamsTFSDK.Blocked.ValueBool() != planLocalHostedParamsTFSDK.Blocked.ValueBool() {
		toBeUpdatedOps = true
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
					"Error blocking AWS Custom Key Store on CipherTrust Manager: ",
					"Could not block AWS Custom Key Store, unexpected error: "+err.Error(),
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
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> unblock]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error unblocking AWS Custom Key Store on CipherTrust Manager: ",
					"Could not unblock AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		}
	} else if plan.LinkedState.ValueBool() &&
		state.LinkedState.ValueBool() != plan.LinkedState.ValueBool() {
		toBeUpdatedOps = true
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
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> link]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Invalid data input: AWS Custom Key Store link",
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
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> link]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Error linking AWS Custom Key Store on CipherTrust Manager: ",
				"Could not link AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
		r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
	} else if plan.ConnectDisconnectKeystore.ValueString() != "" &&
		plan.ConnectDisconnectKeystore.ValueString() != types.StringNull().ValueString() &&
		plan.ConnectDisconnectKeystore.ValueString() != state.ConnectDisconnectKeystore.ValueString() {
		operationTimeOutInSeconds := 2 * 60
		if plan.ConnectDisconnectKeystore.ValueString() == StateConnectKeystore {
			toBeUpdatedOps = true
			if planAWSParamTFSDK.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM {
				operationTimeOutInSeconds = 21 * 60
			}
			maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay

			payload := AWSCustomKeyStoreConnectPayloadJSON{
				KeyStorePassword: common.TrimString(stateAWSParamTFSDK.KeyStorePassword.ValueString()),
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> connect]["+plan.ID.ValueString()+"]")
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
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> connect]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error connecting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not connect AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}

			response, err := r.retryOperation(ctx, id, StateConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error connecting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not connect AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		}
		if plan.ConnectDisconnectKeystore.ValueString() == StateDisconnectKeystore {
			toBeUpdatedOps = true
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
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> disconnect]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error disconnecting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not disconnect AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			response, err := r.retryOperation(ctx, id, StateDisConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, &state) }, maxOperationRetries)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error disconnecting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not disconnect AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		}
	}
	response, err := r.customKeyStoreById(ctx, id, &state)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error getting AWS Custom Key Store on CipherTrust Manager: ",
			"Could not get AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
	linkedState := gjson.Get(response, "local_hosted_params.linked_state").Bool()
	if linkedState {
		var dg diag.Diagnostics
		updated := r.enableDisableCredentialRotation(ctx, id, &plan, &state, &dg)
		if dg.HasError() {
			resp.Diagnostics.Append(dg...)
		} else if updated {
			response, err := r.customKeyStoreById(ctx, id, &state)
			if err != nil {
				resp.Diagnostics.AddError(
					"Error getting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not get AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		}
	}
	if !(toBeUpdated || toBeUpdatedOps) {
		response, err := r.customKeyStoreById(ctx, id, &state)
		if err != nil {
			resp.Diagnostics.AddError(
				"Error getting AWS Custom Key Store on CipherTrust Manager: ",
				"Could not get AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
		r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
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

	timeouts, diags := state.Timeouts.Update(ctx, 30*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeouts)
	defer cancel()

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AWS_XKS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		if strings.Contains(err.Error(), "Resource not found") {
			msg := "AWS custom key stores was not found, it will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"id": state.ID.ValueString()})
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
		} else {
			resp.Diagnostics.AddError(
				"Error Deleting AWS Custom Key Store",
				"Could not delete AWS Custom Key Store, unexpected error: "+err.Error(),
			)
		}
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
		planAWSParamTFSDK          AWSCustomKeyStoreParamTFSDK
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
		stateAWSParamTFSDK          AWSCustomKeyStoreParamTFSDK
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
		"connection_state":                    types.StringType,
		"custom_key_store_id":                 types.StringType,
		"custom_key_store_name":               types.StringType,
		"xks_proxy_uri_path":                  types.StringType,
	}
	itemObjectType := types.ObjectType{
		AttrTypes: attributeTypes,
	}
	terraformList := make([]attr.Value, 0)

	attributeValues := map[string]attr.Value{
		"cloud_hsm_cluster_id":                types.StringValue(awsParamJSONResponse.CloudHSMClusterID),
		"custom_key_store_type":               types.StringValue(awsParamJSONResponse.CustomKeystoreType),
		"key_store_password":                  types.StringValue(planAWSParamTFSDK.KeyStorePassword.ValueString()),
		"trust_anchor_certificate":            types.StringValue(awsParamJSONResponse.TrustAnchorCertificate),
		"xks_proxy_connectivity":              types.StringValue(awsParamJSONResponse.XKSProxyConnectivity),
		"xks_proxy_uri_endpoint":              types.StringValue(awsParamJSONResponse.XKSProxyURIEndpoint),
		"xks_proxy_vpc_endpoint_service_name": types.StringValue(awsParamJSONResponse.XKSProxyVPCEndpointServiceName),
		"connection_state":                    types.StringValue(awsParamJSONResponse.ConnectionState),
		"custom_key_store_id":                 types.StringValue(awsParamJSONResponse.CustomKeystoreID),
		"custom_key_store_name":               types.StringValue(awsParamJSONResponse.CustomKeystoreName),
		"xks_proxy_uri_path":                  types.StringValue(awsParamJSONResponse.XKSProxyURIPath),
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

	keyStoreID := gjson.Get(response, "id").String()
	var labels types.Map
	setKeyStoreLabels(ctx, response, keyStoreID, &labels, diags)
	if diags.HasError() {
		return
	}
	plan.Labels = labels

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
		"health_check_key_id":     types.StringType,
		"max_credentials":         types.Int32Type,
		"mtls_enabled":            types.BoolType,
		"partition_id":            types.StringType,
		"source_key_tier":         types.StringType,
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
		"blocked":                 types.BoolValue(_LocalHostedParamsJSONResponse.Blocked),
		"health_check_key_id":     types.StringValue(_LocalHostedParamsJSONResponse.HealthCheckKeyID),
		"max_credentials":         types.Int32Value(_LocalHostedParamsJSONResponse.MaxCredentials),
		"mtls_enabled":            types.BoolValue(_LocalHostedParamsJSONResponse.MTLSEnabled),
		"partition_id":            types.StringValue(_LocalHostedParamsJSONResponse.PartitionID),
		"source_key_tier":         types.StringValue(_LocalHostedParamsJSONResponse.SourceKeyTier),
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

func (r *resourceAWSCustomKeyStore) retryOperation(ctx context.Context, id string, wantState string, operation func() (string, error), maxRetries int) (string, error) {
	var (
		response string
		err      error
	)
	retryDelay := time.Duration(operationRetryDelay) * time.Second
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt < maxRetries {
			time.Sleep(retryDelay)
		}
		if err := r.client.RefreshToken(ctx, id); err != nil {
			return "", err
		}
		response, err = operation()
		if err != nil {
			return "", err
		}
		var awsParamJSONResponse AWSParamJSONResponse
		if err := json.Unmarshal([]byte(gjson.Get(response, "aws_param").String()), &awsParamJSONResponse); err != nil {
			return "", err
		}
		tflog.Trace(ctx, fmt.Sprintf("ConnectionState: %s (attempt %d/%d)", awsParamJSONResponse.ConnectionState, attempt, maxRetries))
		if awsParamJSONResponse.ConnectionState == wantState {
			return response, nil
		}
		if awsParamJSONResponse.ConnectionState == StateFailed {
			break
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

func (r *resourceAWSCustomKeyStore) enableDisableCredentialRotation(ctx context.Context, id string, plan *AWSCustomKeyStoreTFSDK, state *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) bool {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> enableDisableCredentialRotation]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> enableDisableCredentialRotation]["+id+"]")
	planParams := make([]AWSEnableXksCredentialRotationJobTFSDK, 0, len(plan.EnableCredentialRotation.Elements()))
	if !plan.EnableCredentialRotation.IsUnknown() {
		diags.Append(plan.EnableCredentialRotation.ElementsAs(ctx, &planParams, false)...)
		if diags.HasError() {
			return false
		}
	}
	stateParams := make([]AWSEnableXksCredentialRotationJobTFSDK, 0, len(state.EnableCredentialRotation.Elements()))
	diags.Append(state.EnableCredentialRotation.ElementsAs(ctx, &stateParams, false)...)
	if diags.HasError() {
		return false
	}
	updated := false
	if len(planParams) == 0 && len(stateParams) != 0 {
		r.disableCredentialRotation(ctx, id, plan, diags)
		if diags.HasError() {
			return false
		}
		updated = true
	}
	if !reflect.DeepEqual(planParams, stateParams) {
		r.enableCredentialRotation(ctx, id, plan, diags)
		if diags.HasError() {
			return false
		}
		updated = true
	}
	return updated
}

func (r *resourceAWSCustomKeyStore) enableCredentialRotation(ctx context.Context, id string, plan *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	rotationParams := make([]AWSEnableXksCredentialRotationJobTFSDK, 0, len(plan.EnableCredentialRotation.Elements()))
	if !plan.EnableCredentialRotation.IsUnknown() {
		diags.Append(plan.EnableCredentialRotation.ElementsAs(ctx, &rotationParams, false)...)
		if diags.HasError() {
			return
		}
	}
	for _, params := range rotationParams {
		payload := AWSEnableXksCredentialRotationJobPayloadJSON{
			JobConfigID: params.JobConfigID.ValueString(),
		}
		keyStoreID := plan.ID.ValueString()
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			msg := "Failed to enable credential rotation for custom key store, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "keystore_id": keyStoreID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_XKS+"/"+keyStoreID+"/enable-credential-rotation-job", payloadJSON)
		if err != nil {
			msg := "Failed to enable credential rotation for AWS key store."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "keystore_id": keyStoreID})
			tflog.Error(ctx, details)
			diags.AddError(details, "")
			return
		}
		tflog.Trace(ctx, "[resource_aws_custom_key_store.go -> enableCredentialRotation][response:"+response)
	}
}

func (r *resourceAWSCustomKeyStore) disableCredentialRotation(ctx context.Context, id string, plan *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	keyStoreID := plan.ID.ValueString()
	response, err := r.client.PostNoData(ctx, id, common.URL_AWS_XKS+"/"+keyStoreID+"/disable-credential-rotation-job")
	if err != nil {
		msg := "Error updating custom key store, failed to disable credential rotation job for AWS key store."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "keystore_id": keyStoreID})
		diags.AddError(details, "")
		tflog.Error(ctx, details)
		return
	}
	tflog.Trace(ctx, "[resource_aws_custom_key_store -> disableCredentialRotation][response:"+response)
}

func setKeyStoreLabels(ctx context.Context, response string, keyStoreID string, stateLabels *types.Map, diags *diag.Diagnostics) {
	labels := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			msg := "Error setting state for custom keystore labels, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "keystore_id": keyStoreID})
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
