package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
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
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceAWSCustomKeyStore{}
	_ resource.ResourceWithConfigure   = &resourceAWSCustomKeyStore{}
	_ resource.ResourceWithImportState = &resourceAWSCustomKeyStore{}
	_ resource.ResourceWithModifyPlan  = &resourceAWSCustomKeyStore{}
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

func (r *resourceAWSCustomKeyStore) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSCustomKeyStore) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create and manage Custom Key Stores in CipherTrust Manager.\n\n" +
			"CipherTrust Manager provides the integration of Custom Key Stores proxy service for Amazon Web Services.\n\n" +
			"Custom Key Stores types are External Key Stores (XKS) and CloudHSM Key Stores.\n\n" +
			"\t* AWS_CLOUDHSM key stores will have keys backed by a CloudHSM cluster in AWS.\n\n" +
			"\t* EXTERNAL_KEY_STORE key stores will have keys backed by a Luna HSM or CipherTrust Manager.",
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
			"credential_version": schema.Int64Attribute{
				Computed:    true,
				Description: "Version number of the current credentials.",
			},
			"credential_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of credentials currently associated with the key store.",
			},
			"oldest_credentials_id": schema.StringAttribute{
				Computed:    true,
				Description: "ID of the oldest credentials associated with the key store.",
			},
			"version_count": schema.Int64Attribute{
				Computed:    true,
				Description: "Number of credential versions available.",
			},
			"kms_name": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the AWS KMS account container associated with this key store.",
			},
			"kms_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the AWS KMS account container in which to create the key store.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
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
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "Name of the available AWS regions.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
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
					"Once linked, it's not possible to unlink a key store. " +
					"Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked.",
			},
			"connect_disconnect_keystore": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Validators:  []validator.String{stringvalidator.OneOf([]string{StateConnectKeystore, StateDisconnectKeystore}...)},
				Description: "(Updatable) Indicates whether to connect or disconnect the custom key store.",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "A list of key:value pairs associated with the key.",
			},
			"aws_param": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Object{
					nullOrStateForUnknownObject{},
				},
				Description: "Parameters related to AWS interaction with a custom key store.",
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
						//Required: true,
						Optional: true,
						Computed: true,
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
					"connection_error_details": schema.StringAttribute{
						Computed:    true,
						Description: "Details about the last connection error, if any.",
					},
					"number_of_hsms_in_cloudhsm_cluster": schema.Int64Attribute{
						Computed:    true,
						Description: "Number of HSMs in the CloudHSM cluster.",
					},
					"aws_account_id": schema.StringAttribute{
						Computed:    true,
						Description: "AWS account ID that owns this key store.",
					},
					"arn": schema.StringAttribute{
						Computed:    true,
						Description: "Amazon Resource Name (ARN) of the custom key store.",
					},
					"xks_proxy_vpc_endpoint_service_name": schema.StringAttribute{
						Computed: true,
						Optional: true,
						MarkdownDescription: "(Updatable) Indicates the VPC endpoint service name the custom key store uses. " +
							"**Required** field when the xks_proxy_connectivity is VPC_ENDPOINT_SERVICE.",
					},
				},
			},
			"local_hosted_params": schema.SingleNestedAttribute{
				Optional: true,
				Computed: true,
				PlanModifiers: []planmodifier.Object{
					nullOrStateForUnknownObject{},
				},
				Description: "Parameters related to local hosting of a custom key store.",
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
					"health_check_uri_path": schema.StringAttribute{
						Computed:    true,
						Description: "URI path used by AWS KMS to perform health checks on this custom key store.",
					},
					"linked_state": schema.BoolAttribute{
						Computed: true,
					},
					"max_credentials": schema.Int32Attribute{
						Optional: true,
						MarkdownDescription: "Max number of credentials that can be associated with custom key store (min value 2. max value 20). " +
							"**Required** field for a custom key store of type EXTERNAL_KEY_STORE.",
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
						Optional:    true,
						Computed:    true,
						Description: "Source for cryptographic keys in this key store. The only supported value is 'local' (CipherTrust Manager).",
						Validators:  []validator.String{stringvalidator.OneOf([]string{"local"}...)},
					},
				},
			},
			"enable_credential_rotation": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "(Updatable) Enable the custom key store for scheduled credential rotation job.",
				Attributes: map[string]schema.Attribute{
					"job_config_id": schema.StringAttribute{
						Required:    true,
						Description: "(Updatable) ID of the scheduler configuration job that will schedule the AWS XKS credential rotation.",
					},
				},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{
				Create: true,
				Update: true,
				Delete: true,
				Read:   true,
			}),
		},
	}
}

// Create creates a new AWS custom key store in CipherTrust Manager and sets Terraform state.
// After the key store is successfully created, the following post-creation operations are attempted
// but only produce warnings (not errors) on failure, ensuring the key store is always saved to state:
//   - Registering the key store with a CipherTrust Manager scheduled credential rotation job
//     (enable_credential_rotation block)
//   - Connecting the key store to AWS (connect_disconnect_keystore = CONNECT_KEYSTORE)
//   - Refreshing final state from the API after all post-creation operations
func (r *resourceAWSCustomKeyStore) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Create]["+id+"]")
	var plan AWSCustomKeyStoreTFSDK
	var payload AWSCustomKeyStoreJSON
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	createTimeout, diags := plan.Timeouts.Create(ctx, 30*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, createTimeout)
	defer cancel()

	kmsID := plan.KMSID.ValueString()
	if _, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS); err != nil {
		msg := "Error creating AWS custom key store: kms_id does not resolve to a valid KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	payload.KMS = kmsID
	payload.Name = common.TrimString(plan.Name.String())
	payload.Region = common.TrimString(plan.Region.String())
	if plan.EnableSuccessAuditEvent.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableSuccessAuditEvent = plan.EnableSuccessAuditEvent.ValueBool()
	}
	if plan.LinkedState.ValueBool() != types.BoolNull().ValueBool() {
		payload.LinkedState = plan.LinkedState.ValueBool()
	}
	var awsParamJSON AWSParamJSON
	var planAWSParamTFSDK AWSCustomKeyStoreParamTFSDK
	if !plan.AWSParams.IsNull() && !plan.AWSParams.IsUnknown() {
		if d := plan.AWSParams.As(ctx, &planAWSParamTFSDK, basetypes.ObjectAsOptions{}); d.HasError() {
			resp.Diagnostics.Append(d...)
			return
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
	}

	var LocalHostedParams LocalHostedParamsJSON
	if !plan.LocalHostedParams.IsNull() && !plan.LocalHostedParams.IsUnknown() {
		var planLocalHostedParamsTFSDK LocalHostedParamsTFSDK
		if d := plan.LocalHostedParams.As(ctx, &planLocalHostedParamsTFSDK, basetypes.ObjectAsOptions{}); d.HasError() {
			resp.Diagnostics.Append(d...)
			return
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
		if planLocalHostedParamsTFSDK.PartitionID.ValueString() != "" && planLocalHostedParamsTFSDK.PartitionID.ValueString() != types.StringNull().ValueString() {
			LocalHostedParams.PartitionID = planLocalHostedParamsTFSDK.PartitionID.ValueString()
		}
		if planLocalHostedParamsTFSDK.SourceKeyTier.ValueString() != "" && planLocalHostedParamsTFSDK.SourceKeyTier.ValueString() != types.StringNull().ValueString() {
			LocalHostedParams.SourceKeyTier = planLocalHostedParamsTFSDK.SourceKeyTier.ValueString()
		}
		payload.LocalHostedParams = &LocalHostedParams
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Custom Key Store Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_XKS, payloadJSON)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating AWS Custom Key Store on CipherTrust Manager: ",
			"Could not create AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Debug(ctx, "[resource_aws_custom_key_store.go -> Create][response:"+redactAWSResponse(response)+"]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// Capture credentials from initial create response - the GET endpoint does not return them.
	createdAccessKeyID := gjson.Get(response, "access_key_id").String()
	createdSecretAccessKey := gjson.Get(response, "secret_access_key").String()

	// No error after this

	if plan.EnableCredentialRotation != nil {
		var diags diag.Diagnostics
		r.enableCredentialRotation(ctx, id, &plan, &diags)
		for _, d := range diags {
			resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
		}
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

			connectPayload := AWSCustomKeyStoreConnectPayloadJSON{
				KeyStorePassword: common.TrimString(awsParamJSON.KeyStorePassword),
			}
			payloadJSON, err := json.Marshal(connectPayload)
			if err != nil {
				tflog.Warn(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> connect]["+plan.ID.ValueString()+"]")
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
					tflog.Warn(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
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
	}

	getResponse, err := r.client.GetById(ctx, id, plan.ID.ValueString(), common.URL_AWS_XKS)
	if err != nil {
		tflog.Warn(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Create]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddWarning(
			"Error reading AWS Custom Key Store on CipherTrust Manager: ",
			"Could not read AWS Custom Key Store, unexpected error: "+err.Error(),
		)
	} else {
		response = getResponse
		tflog.Debug(ctx, "[resource_aws_custom_key_store.go -> Create][response:"+redactAWSResponse(response)+"]")
	}

	var warningDiags diag.Diagnostics
	r.setCustomKeyStoreState(ctx, response, &plan, nil, &warningDiags)
	for _, d := range warningDiags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}

	// Restore credentials captured from the initial create response if the GET response omitted them.
	if createdAccessKeyID != "" {
		plan.AccessKeyID = types.StringValue(createdAccessKeyID)
	}
	if createdSecretAccessKey != "" {
		plan.SecretAccessKey = types.StringValue(createdSecretAccessKey)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state for an AWS custom key store from CipherTrust Manager.
// If the key store is no longer found (404 / notFoundError), it is silently removed from
// Terraform state rather than returning an error, allowing Terraform to plan its recreation.
func (r *resourceAWSCustomKeyStore) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Read]["+id+"]")

	var state AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response := getAwsCustomKeyStore(ctx, r.client, id, state.ID.ValueString(), "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.setCustomKeyStoreState(ctx, response, &state, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update applies plan changes to an AWS custom key store. Changes are applied conditionally based on
// which attributes have changed. The order of precedence is:
//
//  1. If name, enable_success_audit_event, or aws_param / local_hosted_params (excluding blocked) changed:
//     the key store is updated via PATCH, then state is refreshed.
//
//  2. Else if local_hosted_params.blocked changed: the key store is blocked or unblocked.
//
//  3. Else if linked_state changed from false to true: the key store is linked to AWS.
//     (Transitioning back from linked to unlinked is not supported.)
//
//  4. Else if connect_disconnect_keystore changed: the key store is connected or disconnected.
//
//     Additionally, enable_credential_rotation is only evaluated and applied when the key store's
//     local_hosted_params.linked_state is true; it is silently skipped for unlinked key stores.
func (r *resourceAWSCustomKeyStore) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Update]["+id+"]")
	var plan AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	updateTimeout, diags := plan.Timeouts.Update(ctx, 30*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()

	var state AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	getAwsCustomKeyStore(ctx, r.client, id, state.ID.ValueString(), "updating", &resp.Diagnostics)
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
	if !plan.AWSParams.IsNull() && !plan.AWSParams.IsUnknown() {
		if d := plan.AWSParams.As(ctx, &planAWSParamTFSDK, basetypes.ObjectAsOptions{}); d.HasError() {
			resp.Diagnostics.Append(d...)
			return
		}
	}
	var stateAWSParamTFSDK AWSCustomKeyStoreParamTFSDK
	if !state.AWSParams.IsNull() && !state.AWSParams.IsUnknown() {
		if d := state.AWSParams.As(ctx, &stateAWSParamTFSDK, basetypes.ObjectAsOptions{}); d.HasError() {
			resp.Diagnostics.Append(d...)
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
	if !plan.LocalHostedParams.IsNull() && !plan.LocalHostedParams.IsUnknown() {
		if d := plan.LocalHostedParams.As(ctx, &planLocalHostedParamsTFSDK, basetypes.ObjectAsOptions{}); d.HasError() {
			resp.Diagnostics.Append(d...)
			return
		}
	}
	var stateLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	if !state.LocalHostedParams.IsNull() && !state.LocalHostedParams.IsUnknown() {
		if d := state.LocalHostedParams.As(ctx, &stateLocalHostedParamsTFSDK, basetypes.ObjectAsOptions{}); d.HasError() {
			resp.Diagnostics.Append(d...)
			return
		}
	}
	if stateLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() {
		toBeUpdated = true
	}
	if planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != "" && planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != types.StringNull().ValueString() {
		planLocalHostedParams.HealthCheckKeyID = planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString()
	}
	payload.LocalHostedParams = &planLocalHostedParams
	if toBeUpdated {
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Invalid data input: AWS Custom Key Store Update",
				err.Error(),
			)
			return
		}

		response, err := r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_AWS_XKS, payloadJSON)
		if err != nil {
			tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
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
			response, err := r.client.PostNoData(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/block")
			if err != nil {
				tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error blocking AWS Custom Key Store on CipherTrust Manager: ",
					"Could not block AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, response, &plan, &state, &resp.Diagnostics)
		} else {
			response, err := r.client.PostNoData(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/unblock")
			if err != nil {
				tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> unblock]["+plan.ID.ValueString()+"]")
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
		var linkPayload AWSCustomKeyStoreJSON
		var linkAWSParams AWSParamJSON
		if planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != "" && planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() {
			linkAWSParams.XKSProxyURIEndpoint = planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString()
		}
		if planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != types.StringNull().ValueString() {
			linkAWSParams.XKSProxyVPCEndpointServiceName = planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString()
		}
		linkPayload.AWSParams = &linkAWSParams
		payloadJSON, err := json.Marshal(linkPayload)
		if err != nil {
			tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> link]["+plan.ID.ValueString()+"]")
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
			tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> link]["+plan.ID.ValueString()+"]")
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

			connectPayload := AWSCustomKeyStoreConnectPayloadJSON{
				KeyStorePassword: common.TrimString(stateAWSParamTFSDK.KeyStorePassword.ValueString()),
			}
			payloadJSON, err := json.Marshal(connectPayload)
			if err != nil {
				tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> connect]["+plan.ID.ValueString()+"]")
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
				tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> connect]["+plan.ID.ValueString()+"]")
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
		} else if plan.ConnectDisconnectKeystore.ValueString() == StateDisconnectKeystore {
			toBeUpdatedOps = true
			if planAWSParamTFSDK.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM {
				operationTimeOutInSeconds = 11 * 60
			}
			maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay
			_, err := r.client.PostNoData(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/disconnect")
			if err != nil {
				tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> disconnect]["+plan.ID.ValueString()+"]")
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
	lastResponse := response
	linkedState := gjson.Get(response, "local_hosted_params.linked_state").Bool()
	if linkedState {
		var dg diag.Diagnostics
		updated := r.enableDisableCredentialRotation(ctx, id, &plan, &state, &dg)
		if dg.HasError() {
			resp.Diagnostics.Append(dg...)
		} else if updated {
			updatedResponse, updatedErr := r.customKeyStoreById(ctx, id, &state)
			if updatedErr != nil {
				resp.Diagnostics.AddError(
					"Error getting AWS Custom Key Store on CipherTrust Manager: ",
					"Could not get AWS Custom Key Store, unexpected error: "+updatedErr.Error(),
				)
				return
			}
			r.setCustomKeyStoreState(ctx, updatedResponse, &plan, &state, &resp.Diagnostics)
			lastResponse = updatedResponse
		}
	}
	if !(toBeUpdated || toBeUpdatedOps) {
		finalResponse, finalErr := r.customKeyStoreById(ctx, id, &state)
		if finalErr != nil {
			resp.Diagnostics.AddError(
				"Error getting AWS Custom Key Store on CipherTrust Manager: ",
				"Could not get AWS Custom Key Store, unexpected error: "+finalErr.Error(),
			)
			return
		}
		r.setCustomKeyStoreState(ctx, finalResponse, &plan, &state, &resp.Diagnostics)
		lastResponse = finalResponse
	}
	tflog.Debug(ctx, "[resource_aws_custom_key_store.go -> Update][response:"+redactAWSResponse(lastResponse)+"]")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the AWS custom key store from CipherTrust Manager.
// If the key store is not found (HTTP 404) when destroy runs, a warning is emitted and the resource is
// removed from state rather than returning an error.
func (r *resourceAWSCustomKeyStore) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> Delete]["+id+"]")
	var state AWSCustomKeyStoreTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	deleteTimeout, diags := state.Timeouts.Delete(ctx, 30*time.Minute)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, deleteTimeout)
	defer cancel()

	keystoreJSON := getAwsCustomKeyStore(ctx, r.client, id, state.ID.ValueString(), "deleting", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return // Non-404 error - key store kept in state.
	}
	if keystoreJSON == "" {
		return // Key store not found (404) - warning already added, Terraform removes from state.
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AWS_XKS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Debug(ctx, "[resource_aws_custom_key_store.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		msg := "Error deleting AWS custom key store."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": state.ID.ValueString()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
	}
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceAWSCustomKeyStore) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state AWSCustomKeyStoreTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string

	// Check immutable fields inside the aws_param block.
	if !plan.AWSParams.IsNull() && !plan.AWSParams.IsUnknown() &&
		!state.AWSParams.IsNull() && !state.AWSParams.IsUnknown() {
		var planAWSParam, stateAWSParam AWSCustomKeyStoreParamTFSDK
		resp.Diagnostics.Append(plan.AWSParams.As(ctx, &planAWSParam, basetypes.ObjectAsOptions{})...)
		resp.Diagnostics.Append(state.AWSParams.As(ctx, &stateAWSParam, basetypes.ObjectAsOptions{})...)
		if resp.Diagnostics.HasError() {
			return
		}
		if planAWSParam.CustomKeystoreType != stateAWSParam.CustomKeystoreType {
			changed = append(changed, "aws_param.custom_key_store_type")
		}
		// Guard against false positives when the field was never set in config (null)
		// but the API returned a value (e.g. empty string after create).
		if !planAWSParam.TrustAnchorCertificate.IsNull() && !planAWSParam.TrustAnchorCertificate.IsUnknown() &&
			planAWSParam.TrustAnchorCertificate != stateAWSParam.TrustAnchorCertificate {
			changed = append(changed, "aws_param.trust_anchor_certificate")
		}
	}

	// kms_id is immutable; ModifyPlan enforces this by returning an error if the value changes.
	if plan.KMSID != state.KMSID {
		changed = append(changed, "kms_id")
	}

	// Check immutable fields inside the local_hosted_params block.
	if !plan.LocalHostedParams.IsNull() && !plan.LocalHostedParams.IsUnknown() &&
		!state.LocalHostedParams.IsNull() && !state.LocalHostedParams.IsUnknown() {
		var planLHP, stateLHP LocalHostedParamsTFSDK
		resp.Diagnostics.Append(plan.LocalHostedParams.As(ctx, &planLHP, basetypes.ObjectAsOptions{})...)
		resp.Diagnostics.Append(state.LocalHostedParams.As(ctx, &stateLHP, basetypes.ObjectAsOptions{})...)
		if resp.Diagnostics.HasError() {
			return
		}
		// max_credentials is Optional-only; guard against false positives when
		// the field was never set in config (null) but the API returned a value.
		if !planLHP.MaxCredentials.IsNull() && !stateLHP.MaxCredentials.IsNull() &&
			planLHP.MaxCredentials != stateLHP.MaxCredentials {
			changed = append(changed, "local_hosted_params.max_credentials")
		}
		// Guard against false positives when the field was never set in config (null)
		// but the API returned a value (e.g. empty string after create).
		if !planLHP.PartitionID.IsNull() && !planLHP.PartitionID.IsUnknown() &&
			planLHP.PartitionID != stateLHP.PartitionID {
			changed = append(changed, "local_hosted_params.partition_id")
		}
		if planLHP.SourceKeyTier != stateLHP.SourceKeyTier {
			changed = append(changed, "local_hosted_params.source_key_tier")
		}
	}

	if plan.Region != state.Region {
		changed = append(changed, "region")
	}

	if len(changed) > 0 {
		resp.Diagnostics.AddError(
			"Immutable attribute change detected",
			fmt.Sprintf(
				"The following attributes cannot be modified after creation: %s. "+
					"Delete and recreate the resource to apply these changes.",
				strings.Join(changed, ", "),
			),
		)
	}
}

// ImportState imports an existing AWS custom key store into Terraform state using its resource ID.
func (r *resourceAWSCustomKeyStore) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// getAwsCustomKeyStore fetches an AWS custom key store from CipherTrust Manager by its ID.
// On a 404: if op is "deleting", a warning is added and "" is returned;
// any other op adds an error and returns "".
// Any non-404 API error always adds an error and returns "".
func getAwsCustomKeyStore(ctx context.Context, client *common.Client, id string, keystoreID string, op string, diags *diag.Diagnostics) string {
	response, err := client.GetById(ctx, id, keystoreID, common.URL_AWS_XKS)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			if op == "deleting" {
				msg := "AWS custom key store (" + keystoreID + ") was not found. It will be removed from state."
				details := utils.ApiError(msg, map[string]interface{}{"id": keystoreID})
				tflog.Warn(ctx, details)
				diags.AddWarning(details, "")
			} else {
				msg := "AWS custom key store (" + keystoreID + ") was not found."
				details := utils.ApiError(msg, map[string]interface{}{"id": keystoreID})
				tflog.Error(ctx, details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + op + " AWS custom key store, failed to read custom key store."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": keystoreID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// setCustomKeyStoreState populates the Terraform state for a custom key store from an API response JSON string.
func (r *resourceAWSCustomKeyStore) setCustomKeyStoreState(ctx context.Context, response string, plan *AWSCustomKeyStoreTFSDK, state *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	// Preserve key_store_password from plan (API never returns it).
	keyStorePassword := ""
	if !plan.AWSParams.IsNull() && !plan.AWSParams.IsUnknown() {
		var existing AWSCustomKeyStoreParamTFSDK
		if d := plan.AWSParams.As(ctx, &existing, basetypes.ObjectAsOptions{}); !d.HasError() {
			keyStorePassword = existing.KeyStorePassword.ValueString()
		}
	}

	plan.AccessKeyID = types.StringValue(gjson.Get(response, "access_key_id").String())
	plan.SecretAccessKey = types.StringValue(gjson.Get(response, "secret_access_key").String())
	if state != nil {
		plan.AccessKeyID = state.AccessKeyID
		plan.SecretAccessKey = state.SecretAccessKey
	}
	plan.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	plan.CredentialVersion = types.Int64Value(gjson.Get(response, "credential_version").Int())
	plan.VersionCount = types.Int64Value(gjson.Get(response, "version_count").Int())
	plan.CredentialCount = types.Int64Value(gjson.Get(response, "credential_count").Int())
	plan.OldestCredentialsID = types.StringValue(gjson.Get(response, "oldest_credentials_id").String())
	plan.KMSID = types.StringValue(gjson.Get(response, "kms_id").String())
	plan.Type = types.StringValue(gjson.Get(response, "type").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Name = types.StringValue(gjson.Get(response, "name").String())
	plan.Region = types.StringValue(gjson.Get(response, "region").String())
	plan.LinkedState = types.BoolValue(gjson.Get(response, "local_hosted_params.linked_state").Bool())
	plan.KMSName = types.StringValue(gjson.Get(response, "kms").String())
	plan.EnableSuccessAuditEvent = types.BoolValue(gjson.Get(response, "enable_success_audit_event").Bool())

	var awsParamJSONResponse AWSParamJSONResponse
	if err := json.Unmarshal([]byte(gjson.Get(response, "aws_param").String()), &awsParamJSONResponse); err != nil {
		diags.AddError(
			"Error Unmarshaling JSON Response",
			fmt.Sprintf("Could not unmarshal JSON response: %v", err),
		)
		return
	}
	plan.AWSParams = setCustomKeyStoreAwsParams(awsParamJSONResponse, keyStorePassword, diags)
	if diags.HasError() {
		return
	}

	if awsParamJSONResponse.ConnectionState == "CONNECTED" {
		plan.ConnectDisconnectKeystore = types.StringValue("CONNECT_KEYSTORE")
	} else {
		plan.ConnectDisconnectKeystore = types.StringValue("DISCONNECT_KEYSTORE")
	}

	keyStoreID := gjson.Get(response, "id").String()
	var labels types.Map
	setKeyStoreLabels(ctx, response, keyStoreID, &labels, diags)
	if diags.HasError() {
		return
	}
	plan.Labels = labels

	var lhp LocalHostedParamsJSONResponse
	if err := json.Unmarshal([]byte(gjson.Get(response, "local_hosted_params").String()), &lhp); err != nil {
		diags.AddError(
			"Error Unmarshaling JSON Response",
			fmt.Sprintf("Could not unmarshal JSON response: %v", err),
		)
		return
	}
	plan.LocalHostedParams = setCustomKeyStoreLocalHostedParams(lhp, diags)
}

// retryOperation polls the custom key store until its connection state matches wantState or the retry limit is reached.
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
		response, err = operation()
		if err != nil {
			return "", err
		}
		var awsParamJSONResponse AWSParamJSONResponse
		if err := json.Unmarshal([]byte(gjson.Get(response, "aws_param").String()), &awsParamJSONResponse); err != nil {
			return "", err
		}
		tflog.Debug(ctx, fmt.Sprintf("ConnectionState: %s (attempt %d/%d)", awsParamJSONResponse.ConnectionState, attempt, maxRetries))
		if awsParamJSONResponse.ConnectionState == wantState {
			return response, nil
		}
		if awsParamJSONResponse.ConnectionState == StateFailed {
			return "", fmt.Errorf("operation reached %s state on attempt %d", StateFailed, attempt)
		}
	}

	return "", fmt.Errorf("TIMED OUT waiting for state %s after %d attempts", wantState, maxRetries)
}

// customKeyStoreById fetches the current custom key store JSON from CipherTrust Manager by its state ID.
func (r *resourceAWSCustomKeyStore) customKeyStoreById(ctx context.Context, id string, state *AWSCustomKeyStoreTFSDK) (string, error) {
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AWS_XKS)
	if err != nil {
		tflog.Error(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_custom_key_store.go -> Read]["+state.ID.ValueString()+"]")
		return "", err
	}
	return response, nil
}

// enableDisableCredentialRotation enables or disables the CipherTrust Manager credential rotation job
// for the custom key store based on the difference between plan and state. Used by resourceAWSCustomKeyStore (Update).
// Only applied when local_hosted_params.linked_state is true (silently skipped for unlinked key stores).
// Returns true if a credential rotation change was made, false otherwise.
func (r *resourceAWSCustomKeyStore) enableDisableCredentialRotation(ctx context.Context, id string, plan *AWSCustomKeyStoreTFSDK, state *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) bool {
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_custom_key_store.go -> enableDisableCredentialRotation]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_custom_key_store.go -> enableDisableCredentialRotation]["+id+"]")

	planJobID := ""
	if plan.EnableCredentialRotation != nil {
		planJobID = plan.EnableCredentialRotation.JobConfigID.ValueString()
	}
	stateJobID := ""
	if state.EnableCredentialRotation != nil {
		stateJobID = state.EnableCredentialRotation.JobConfigID.ValueString()
	}

	updated := false
	if plan.EnableCredentialRotation == nil && state.EnableCredentialRotation != nil {
		r.disableCredentialRotation(ctx, id, plan, diags)
		if diags.HasError() {
			return false
		}
		updated = true
	} else if planJobID != stateJobID {
		r.enableCredentialRotation(ctx, id, plan, diags)
		if diags.HasError() {
			return false
		}
		updated = true
	}
	return updated
}

// enableCredentialRotation registers the custom key store with a CipherTrust Manager scheduled credential rotation job.
func (r *resourceAWSCustomKeyStore) enableCredentialRotation(ctx context.Context, id string, plan *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	if plan.EnableCredentialRotation == nil {
		return
	}
	keyStoreID := plan.ID.ValueString()
	payload := AWSEnableXksCredentialRotationJobPayloadJSON{
		JobConfigID: plan.EnableCredentialRotation.JobConfigID.ValueString(),
	}
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
	tflog.Info(ctx, fmt.Sprintf("[resource_aws_custom_key_store.go -> enableCredentialRotation] credential rotation enabled successfully. keystore_id: %s", keyStoreID))
	tflog.Debug(ctx, "[resource_aws_custom_key_store.go -> enableCredentialRotation][response:"+redactAWSResponse(response)+"]")
}

// disableCredentialRotation removes the custom key store from its scheduled CipherTrust Manager credential rotation job.
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
	tflog.Info(ctx, fmt.Sprintf("[resource_aws_custom_key_store.go -> disableCredentialRotation] credential rotation disabled successfully. keystore_id: %s", keyStoreID))
	tflog.Debug(ctx, "[resource_aws_custom_key_store.go -> disableCredentialRotation][response:"+redactAWSResponse(response)+"]")
}

// awsCustomKeyStoreParamAttrTypes returns the attribute type map for the aws_param
// Object used in AWSCustomKeyStoreCommonTFSDK. Used by both resource and datasource.
func awsCustomKeyStoreParamAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"cloud_hsm_cluster_id":                types.StringType,
		"connection_state":                    types.StringType,
		"connection_error_details":            types.StringType,
		"custom_key_store_id":                 types.StringType,
		"custom_key_store_name":               types.StringType,
		"custom_key_store_type":               types.StringType,
		"key_store_password":                  types.StringType,
		"number_of_hsms_in_cloudhsm_cluster":  types.Int64Type,
		"trust_anchor_certificate":            types.StringType,
		"xks_proxy_connectivity":              types.StringType,
		"xks_proxy_uri_endpoint":              types.StringType,
		"xks_proxy_uri_path":                  types.StringType,
		"xks_proxy_vpc_endpoint_service_name": types.StringType,
		"aws_account_id":                      types.StringType,
		"arn":                                 types.StringType,
	}
}

// setCustomKeyStoreAwsParams constructs a types.Object for the aws_param block
// from an unmarshalled API response. keyStorePassword is preserved from plan state
// because the API never returns it. Used by both resource and datasource setCustomKeyStoreState.
func setCustomKeyStoreAwsParams(p AWSParamJSONResponse, keyStorePassword string, diags *diag.Diagnostics) types.Object {
	attrTypes := awsCustomKeyStoreParamAttrTypes()
	numHSMs := int64(0)
	if p.NumberOfHSMsInCloudHSMCluster != nil {
		numHSMs = int64(*p.NumberOfHSMsInCloudHSMCluster)
	}
	attrValues := map[string]attr.Value{
		"cloud_hsm_cluster_id":                types.StringValue(p.CloudHSMClusterID),
		"connection_state":                    types.StringValue(p.ConnectionState),
		"connection_error_details":            types.StringValue(p.ConnectionErrorDetails),
		"custom_key_store_id":                 types.StringValue(p.CustomKeystoreID),
		"custom_key_store_name":               types.StringValue(p.CustomKeystoreName),
		"custom_key_store_type":               types.StringValue(p.CustomKeystoreType),
		"key_store_password":                  types.StringValue(keyStorePassword),
		"number_of_hsms_in_cloudhsm_cluster":  types.Int64Value(numHSMs),
		"trust_anchor_certificate":            types.StringValue(p.TrustAnchorCertificate),
		"xks_proxy_connectivity":              types.StringValue(p.XKSProxyConnectivity),
		"xks_proxy_uri_endpoint":              types.StringValue(p.XKSProxyURIEndpoint),
		"xks_proxy_uri_path":                  types.StringValue(p.XKSProxyURIPath),
		"xks_proxy_vpc_endpoint_service_name": types.StringValue(p.XKSProxyVPCEndpointServiceName),
		"aws_account_id":                      types.StringValue(p.AWSAccountID),
		"arn":                                 types.StringValue(p.Arn),
	}
	obj, d := types.ObjectValue(attrTypes, attrValues)
	diags.Append(d...)
	return obj
}

// localHostedParamsAttrTypes returns the attribute type map for the local_hosted_params
// Object used in AWSCustomKeyStoreCommonTFSDK. Used by both resource and datasource.
func localHostedParamsAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"blocked":                 types.BoolType,
		"health_check_ciphertext": types.StringType,
		"health_check_key_id":     types.StringType,
		"health_check_uri_path":   types.StringType,
		"linked_state":            types.BoolType,
		"max_credentials":         types.Int32Type,
		"partition_id":            types.StringType,
		"partition_label":         types.StringType,
		"source_container_id":     types.StringType,
		"source_container_type":   types.StringType,
		"source_key_tier":         types.StringType,
	}
}

// setCustomKeyStoreLocalHostedParams constructs a types.Object for the local_hosted_params block
// from an unmarshalled API response. Used by both resource and datasource setCustomKeyStoreState.
func setCustomKeyStoreLocalHostedParams(p LocalHostedParamsJSONResponse, diags *diag.Diagnostics) types.Object {
	attrTypes := localHostedParamsAttrTypes()
	attrValues := map[string]attr.Value{
		"blocked":                 types.BoolValue(p.Blocked),
		"health_check_ciphertext": types.StringValue(p.HealthCheckCiphertext),
		"health_check_key_id":     types.StringValue(p.HealthCheckKeyID),
		"health_check_uri_path":   types.StringValue(p.HealthCheckURIPath),
		"linked_state":            types.BoolValue(p.LinkedState),
		"max_credentials":         types.Int32Value(p.MaxCredentials),
		"partition_id":            types.StringValue(p.PartitionID),
		"partition_label":         types.StringValue(p.PartitionLabel),
		"source_container_id":     types.StringValue(p.SourceContainerID),
		"source_container_type":   types.StringValue(p.SourceContainerType),
		"source_key_tier":         types.StringValue(p.SourceKeyTier),
	}
	obj, d := types.ObjectValue(attrTypes, attrValues)
	diags.Append(d...)
	return obj
}

// setKeyStoreLabels parses the custom key store labels from the API response and stores them in Terraform state.
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
