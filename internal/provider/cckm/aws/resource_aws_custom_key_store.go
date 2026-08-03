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
	StateConnecting               = "CONNECTING"
	StateDisConnected             = "DISCONNECTED"
	StateDisconnecting            = "DISCONNECTING"
	StateFailed                   = "FAILED"
	operationRetryDelay           = 20
	// maxStableStateWaitSeconds is the ceiling used when waiting for an in-progress
	// connect/disconnect to reach a stable state before we issue our own command.
	// 21 minutes covers the longest observed CloudHSM connect time.
	maxStableStateWaitSeconds = 21 * 60
	// defaultConnectTimeoutSeconds is the polling ceiling for a standard connect or disconnect.
	defaultConnectTimeoutSeconds = 2 * 60
	// cloudHSMConnectTimeoutSeconds is the polling ceiling for a CloudHSM connect operation.
	cloudHSMConnectTimeoutSeconds = 21 * 60
	// cloudHSMDisconnectTimeoutSeconds is the polling ceiling for a CloudHSM disconnect operation.
	cloudHSMDisconnectTimeoutSeconds = 11 * 60
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
			"\t* EXTERNAL_KEY_STORE key stores will have keys backed by CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
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
				Description: "Name of an available AWS region.",
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
				Description: "(Updatable) Indicates whether the custom key store is linked with AWS. " +
					"Applicable to a custom key store of type EXTERNAL_KEY_STORE. " +
					"Defaults to false when not set. When false, creating a custom key store in the CCKM does not trigger the AWS KMS to create a new key store. " +
					"Once linked, it is not possible to unlink a key store. " +
					"Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked. " +
					"For AWS_CLOUDHSM key stores this field is computed; do not set it explicitly.",
			},
			"connect_disconnect_keystore": schema.StringAttribute{
				Optional:   true,
				Computed:   true,
				Validators: []validator.String{stringvalidator.OneOf([]string{StateConnectKeystore, StateDisconnectKeystore}...)},
				Description: "(Updatable) Indicates whether to connect or disconnect the custom key store. " +
					"Cannot be set at creation time; connect or disconnect via update after the key store is created.",
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
						MarkdownDescription: "(Updatable) Specifies the protocol (always HTTPS) and DNS hostname to which KMS sends XKS API requests. " +
							"The DNS hostname can be either a load balancer directing requests to CipherTrust Manager or the CipherTrust Manager instance itself. " +
							"**Required** for a custom key store of type EXTERNAL_KEY_STORE. " +
							"For **CDSPaaS**, the endpoint is `https://xks.<cdspaas>.dpondemand.io`; " +
							"for **on-premises** deployments, use the HTTPS address of the CipherTrust Manager instance."},
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
							"Only applicable to LOCAL custom key stores (XKS proxy hosted on CipherTrust Manager).",
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
				Optional: true,
				Description: "(Updatable) Enable the custom key store for scheduled credential rotation job. " +
					"Only applicable to LOCAL custom key stores (XKS proxy hosted on CipherTrust Manager) that are in a linked state (linked_state = true) " +
					"and whose connection state is CONNECTED or DISCONNECTED. " +
					"Cannot be set at creation time; enable credential rotation via update after the key store is created.",
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
// linked_state and local_hosted_params.blocked may be set at creation time.
// Post-creation operations such as connecting/disconnecting and credential rotation
// must be applied via update after the key store is created.
func (r *resourceAWSCustomKeyStore) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_custom_key_store.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_custom_key_store.go -> Create][" + id + "]")
	var plan AWSCustomKeyStoreTFSDK

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
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	payload := AWSCustomKeyStoreJSON{
		KMS:    kmsID,
		Name:   common.TrimString(plan.Name.String()),
		Region: common.TrimString(plan.Region.String()),
	}
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
			cert = strings.ReplaceAll(cert, "\r\n", "\n")
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
	var planLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	if !plan.LocalHostedParams.IsNull() && !plan.LocalHostedParams.IsUnknown() {
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
		if planLocalHostedParamsTFSDK.SourceKeyTier.ValueString() != "" && planLocalHostedParamsTFSDK.SourceKeyTier.ValueString() != types.StringNull().ValueString() {
			LocalHostedParams.SourceKeyTier = planLocalHostedParamsTFSDK.SourceKeyTier.ValueString()
		}
		payload.LocalHostedParams = &LocalHostedParams
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Custom Key Store Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_XKS, payloadJSON)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating AWS Custom Key Store on CipherTrust Manager: ",
			"Could not create AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Debug("[resource_aws_custom_key_store.go -> Create][response:" + redactAWSResponse(response) + "]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())

	// No error after this

	getResponse, err := r.client.GetById(ctx, id, plan.ID.ValueString(), common.URL_AWS_XKS)
	if err != nil {
		r.client.Log.Warn(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> Create][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddWarning(
			"Error reading AWS Custom Key Store on CipherTrust Manager: ",
			"Could not read AWS Custom Key Store, unexpected error: "+err.Error(),
		)
	} else {
		response = getResponse
		r.client.Log.Debug("[resource_aws_custom_key_store.go -> Create][response:" + redactAWSResponse(response) + "]")
	}

	var warningDiags diag.Diagnostics
	r.setCustomKeyStoreState(ctx, response, &plan, &warningDiags)
	for _, d := range warningDiags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state for an AWS custom key store from CipherTrust Manager.
// If the key store is no longer found (404 / notFoundError), it is silently removed from
// Terraform state rather than returning an error, allowing Terraform to plan its recreation.
func (r *resourceAWSCustomKeyStore) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_custom_key_store.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_custom_key_store.go -> Read][" + id + "]")

	var state AWSCustomKeyStoreTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	response := getAwsCustomKeyStore(ctx, r.client, id, state.ID.ValueString(), "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.setCustomKeyStoreState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update applies plan changes to an AWS custom key store. Changes are applied in the following order,
// and each step runs independently (multiple steps may execute in a single apply).
// Note: steps 1, 3, 5, and 6 only take effect for LOCAL key stores (XKS proxy hosted on
// CipherTrust); they are not supported for REMOTE or CLOUDHSM key stores.
//
//  1. If local_hosted_params.blocked is transitioning from true to false: the key store is unblocked.
//
//  2. If name, enable_success_audit_event, or aws_param / local_hosted_params (excluding blocked) changed:
//     the key store is updated via PATCH.
//
//  3. If linked_state changed from false to true: the key store is linked to AWS.
//     (Transitioning back from linked to unlinked is not supported.)
//
//  4. If connect_disconnect_keystore changed: the key store is connected or disconnected.
//
//  5. If local_hosted_params.blocked is transitioning from false to true: the key store is blocked.
//
//  6. Enable\disable credential rotation.
func (r *resourceAWSCustomKeyStore) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_custom_key_store.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_custom_key_store.go -> Update][" + id + "]")
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

	var response string
	var err error

	response = getAwsCustomKeyStore(ctx, r.client, id, state.ID.ValueString(), "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_aws_custom_key_store.go -> Update][response:" + redactAWSResponse(response) + "]")

	// Unlinking is not supported once a key store has been linked to AWS.
	// Only check when linked_state is explicitly set to false (not null/omitted).
	// Catch this early to avoid a confusing "inconsistent result after apply" error.
	if !plan.LinkedState.IsNull() && !plan.LinkedState.IsUnknown() && !plan.LinkedState.ValueBool() && gjson.Get(response, "local_hosted_params.linked_state").Bool() {
		resp.Diagnostics.AddError(
			"Cannot unlink an AWS custom key store",
			"Once a custom key store has been linked to AWS, it cannot be unlinked. "+
				"Remove the linked_state = false setting or set linked_state = true to match the current state.",
		)
		return
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

	var planLocalHostedParams LocalHostedParamsJSON
	var planLocalHostedParamsTFSDK LocalHostedParamsTFSDK
	if !plan.LocalHostedParams.IsNull() && !plan.LocalHostedParams.IsUnknown() {
		if d := plan.LocalHostedParams.As(ctx, &planLocalHostedParamsTFSDK, basetypes.ObjectAsOptions{}); d.HasError() {
			resp.Diagnostics.Append(d...)
			return
		}
	}

	// Step 1: Unblock the key store before any other operations.
	actualBlocked := gjson.Get(response, "local_hosted_params.blocked").Bool()
	if actualBlocked && !planLocalHostedParamsTFSDK.Blocked.ValueBool() {
		response, err = r.client.PostNoData(
			ctx,
			plan.ID.ValueString(),
			common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/unblock")
		if err != nil {
			r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> unblock][" + plan.ID.ValueString() + "]")
			resp.Diagnostics.AddError(
				"Error unblocking AWS Custom Key Store on CipherTrust Manager: ",
				"Could not unblock AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
	}

	var payload AWSCustomKeyStoreJSON
	var toBeUpdated bool

	actualName := gjson.Get(response, "name").String()
	if plan.Name.ValueString() != "" &&
		plan.Name.ValueString() != types.StringNull().ValueString() &&
		common.TrimString(plan.Name.String()) != actualName {
		payload.Name = common.TrimString(plan.Name.String())
		toBeUpdated = true
	}

	actualAuditEvent := gjson.Get(response, "enable_success_audit_event").Bool()
	if plan.EnableSuccessAuditEvent.ValueBool() != actualAuditEvent {
		payload.EnableSuccessAuditEvent = plan.EnableSuccessAuditEvent.ValueBool()
		toBeUpdated = true
	}

	actualCloudHSMClusterID := gjson.Get(response, "aws_param.cloud_hsm_cluster_id").String()
	if planAWSParamTFSDK.CloudHSMClusterID.ValueString() != "" &&
		planAWSParamTFSDK.CloudHSMClusterID.ValueString() != types.StringNull().ValueString() &&
		planAWSParamTFSDK.CloudHSMClusterID.ValueString() != actualCloudHSMClusterID {
		awsParamJSON.CloudHSMClusterID = planAWSParamTFSDK.CloudHSMClusterID.ValueString()
		toBeUpdated = true
		payload.AWSParams = &awsParamJSON
	}

	if planAWSParamTFSDK.KeyStorePassword.ValueString() != "" &&
		planAWSParamTFSDK.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
		awsParamJSON.KeyStorePassword = planAWSParamTFSDK.KeyStorePassword.ValueString()
		toBeUpdated = true
		payload.AWSParams = &awsParamJSON
	}

	actualXKSProxyConnectivity := gjson.Get(response, "aws_param.xks_proxy_connectivity").String()
	if planAWSParamTFSDK.XKSProxyConnectivity.ValueString() != "" &&
		planAWSParamTFSDK.XKSProxyConnectivity.ValueString() != types.StringNull().ValueString() &&
		planAWSParamTFSDK.XKSProxyConnectivity.ValueString() != actualXKSProxyConnectivity {
		awsParamJSON.XKSProxyConnectivity = planAWSParamTFSDK.XKSProxyConnectivity.ValueString()
		toBeUpdated = true
		payload.AWSParams = &awsParamJSON
	}

	actualXKSProxyURIEndpoint := gjson.Get(response, "aws_param.xks_proxy_uri_endpoint").String()
	if planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != "" &&
		planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() &&
		planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString() != actualXKSProxyURIEndpoint {
		awsParamJSON.XKSProxyURIEndpoint = planAWSParamTFSDK.XKSProxyURIEndpoint.ValueString()
		toBeUpdated = true
		payload.AWSParams = &awsParamJSON
	}

	actualXKSProxyVPCEndpointServiceName := gjson.Get(response, "aws_param.xks_proxy_vpc_endpoint_service_name").String()
	if planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != "" &&
		planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != types.StringNull().ValueString() &&
		planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString() != actualXKSProxyVPCEndpointServiceName {
		awsParamJSON.XKSProxyVPCEndpointServiceName = planAWSParamTFSDK.XKSProxyVPCEndpointServiceName.ValueString()
		toBeUpdated = true
		payload.AWSParams = &awsParamJSON
	}

	actualHealthCheckKeyID := gjson.Get(response, "local_hosted_params.health_check_key_id").String()
	if planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != "" &&
		planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != types.StringNull().ValueString() &&
		planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString() != actualHealthCheckKeyID {
		planLocalHostedParams.HealthCheckKeyID = planLocalHostedParamsTFSDK.HealthCheckKeyID.ValueString()
		toBeUpdated = true
		payload.LocalHostedParams = &planLocalHostedParams
	}

	// Step 2: Patch the key store if any patchable fields changed.
	if toBeUpdated {
		var payloadJSON []byte
		payloadJSON, err = json.Marshal(payload)
		if err != nil {
			r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> Update][" + plan.ID.ValueString() + "]")
			resp.Diagnostics.AddError(
				"Invalid data input: AWS Custom Key Store Update",
				err.Error(),
			)
			return
		}

		response, err = r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_AWS_XKS, payloadJSON)
		if err != nil {
			r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> Update][" + plan.ID.ValueString() + "]")
			resp.Diagnostics.AddError(
				"Error updating AWS Custom Key Store on CipherTrust Manager: ",
				"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
	}

	// Step 3: Link the key store to AWS if linked_state is transitioning to true.
	response = r.linkKeyStore(ctx, id, &plan, &planAWSParamTFSDK, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// Step 4: Connect or disconnect the key store.
	if plan.ConnectDisconnectKeystore.ValueString() != "" &&
		plan.ConnectDisconnectKeystore.ValueString() != types.StringNull().ValueString() {
		response = r.connectDisconnectKeyStore(
			ctx,
			id,
			plan.ConnectDisconnectKeystore.ValueString(),
			planAWSParamTFSDK.CustomKeystoreType.ValueString(),
			stateAWSParamTFSDK.KeyStorePassword.ValueString(),
			&state,
			response,
			&resp.Diagnostics,
		)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Step 5: Block the key store after all other operations.
	actualBlockedNow := gjson.Get(response, "local_hosted_params.blocked").Bool()
	if !actualBlockedNow && planLocalHostedParamsTFSDK.Blocked.ValueBool() {
		response, err = r.client.PostNoData(
			ctx,
			plan.ID.ValueString(),
			common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/block")
		if err != nil {
			r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> block][" + plan.ID.ValueString() + "]")
			resp.Diagnostics.AddError(
				"Error blocking AWS Custom Key Store on CipherTrust Manager: ",
				"Could not block AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return
		}
	}

	// Step 6: Enable\disable credential rotation
	r.enableDisableCredentialRotation(ctx, id, &plan, response, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	response = getAwsCustomKeyStore(ctx, r.client, id, state.ID.ValueString(), "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_aws_custom_key_store.go -> Update][final response:" + redactAWSResponse(response) + "]")

	r.setCustomKeyStoreState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete deletes the AWS custom key store from CipherTrust Manager.
// If the key store is not found (HTTP 404) when destroy runs, a warning is emitted and the resource is
// removed from state rather than returning an error.
func (r *resourceAWSCustomKeyStore) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_custom_key_store.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_custom_key_store.go -> Delete][" + id + "]")
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
	r.client.Log.Debug("[resource_aws_custom_key_store.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
	if err != nil {
		msg := "Error deleting AWS custom key store."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": state.ID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
	}
}

// ModifyPlan validates create-time restrictions and errors at plan time if any immutable attribute
// is changed on an existing resource.
func (r *resourceAWSCustomKeyStore) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip destroy operations.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Create-time validations (no prior state).
	if req.State.Raw.IsNull() {
		var plan AWSCustomKeyStoreTFSDK
		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
		if resp.Diagnostics.HasError() {
			return
		}

		// Determine the key store type from aws_param (if provided).
		var planAWSParam AWSCustomKeyStoreParamTFSDK
		if !plan.AWSParams.IsNull() && !plan.AWSParams.IsUnknown() {
			resp.Diagnostics.Append(plan.AWSParams.As(ctx, &planAWSParam, basetypes.ObjectAsOptions{})...)
			if resp.Diagnostics.HasError() {
				return
			}
		}
		isCloudHSM := planAWSParam.CustomKeystoreType.ValueString() == CustomKeystoreTypeAWSCloudHSM

		// CloudHSM key stores are always linked by AWS; explicitly setting linked_state = false is invalid.
		if isCloudHSM && !plan.LinkedState.IsNull() && !plan.LinkedState.IsUnknown() && !plan.LinkedState.ValueBool() {
			resp.Diagnostics.AddError(
				"Invalid attribute for AWS_CLOUDHSM key store",
				"AWS_CLOUDHSM key stores are always linked. Do not set linked_state = false for a CloudHSM key store.",
			)
		}

		// connect_disconnect_keystore cannot be set at creation time.
		if plan.ConnectDisconnectKeystore.ValueString() != "" &&
			plan.ConnectDisconnectKeystore.ValueString() != types.StringNull().ValueString() {
			resp.Diagnostics.AddError(
				"Cannot connect or disconnect a key store at creation time",
				"connect_disconnect_keystore cannot be set at creation time. "+
					"Create the key store first, then connect or disconnect via update.",
			)
		}

		// enable_credential_rotation cannot be set at creation time.
		if plan.EnableCredentialRotation != nil {
			resp.Diagnostics.AddError(
				"Cannot enable credential rotation at creation time",
				"enable_credential_rotation cannot be set at creation time. "+
					"Create the key store first, then enable credential rotation via update.",
			)
		}

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
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_custom_key_store.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_custom_key_store.go -> ImportState][" + id + "]")
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
				client.Log.Warn(details)
				diags.AddWarning(details, "")
			} else {
				msg := fmt.Sprintf(utils.NotFoundRetainedFmt, "AWS custom key store")
				details := utils.ApiError(msg, map[string]interface{}{"id": keystoreID})
				client.Log.Error(details)
				diags.AddError(details, "")
			}
			return ""
		}
		msg := "Error " + op + " AWS custom key store, failed to read custom key store."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "id": keystoreID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return ""
	}
	return response
}

// setCustomKeyStoreState populates the Terraform state for a custom key store from an API response JSON string.
func (r *resourceAWSCustomKeyStore) setCustomKeyStoreState(ctx context.Context, response string, plan *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	// Preserve key_store_password from plan (API never returns it).
	keyStorePassword := ""
	if !plan.AWSParams.IsNull() && !plan.AWSParams.IsUnknown() {
		var existing AWSCustomKeyStoreParamTFSDK
		if d := plan.AWSParams.As(ctx, &existing, basetypes.ObjectAsOptions{}); !d.HasError() {
			keyStorePassword = existing.KeyStorePassword.ValueString()
		}
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
	setKeyStoreLabels(ctx, r.client, response, keyStoreID, &labels, diags)
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

// linkKeyStore links the custom key store to AWS KMS if plan.LinkedState is true and the key store
// is not yet linked (as reported by currentResponse). It is a no-op when already linked or when
// linked_state is false. Returns the latest response string; on error, appends to diags and
// returns currentResponse unchanged.
func (r *resourceAWSCustomKeyStore) linkKeyStore(
	ctx context.Context,
	id string,
	plan *AWSCustomKeyStoreTFSDK,
	planAWSParamTFSDK *AWSCustomKeyStoreParamTFSDK,
	currentResponse string,
	diags *diag.Diagnostics,
) string {
	if !plan.LinkedState.ValueBool() {
		return currentResponse
	}
	if gjson.Get(currentResponse, "local_hosted_params.linked_state").Bool() {
		r.client.Log.Debug("[linkKeyStore] key store is already linked; skipping")
		return currentResponse
	}

	keystoreID := plan.ID.ValueString()
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
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [linkKeyStore][" + keystoreID + "]")
		diags.AddError("Invalid data input: AWS Custom Key Store link", err.Error())
		return currentResponse
	}
	resp, err := r.client.PostDataV2(ctx, keystoreID, common.URL_AWS_XKS+"/"+keystoreID+"/link", payloadJSON)
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [linkKeyStore][" + keystoreID + "]")
		diags.AddError(
			"Error linking AWS Custom Key Store on CipherTrust Manager: ",
			"Could not link AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return currentResponse
	}
	_ = id // id is the trace UUID; kept in signature for consistency with other helpers
	return resp
}

// waitForStableConnectionState polls the custom key store until its connection_state is no longer
// CONNECTING or DISCONNECTING (i.e., it has settled into CONNECTED, DISCONNECTED, or FAILED).
// Unlike retryOperation, this function does not treat FAILED as an error - the caller inspects
// the returned state and decides whether to proceed with a connect or disconnect command.
func (r *resourceAWSCustomKeyStore) waitForStableConnectionState(ctx context.Context, id string, state *AWSCustomKeyStoreTFSDK, maxRetries int) (string, error) {
	retryDelay := time.Duration(operationRetryDelay) * time.Second
	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			time.Sleep(retryDelay)
		}
		response, err := r.customKeyStoreById(ctx, id, state)
		if err != nil {
			return "", err
		}
		var p AWSParamJSONResponse
		if err := json.Unmarshal([]byte(gjson.Get(response, "aws_param").String()), &p); err != nil {
			return "", err
		}
		r.client.Log.Debug(fmt.Sprintf("waitForStableConnectionState: %s (attempt %d/%d)", p.ConnectionState, attempt, maxRetries))
		if p.ConnectionState != StateConnecting && p.ConnectionState != StateDisconnecting {
			return response, nil
		}
	}
	return "", fmt.Errorf("TIMED OUT waiting for stable connection state after %d attempts", maxRetries)
}

// connectDisconnectKeyStore connects or disconnects the custom key store depending on operation
// (StateConnectKeystore or StateDisconnectKeystore). It first waits for any in-progress
// CONNECTING/DISCONNECTING transition to settle, then issues the appropriate command only when
// the current state requires it (e.g. skips connect if already CONNECTED). Returns the latest
// API response string; on error, appends to diags and returns currentResponse unchanged.
func (r *resourceAWSCustomKeyStore) connectDisconnectKeyStore(
	ctx context.Context,
	id string,
	operation string,
	customKeystoreType string,
	keyStorePassword string,
	state *AWSCustomKeyStoreTFSDK,
	currentResponse string,
	diags *diag.Diagnostics,
) string {
	if operation == "" || operation == types.StringNull().ValueString() {
		return currentResponse
	}

	currentConnectionState := gjson.Get(currentResponse, "aws_param.connection_state").String()
	if currentConnectionState == StateConnecting || currentConnectionState == StateDisconnecting {
		r.client.Log.Debug(fmt.Sprintf("[connectDisconnectKeyStore] connection_state is %s; waiting for stable state", currentConnectionState))
		maxWaitRetries := maxStableStateWaitSeconds / operationRetryDelay
		resp, err := r.waitForStableConnectionState(ctx, id, state, maxWaitRetries)
		if err != nil {
			diags.AddError("Error waiting for AWS Custom Key Store connection state to stabilize: ", err.Error())
			return currentResponse
		}
		currentResponse = resp
		currentConnectionState = gjson.Get(currentResponse, "aws_param.connection_state").String()
		r.client.Log.Debug(fmt.Sprintf("[connectDisconnectKeyStore] stable connection_state: %s", currentConnectionState))
	}

	operationTimeOutInSeconds := defaultConnectTimeoutSeconds
	keystoreID := state.ID.ValueString()

	if operation == StateConnectKeystore {
		if currentConnectionState != StateDisConnected && currentConnectionState != StateFailed {
			r.client.Log.Debug(fmt.Sprintf("[connectDisconnectKeyStore] skipping connect: connection_state is %s", currentConnectionState))
			return currentResponse
		}
		if customKeystoreType == CustomKeystoreTypeAWSCloudHSM {
			operationTimeOutInSeconds = cloudHSMConnectTimeoutSeconds
		}
		maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay
		connectPayload := AWSCustomKeyStoreConnectPayloadJSON{
			KeyStorePassword: common.TrimString(keyStorePassword),
		}
		payloadJSON, err := json.Marshal(connectPayload)
		if err != nil {
			r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [connectDisconnectKeyStore -> connect][" + keystoreID + "]")
			diags.AddError("Invalid data input: AWS Custom Key Store connect", err.Error())
			return currentResponse
		}
		_, err = r.client.PostDataV2(ctx, keystoreID, common.URL_AWS_XKS+"/"+keystoreID+"/connect", payloadJSON)
		if err != nil {
			r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [connectDisconnectKeyStore -> connect][" + keystoreID + "]")
			diags.AddError(
				"Error connecting AWS Custom Key Store on CipherTrust Manager: ",
				"Could not connect AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return currentResponse
		}
		resp, err := r.retryOperation(ctx, StateConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, state) }, maxOperationRetries)
		if err != nil {
			diags.AddError(
				"Error connecting AWS Custom Key Store on CipherTrust Manager: ",
				"Could not connect AWS Custom Key Store, unexpected error: "+err.Error(),
			)
			return currentResponse
		}
		return resp
	}

	// DISCONNECT_KEYSTORE
	if currentConnectionState != StateConnected {
		r.client.Log.Debug(fmt.Sprintf("[connectDisconnectKeyStore] skipping disconnect: connection_state is %s", currentConnectionState))
		return currentResponse
	}
	if customKeystoreType == CustomKeystoreTypeAWSCloudHSM {
		operationTimeOutInSeconds = cloudHSMDisconnectTimeoutSeconds
	}
	maxOperationRetries := operationTimeOutInSeconds / operationRetryDelay
	_, err := r.client.PostNoData(ctx, keystoreID, common.URL_AWS_XKS+"/"+keystoreID+"/disconnect")
	if err != nil {
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [connectDisconnectKeyStore -> disconnect][" + keystoreID + "]")
		diags.AddError(
			"Error disconnecting AWS Custom Key Store on CipherTrust Manager: ",
			"Could not disconnect AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return currentResponse
	}
	resp, err := r.retryOperation(ctx, StateDisConnected, func() (string, error) { return r.customKeyStoreById(ctx, id, state) }, maxOperationRetries)
	if err != nil {
		diags.AddError(
			"Error disconnecting AWS Custom Key Store on CipherTrust Manager: ",
			"Could not disconnect AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return currentResponse
	}
	return resp
}

// retryOperation polls the custom key store until its connection state matches wantState or the retry limit is reached.
func (r *resourceAWSCustomKeyStore) retryOperation(_ context.Context, wantState string, operation func() (string, error), maxRetries int) (string, error) {
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
		r.client.Log.Debug(fmt.Sprintf("ConnectionState: %s (attempt %d/%d)", awsParamJSONResponse.ConnectionState, attempt, maxRetries))
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
		r.client.Log.Error(common.ERR_METHOD_END + err.Error() + " [resource_aws_custom_key_store.go -> Read][" + state.ID.ValueString() + "]")
		return "", err
	}
	return response, nil
}

// enableDisableCredentialRotation enables or disables the CipherTrust Manager credential rotation job
// for the custom key store based on the difference between plan and the actual API state (response).
// The actual current job_config_id is read from labels.job_config_id in the API response.
func (r *resourceAWSCustomKeyStore) enableDisableCredentialRotation(ctx context.Context, id string, plan *AWSCustomKeyStoreTFSDK, response string, diags *diag.Diagnostics) {
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_custom_key_store.go -> enableDisableCredentialRotation][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_custom_key_store.go -> enableDisableCredentialRotation][" + id + "]")

	planJobID := ""
	if plan.EnableCredentialRotation != nil {
		planJobID = plan.EnableCredentialRotation.JobConfigID.ValueString()
	}
	actualJobID := gjson.Get(response, "labels.job_config_id").String()

	if plan.EnableCredentialRotation == nil && actualJobID != "" {
		r.disableCredentialRotation(ctx, id, plan, diags)
	} else if planJobID != actualJobID {
		r.enableCredentialRotation(ctx, id, plan, diags)
	}
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
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_XKS+"/"+keyStoreID+"/enable-credential-rotation-job", payloadJSON)
	if err != nil {
		msg := "Failed to enable credential rotation for AWS key store."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "keystore_id": keyStoreID})
		r.client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	r.client.Log.Info(fmt.Sprintf("[resource_aws_custom_key_store.go -> enableCredentialRotation] credential rotation enabled successfully. keystore_id: %s", keyStoreID))
	r.client.Log.Debug("[resource_aws_custom_key_store.go -> enableCredentialRotation][response:" + redactAWSResponse(response) + "]")
}

// disableCredentialRotation removes the custom key store from its scheduled CipherTrust Manager credential rotation job.
func (r *resourceAWSCustomKeyStore) disableCredentialRotation(ctx context.Context, id string, plan *AWSCustomKeyStoreTFSDK, diags *diag.Diagnostics) {
	keyStoreID := plan.ID.ValueString()
	response, err := r.client.PostNoData(ctx, id, common.URL_AWS_XKS+"/"+keyStoreID+"/disable-credential-rotation-job")
	if err != nil {
		msg := "Error updating custom key store, failed to disable credential rotation job for AWS key store."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "keystore_id": keyStoreID})
		diags.AddError(details, "")
		r.client.Log.Error(details)
		return
	}
	r.client.Log.Info(fmt.Sprintf("[resource_aws_custom_key_store.go -> disableCredentialRotation] credential rotation disabled successfully. keystore_id: %s", keyStoreID))
	r.client.Log.Debug("[resource_aws_custom_key_store.go -> disableCredentialRotation][response:" + redactAWSResponse(response) + "]")
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
		"source_container_id":     types.StringValue(p.SourceContainerID),
		"source_container_type":   types.StringValue(p.SourceContainerType),
		"source_key_tier":         types.StringValue(p.SourceKeyTier),
	}
	obj, d := types.ObjectValue(attrTypes, attrValues)
	diags.Append(d...)
	return obj
}

// setKeyStoreLabels parses the custom key store labels from the API response and stores them in Terraform state.
func setKeyStoreLabels(ctx context.Context, client *common.Client, response string, keyStoreID string, stateLabels *types.Map, diags *diag.Diagnostics) {
	labels := make(map[string]string)
	if gjson.Get(response, "labels").Exists() {
		labelsJSON := gjson.Get(response, "labels").Raw
		if err := json.Unmarshal([]byte(labelsJSON), &labels); err != nil {
			msg := "Error setting state for custom keystore labels, invalid data input."
			details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "keystore_id": keyStoreID})
			client.Log.Error(details)
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
