package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceAWSCustomKeyStore{}
	_ resource.ResourceWithConfigure = &resourceAWSCustomKeyStore{}
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
			"aws_param": schema.ListNestedAttribute{
				Required:    true,
				Description: "Parameters related to AWS interaction with a custom key store.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"cloud_hsm_cluster_id": schema.StringAttribute{
							Required:    false,
							Description: "The contents of a CA certificate or a self-signed certificate file created during the initialization of a CloudHSM cluster. Required field for a custom key store of type AWS_CLOUDHSM.",
						},
						"custom_key_store_type": schema.StringAttribute{
							Required:    false,
							Description: "Specifies the type of custom key store. The default value is EXTERNAL_KEY_STORE. For a custom key store backed by an AWS CloudHSM cluster, the key store type is AWS_CLOUDHSM. For a custom key store backed by an HSM or key manager outside of AWS, the key store type is EXTERNAL_KEY_STORE.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"EXTERNAL_KEY_STORE", "AWS_CLOUDHSM"}...),
							},
						},
						"key_store_password": schema.StringAttribute{
							Required:    false,
							Description: "The password of the kmsuser crypto user (CU) account configured in the specified CloudHSM cluster. This parameter does not change the password in the CloudHSM cluster. User needs to configure the credentials on the CloudHSM cluster separately. Required field for custom key store of type AWS_CLOUDHSM.",
						},
						"trust_anchor_certificate": schema.StringAttribute{
							Required:    false,
							Description: "The contents of a CA certificate or a self-signed certificate file created during the initialization of a CloudHSM cluster. Required field for a custom key store of type AWS_CLOUDHSM",
						},
						"xks_proxy_connectivity": schema.StringAttribute{
							Optional:    false,
							Description: "Indicates how AWS KMS communicates with the Ciphertrust Manager. This field is required for a custom key store of type EXTERNAL_KEY_STORE. Default value is PUBLIC_ENDPOINT.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"VPC_ENDPOINT_SERVICE", "PUBLIC_ENDPOINT"}...),
							},
						},
						"xks_proxy_uri_endpoint": schema.StringAttribute{
							Optional:    false,
							Description: "Specifies the protocol (always HTTPS) and DNS hostname to which KMS will send XKS API requests. The DNS hostname is for either for a load balancer directing to the CipherTrust Manager or the CipherTrust Manager itself. This field is required for a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"xks_proxy_vpc_endpoint_service_name": schema.StringAttribute{
							Optional:    false,
							Description: "Indicates the VPC endpoint service name the custom key store uses. This field is required when the xks_proxy_connectivity is VPC_ENDPOINT_SERVICE.",
						},
					},
				},
			},
			"kms": schema.StringAttribute{
				Optional:    true,
				Description: "Name or ID of the AWS Account container in which to create the key store.",
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Unique name for the custom key store.",
			},
			"region": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the available AWS regions.",
			},
			"enable_success_audit_event": schema.BoolAttribute{
				Optional:    true,
				Description: "Enable or disable audit recording of successful operations within an external key store. Default value is false. Recommended value is false as enabling it can affect performance.",
			},
			"linked_state": schema.BoolAttribute{
				Optional:    true,
				Description: "Indicates whether the custom key store is linked with AWS. Applicable to a custom key store of type EXTERNAL_KEY_STORE. Default value is false. When false, creating a custom key store in the CCKM does not trigger the AWS KMS to create a new key store. Also, the new custom key store will not synchronize with any key stores within the AWS KMS until the new key store is linked.",
			},
			"local_hosted_params": schema.ListNestedAttribute{
				Optional: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"blocked": schema.BoolAttribute{
							Required:    true,
							Description: "This field indicates whether the custom key store is in a blocked or unblocked state. Default value is false, which indicates the key store is in an unblocked state. Applicable to a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"health_check_key_id": schema.StringAttribute{
							Required:    true,
							Description: "ID of an existing LUNA key (if source key tier is 'hsm-luna') or CipherTrust key (if source key tier is 'local') to use for health check of the custom key store. Crypto operation would be performed using this key before creating a custom key store. Required field for custom key store of type EXTERNAL_KEY_STORE.",
						},
						"max_credentials": schema.StringAttribute{
							Required:    true,
							Description: "Max number of credentials that can be associated with custom key store (min value 2. max value 20). Required field for a custom key store of type EXTERNAL_KEY_STORE.",
						},
						"mtls_enabled": schema.BoolAttribute{
							Required:    true,
							Description: "Set it to true to enable tls client-side certificate verification — where cipher trust manager authenticates the AWS KMS client . Default value is false.",
						},
						"partition_id": schema.StringAttribute{
							Optional:    true,
							Description: "ID of Luna HSM partition. Required field, if custom key store is of type EXTERNAL_KEY_STORE and source key tier is 'hsm-luna'.",
						},
						"source_key_tier": schema.StringAttribute{
							Optional:    true,
							Description: "This field indicates whether to use Luna HSM (luna-hsm) or Ciphertrust Manager (local) as source for cryptographic keys in this key store. Default value is luna-hsm.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"local", "luna-hsm"}...),
							},
						},
					},
				},
			},
			"block": schema.BoolAttribute{
				Required:    false,
				Description: "Block or unblock the access to the AWS Custom Key Store",
			},
			"connect": schema.BoolAttribute{
				Required:    false,
				Description: "Connect or dis-connect to an AWS Custom Key Store. You would need to provide the key_store_password to connect.",
			},
			"key_store_password": schema.StringAttribute{
				Required:    false,
				Description: "The password of the kmsuser crypto user (CU) account configured in the specified CloudHSM cluster. This parameter does not change the password in CloudHSM cluster. User needs to configure the credentials on CloudHSM cluster separately. Required field for custom key store of type AWS_CLOUDHSM. Omit for External Key Stores.",
			},
			"update_op_type": schema.StringAttribute{
				Required:    false,
				Description: "Type of update operation to be performed on the given Custom Key Store.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"update", "block", "unblock", "connect", "disconnect", "link"}...),
				},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceAWSCustomKeyStore) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_custom_key_store.go -> Create]["+id+"]")

	// Retrieve values from plan
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

	var AWSParams AWSParamJSON
	if (AWSParamTFSDK{} != plan.AWSParams) {
		tflog.Debug(ctx, "aws_params should not be empty")
		if plan.AWSParams.CloudHSMClusterID.ValueString() != "" && plan.AWSParams.CloudHSMClusterID.ValueString() != types.StringNull().ValueString() {
			AWSParams.CloudHSMClusterID = plan.AWSParams.CloudHSMClusterID.ValueString()
		}
		if plan.AWSParams.XKSType.ValueString() != "" && plan.AWSParams.XKSType.ValueString() != types.StringNull().ValueString() {
			AWSParams.XKSType = plan.AWSParams.XKSType.ValueString()
		}
		if plan.AWSParams.KeyStorePassword.ValueString() != "" && plan.AWSParams.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
			AWSParams.KeyStorePassword = plan.AWSParams.KeyStorePassword.ValueString()
		}
		if plan.AWSParams.TrustAnchorCertificate.ValueString() != "" && plan.AWSParams.TrustAnchorCertificate.ValueString() != types.StringNull().ValueString() {
			AWSParams.TrustAnchorCertificate = plan.AWSParams.TrustAnchorCertificate.ValueString()
		}
		if plan.AWSParams.XKSProxyConnectivity.ValueString() != "" && plan.AWSParams.XKSProxyConnectivity.ValueString() != types.StringNull().ValueString() {
			AWSParams.XKSProxyConnectivity = plan.AWSParams.XKSProxyConnectivity.ValueString()
		}
		if plan.AWSParams.XKSProxyURIEndpoint.ValueString() != "" && plan.AWSParams.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() {
			AWSParams.XKSProxyURIEndpoint = plan.AWSParams.XKSProxyURIEndpoint.ValueString()
		}
		if plan.AWSParams.XKSProxyVPCEndpointServiceName.ValueString() != "" && plan.AWSParams.XKSProxyVPCEndpointServiceName.ValueString() != types.StringNull().ValueString() {
			AWSParams.XKSProxyVPCEndpointServiceName = plan.AWSParams.XKSProxyVPCEndpointServiceName.ValueString()
		}
		payload.AWSParams = &AWSParams
	}

	var LocalHostedParams LocalHostedParamsJSON
	if (LocalHostedParamsTFSDK{} != plan.LocalHostedParams) {
		tflog.Debug(ctx, "local_hosted_params should not be empty")
		if plan.LocalHostedParams.Blocked.ValueBool() != types.BoolNull().ValueBool() {
			LocalHostedParams.Blocked = plan.LocalHostedParams.Blocked.ValueBool()
		}
		if plan.LocalHostedParams.HealthCheckKeyID.ValueString() != "" && plan.LocalHostedParams.HealthCheckKeyID.ValueString() != types.StringNull().ValueString() {
			LocalHostedParams.HealthCheckKeyID = plan.LocalHostedParams.HealthCheckKeyID.ValueString()
		}
		if plan.LocalHostedParams.MaxCredentials.ValueString() != "" && plan.LocalHostedParams.MaxCredentials.ValueString() != types.StringNull().ValueString() {
			LocalHostedParams.MaxCredentials = plan.LocalHostedParams.MaxCredentials.ValueString()
		}
		if plan.LocalHostedParams.MTLSEnabled.ValueBool() != types.BoolNull().ValueBool() {
			LocalHostedParams.MTLSEnabled = plan.LocalHostedParams.MTLSEnabled.ValueBool()
		}
		if plan.LocalHostedParams.PartitionID.ValueString() != "" && plan.LocalHostedParams.PartitionID.ValueString() != types.StringNull().ValueString() {
			LocalHostedParams.PartitionID = plan.LocalHostedParams.PartitionID.ValueString()
		}
		if plan.LocalHostedParams.SourceKeyTier.ValueString() != "" && plan.LocalHostedParams.SourceKeyTier.ValueString() != types.StringNull().ValueString() {
			LocalHostedParams.SourceKeyTier = plan.LocalHostedParams.SourceKeyTier.ValueString()
		}
		payload.LocalHostedParams = &LocalHostedParams
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS Custom Key Store Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_XKS, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating AWS Custom Key Store on CipherTrust Manager: ",
			"Could not create AWS Custom Key Store, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_custom_key_store.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceAWSCustomKeyStore) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceAWSCustomKeyStore) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan AWSCustomKeyStoreTFSDK
	var payload AWSCustomKeyStoreJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.UpdateOpType.ValueString() != "" && plan.UpdateOpType.ValueString() != types.StringNull().ValueString() {
		if plan.UpdateOpType.ValueString() == "update" {
			if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
				payload.Name = common.TrimString(plan.Name.String())
			}
			if plan.EnableSuccessAuditEvent.ValueBool() != types.BoolNull().ValueBool() {
				payload.EnableSuccessAuditEvent = plan.EnableSuccessAuditEvent.ValueBool()
			}

			var AWSParams AWSParamJSON
			if (AWSParamTFSDK{} != plan.AWSParams) {
				tflog.Debug(ctx, "aws_params should not be empty")
				if plan.AWSParams.CloudHSMClusterID.ValueString() != "" && plan.AWSParams.CloudHSMClusterID.ValueString() != types.StringNull().ValueString() {
					AWSParams.CloudHSMClusterID = plan.AWSParams.CloudHSMClusterID.ValueString()
				}
				if plan.AWSParams.KeyStorePassword.ValueString() != "" && plan.AWSParams.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
					AWSParams.KeyStorePassword = plan.AWSParams.KeyStorePassword.ValueString()
				}
				if plan.AWSParams.XKSProxyConnectivity.ValueString() != "" && plan.AWSParams.XKSProxyConnectivity.ValueString() != types.StringNull().ValueString() {
					AWSParams.XKSProxyConnectivity = plan.AWSParams.XKSProxyConnectivity.ValueString()
				}
				if plan.AWSParams.XKSProxyURIEndpoint.ValueString() != "" && plan.AWSParams.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() {
					AWSParams.XKSProxyURIEndpoint = plan.AWSParams.XKSProxyURIEndpoint.ValueString()
				}
				if plan.AWSParams.XKSProxyVPCEndpointServiceName.ValueString() != "" && plan.AWSParams.XKSProxyVPCEndpointServiceName.ValueString() != types.StringNull().ValueString() {
					AWSParams.XKSProxyVPCEndpointServiceName = plan.AWSParams.XKSProxyVPCEndpointServiceName.ValueString()
				}
				payload.AWSParams = &AWSParams
			}

			var LocalHostedParams LocalHostedParamsJSON
			if (LocalHostedParamsTFSDK{} != plan.LocalHostedParams) {
				tflog.Debug(ctx, "local_hosted_params should not be empty")
				if plan.LocalHostedParams.HealthCheckKeyID.ValueString() != "" && plan.LocalHostedParams.HealthCheckKeyID.ValueString() != types.StringNull().ValueString() {
					LocalHostedParams.HealthCheckKeyID = plan.LocalHostedParams.HealthCheckKeyID.ValueString()
				}
				if plan.LocalHostedParams.MTLSEnabled.ValueBool() != types.BoolNull().ValueBool() {
					LocalHostedParams.MTLSEnabled = plan.LocalHostedParams.MTLSEnabled.ValueBool()
				}
				payload.LocalHostedParams = &LocalHostedParams
			}

			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: AWS Custom Key Store Update",
					err.Error(),
				)
				return
			}

			response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_AWS_XKS, payloadJSON, "id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error creating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not create AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.UpdateOpType.ValueString() == "block" {
			var payload []byte
			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/block",
				payload,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.UpdateOpType.ValueString() == "unblock" {
			var payload []byte
			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/unblock",
				payload,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.UpdateOpType.ValueString() == "connect" {
			if plan.AWSParams.KeyStorePassword.ValueString() != "" && plan.AWSParams.KeyStorePassword.ValueString() != types.StringNull().ValueString() {
				payload.KeyStorePassword = common.TrimString(plan.AWSParams.KeyStorePassword.String())
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: AWS Custom Key Store Update",
					err.Error(),
				)
				return
			}
			//var payload []byte
			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/connect",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.UpdateOpType.ValueString() == "disconnect" {
			var payload []byte
			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/disconnect",
				payload,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else if plan.UpdateOpType.ValueString() == "link" {
			if plan.AWSParams.XKSProxyURIEndpoint.ValueString() != "" && plan.AWSParams.XKSProxyURIEndpoint.ValueString() != types.StringNull().ValueString() {
				payload.AWSParams.XKSProxyURIEndpoint = common.TrimString(plan.AWSParams.XKSProxyURIEndpoint.ValueString())
			}
			payloadJSON, err := json.Marshal(payload)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> Update]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: AWS Custom Key Store Update",
					err.Error(),
				)
				return
			}
			response, err := r.client.UpdateDataFullURL(
				ctx,
				plan.ID.ValueString(),
				common.URL_AWS_XKS+"/"+plan.ID.ValueString()+"/link",
				payloadJSON,
				"id")
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
				resp.Diagnostics.AddError(
					"Error updating AWS Custom Key Store on CipherTrust Manager: ",
					"Could not update AWS Custom Key Store, unexpected error: "+err.Error(),
				)
				return
			}
			plan.ID = types.StringValue(response)
		} else {
			tflog.Debug(ctx, common.ERR_METHOD_END+"Invalid op_type value [resource_custom_key_store.go -> block]["+plan.ID.ValueString()+"]")
			resp.Diagnostics.AddError(
				"Error updating AWS Custom Key Store on CipherTrust Manager: ",
				"Could not update AWS Custom Key Store, unexpected error: Invalid op_type value",
			)
			return
		}
	}

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
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
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_custom_key_store.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
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
