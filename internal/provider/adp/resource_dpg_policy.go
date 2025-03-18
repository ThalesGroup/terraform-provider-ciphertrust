package adp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

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
	_ resource.Resource              = &resourceDPGPolicy{}
	_ resource.ResourceWithConfigure = &resourceDPGPolicy{}
)

func NewResourceDPGPolicy() resource.Resource {
	return &resourceDPGPolicy{}
}

type resourceDPGPolicy struct {
	client *common.Client
}

func (r *resourceDPGPolicy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dpg_policy"
}

// Schema defines the schema for the resource.
func (r *resourceDPGPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the DPG policy.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the DPG policy.",
			},
			"update_api_url_id": schema.StringAttribute{
				Optional:    true,
				Description: "API URL ID to be updated",
			},
			"delete_api_url_id": schema.StringAttribute{
				Optional:    true,
				Description: "API URL ID to be deleted",
			},
			"proxy_config": schema.ListNestedAttribute{
				Optional:    true,
				Description: "List of API urls to be added to the proxy configuration.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":         schema.StringAttribute{Computed: true},
						"uri":        schema.StringAttribute{Computed: true},
						"account":    schema.StringAttribute{Computed: true},
						"created_at": schema.StringAttribute{Computed: true},
						"updated_at": schema.StringAttribute{Computed: true},
						"api_url": schema.StringAttribute{
							Optional:    true,
							Description: "URL of the application server from which the request will received.",
						},
						"destination_url": schema.StringAttribute{
							Optional:    true,
							Description: "URL of the application server where the request will be served.",
						},
						"json_request_post_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_response_post_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"access_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_request_get_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_response_get_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"access_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_request_put_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_response_put_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"access_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_request_patch_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_response_patch_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"access_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_request_delete_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"json_response_delete_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"access_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"url_request_post_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"url_request_get_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"access_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"url_request_put_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"url_request_patch_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"access_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
						"url_request_delete_tokens": schema.ListNestedAttribute{
							Optional: true,
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"name": schema.StringAttribute{
										Optional: true,
									},
									"operation": schema.StringAttribute{
										Optional: true,
										Validators: []validator.String{
											stringvalidator.OneOf([]string{"protect",
												"reveal"}...),
										},
									},
									"protection_policy": schema.StringAttribute{
										Optional: true,
									},
									"external_version_header": schema.StringAttribute{
										Optional: true,
									},
								},
							},
						},
					},
				},
			},
			"uri":        schema.StringAttribute{Computed: true},
			"account":    schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceDPGPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_dpg_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan DPGPolicyTFSDK
	var payload DPGPolicyCreateJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_dpg_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: DPG Policy Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, URL_DPG_POLICIES, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_dpg_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating DPG Policy on CipherTrust Manager: ",
			"Could not create DPG Policy, unexpected error: "+err.Error(),
		)
		return
	}

	// Now let's add the userset policies if any provided as part of the create call
	if len(plan.ProxyConfig) > 0 {
		for idx, proxyConfig := range plan.ProxyConfig {
			var proxy DPGJSONTokensJSON
			if proxyConfig.APIUrl.ValueString() != "" && proxyConfig.APIUrl.ValueString() != types.StringNull().ValueString() {
				proxy.APIUrl = proxyConfig.APIUrl.ValueString()
			}
			if proxyConfig.DestinationUrl.ValueString() != "" && proxyConfig.DestinationUrl.ValueString() != types.StringNull().ValueString() {
				proxy.DestinationUrl = proxyConfig.DestinationUrl.ValueString()
			}

			if len(proxyConfig.JSONRequestPostTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestPostTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestPostTokens = tokensArr
			}

			if len(proxyConfig.JSONResponsePostTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponsePostTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponsePostTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestGetTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestGetTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestGetTokens = tokensArr
			}

			if len(proxyConfig.JSONResponseGetTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponseGetTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponseGetTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestPutTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestPutTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestPutTokens = tokensArr
			}

			if len(proxyConfig.JSONResponsePutTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponsePutTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponsePutTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestPatchTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestPatchTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestPatchTokens = tokensArr
			}

			if len(proxyConfig.JSONResponsePatchTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponsePatchTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponsePatchTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestDeleteTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestDeleteTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestDeleteTokens = tokensArr
			}

			if len(proxyConfig.JSONResponseDeleteTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponseDeleteTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponseDeleteTokens = tokensArr
			}

			if len(proxyConfig.URLRequestPostTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.URLRequestPostTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestPostTokens = tokensArr
			}

			if len(proxyConfig.URLRequestGetTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.URLRequestGetTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestGetTokens = tokensArr
			}

			if len(proxyConfig.URLRequestPutTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.URLRequestPutTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestPutTokens = tokensArr
			}

			if len(proxyConfig.URLRequestPatchTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.URLRequestPatchTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestPatchTokens = tokensArr
			}

			if len(proxyConfig.URLRequestDeleteTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.URLRequestDeleteTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestDeleteTokens = tokensArr
			}

			proxyConfigJSON, err := json.Marshal(proxy)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_dpg_policy.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: DPG Policy Proxy Config",
					err.Error(),
				)
				return
			}

			responseAddProxyConfig, _ := r.client.PostDataV2(
				ctx,
				id,
				URL_DPG_POLICIES+"/"+gjson.Get(response, "id").String()+"/api-urls",
				proxyConfigJSON)

			plan.ProxyConfig[idx].ID = types.StringValue(gjson.Get(responseAddProxyConfig, "id").String())
			plan.ProxyConfig[idx].URI = types.StringValue(gjson.Get(response, "uri").String())
			plan.ProxyConfig[idx].Account = types.StringValue(gjson.Get(response, "account").String())
			plan.ProxyConfig[idx].CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
			plan.ProxyConfig[idx].UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
		}
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_dpg_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceDPGPolicy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state DPGPolicyTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), URL_ACCESS_POLICY)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_dpg_policy.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading DPG Policy on CipherTrust Manager: ",
			"Could not read DPG Policy id : ,"+state.Name.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceDPGPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_dpg_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan DPGPolicyTFSDK
	var payload DPGPolicyUpdateJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_dpg_policy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: DPG Policy Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(
		ctx,
		plan.ID.ValueString(),
		URL_ACCESS_POLICY,
		payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_dpg_policy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating DPG Policy on CipherTrust Manager: ",
			"Could not update DPG Policy, unexpected error: "+err.Error(),
		)
		return
	}

	// Add API URLs if the array exists and length is greater than zero
	if len(plan.ProxyConfig) > 0 {
		for idx, proxyConfig := range plan.ProxyConfig {
			var proxy DPGJSONTokensJSON
			if proxyConfig.APIUrl.ValueString() != "" && proxyConfig.APIUrl.ValueString() != types.StringNull().ValueString() {
				proxy.APIUrl = proxyConfig.APIUrl.ValueString()
			}
			if proxyConfig.DestinationUrl.ValueString() != "" && proxyConfig.DestinationUrl.ValueString() != types.StringNull().ValueString() {
				proxy.DestinationUrl = proxyConfig.DestinationUrl.ValueString()
			}

			if len(proxyConfig.JSONRequestPostTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestPostTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestPostTokens = tokensArr
			}

			if len(proxyConfig.JSONResponsePostTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponsePostTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponsePostTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestGetTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestGetTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestGetTokens = tokensArr
			}

			if len(proxyConfig.JSONResponseGetTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponseGetTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponseGetTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestPutTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestPutTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestPutTokens = tokensArr
			}

			if len(proxyConfig.JSONResponsePutTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponsePutTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponsePutTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestPatchTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestPatchTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestPatchTokens = tokensArr
			}

			if len(proxyConfig.JSONResponsePatchTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponsePatchTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponsePatchTokens = tokensArr
			}

			if len(proxyConfig.JSONRequestDeleteTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.JSONRequestDeleteTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONRequestDeleteTokens = tokensArr
			}

			if len(proxyConfig.JSONResponseDeleteTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.JSONResponseDeleteTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.JSONResponseDeleteTokens = tokensArr
			}

			if len(proxyConfig.URLRequestPostTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.URLRequestPostTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestPostTokens = tokensArr
			}

			if len(proxyConfig.URLRequestGetTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.URLRequestGetTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestGetTokens = tokensArr
			}

			if len(proxyConfig.URLRequestPutTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.URLRequestPutTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestPutTokens = tokensArr
			}

			if len(proxyConfig.URLRequestPatchTokens) > 0 {
				var tokensArr []DPGJsonResponseTokenJSON
				for _, token := range proxyConfig.URLRequestPatchTokens {
					var tokenJSON DPGJsonResponseTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.AccessPolicy.ValueString() != "" && token.AccessPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.AccessPolicy = token.AccessPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestPatchTokens = tokensArr
			}

			if len(proxyConfig.URLRequestDeleteTokens) > 0 {
				var tokensArr []DPGJsonRequestTokenJSON
				for _, token := range proxyConfig.URLRequestDeleteTokens {
					var tokenJSON DPGJsonRequestTokenJSON
					if token.Name.ValueString() != "" && token.Name.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Name = token.Name.ValueString()
					}
					if token.Operation.ValueString() != "" && token.Operation.ValueString() != types.StringNull().ValueString() {
						tokenJSON.Operation = token.Operation.ValueString()
					}
					if token.ProtectionPolicy.ValueString() != "" && token.ProtectionPolicy.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ProtectionPolicy = token.ProtectionPolicy.ValueString()
					}
					if token.ExternalVersionHeader.ValueString() != "" && token.ExternalVersionHeader.ValueString() != types.StringNull().ValueString() {
						tokenJSON.ExternalVersionHeader = token.ExternalVersionHeader.ValueString()
					}
					tokensArr = append(tokensArr, tokenJSON)
				}
				proxy.URLRequestDeleteTokens = tokensArr
			}

			proxyConfigJSON, err := json.Marshal(proxy)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_dpg_policy.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: DPG Policy Proxy Config",
					err.Error(),
				)
				return
			}

			responseAddProxyConfig, _ := r.client.PostDataV2(
				ctx,
				id,
				URL_DPG_POLICIES+"/"+gjson.Get(response, "id").String()+"/api-urls",
				proxyConfigJSON)

			plan.ProxyConfig[idx].ID = types.StringValue(gjson.Get(responseAddProxyConfig, "id").String())
			plan.ProxyConfig[idx].URI = types.StringValue(gjson.Get(response, "uri").String())
			plan.ProxyConfig[idx].Account = types.StringValue(gjson.Get(response, "account").String())
			plan.ProxyConfig[idx].CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
			plan.ProxyConfig[idx].UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
		}
	}

	// Delete API URL from DPG Policy if the delete_api_url_id is defined
	if plan.DeleteProxyConfigId.ValueString() != "" && plan.DeleteProxyConfigId.ValueString() != types.StringNull().ValueString() {
		r.client.DeleteByURL(
			ctx,
			plan.ID.ValueString(),
			URL_DPG_POLICIES+"/"+plan.ID.ValueString()+"/api-urls/"+plan.DeleteProxyConfigId.ValueString())
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_dpg_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceDPGPolicy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state DPGPolicyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, URL_DPG_POLICIES, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_dpg_policy.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting DPG Policy",
			"Could not delete DPG Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceDPGPolicy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
