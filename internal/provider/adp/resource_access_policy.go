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
	_ resource.Resource              = &resourceADPAccessPolicy{}
	_ resource.ResourceWithConfigure = &resourceADPAccessPolicy{}
)

func NewResourceADPAccessPolicy() resource.Resource {
	return &resourceADPAccessPolicy{}
}

type resourceADPAccessPolicy struct {
	client *common.Client
}

func (r *resourceADPAccessPolicy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_adp_access_policy"
}

// Schema defines the schema for the resource.
func (r *resourceADPAccessPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"default_error_replacement_value": schema.StringAttribute{
				Optional:    true,
				Description: "Value to be revealed if the type is 'Error Replacement Value'.",
			},
			"default_masking_format_id": schema.StringAttribute{
				Optional:    true,
				Description: "Masking format used to reveal if the type is 'Masked Value'.",
			},
			"default_reveal_type": schema.StringAttribute{
				Optional:    true,
				Description: "Value using which data should be revealed.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Error Replacement Value",
						"Masked Value",
						"Ciphertext",
						"Plaintext"}...),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description of the Access Policy",
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Description: "Access Policy name.",
			},
			"user_set_policy": schema.ListNestedAttribute{
				Optional:    true,
				Description: "List of policies to be added to the access policy.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"error_replacement_value": schema.StringAttribute{
							Optional:    true,
							Description: "Value to be revealed if the type is 'Error Replacement Value'.",
						},
						"masking_format_id": schema.StringAttribute{
							Optional:    true,
							Description: "Masking format used to reveal if the type is 'Masked Value'.",
						},
						"reveal_type": schema.StringAttribute{
							Optional:    true,
							Description: "Value using which data should be revealed.",
							Validators: []validator.String{
								stringvalidator.OneOf([]string{"Error Replacement Value",
									"Masked Value",
									"Ciphertext",
									"Plaintext"}...),
							},
						},
						"user_set_id": schema.StringAttribute{
							Optional:    true,
							Description: "User set to which the policy is applied.",
						},
					},
				},
			},
			"error_replacement_value": schema.StringAttribute{
				Optional:    true,
				Description: "Value to be revealed if the type is 'Error Replacement Value'.",
			},
			"masking_format_id": schema.StringAttribute{
				Optional:    true,
				Description: "Masking format used to reveal if the type is 'Masked Value'.",
			},
			"reveal_type": schema.StringAttribute{
				Optional:    true,
				Description: "Value using which data should be revealed.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"Error Replacement Value",
						"Masked Value",
						"Ciphertext",
						"Plaintext"}...),
				},
			},
			"update_user_set_id": schema.StringAttribute{
				Optional:    true,
				Description: "User set ID to be updated.",
			},
			"delete_user_set_id": schema.StringAttribute{
				Optional:    true,
				Description: "User set ID to be updated.",
			},
			"uri":        schema.StringAttribute{Computed: true},
			"account":    schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceADPAccessPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_access_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan ADPAccessPolicyTFSDK
	var payload CreateAccessPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.DefaultErrorReplacementValue.ValueString() != "" && plan.DefaultErrorReplacementValue.ValueString() != types.StringNull().ValueString() {
		payload.DefaultErrorReplacementValue = plan.DefaultErrorReplacementValue.ValueString()
	}
	if plan.DefaultMaskingFormatId.ValueString() != "" && plan.DefaultMaskingFormatId.ValueString() != types.StringNull().ValueString() {
		payload.DefaultMaskingFormatId = plan.DefaultMaskingFormatId.ValueString()
	}
	if plan.DefaultRevealType.ValueString() != "" && plan.DefaultRevealType.ValueString() != types.StringNull().ValueString() {
		payload.DefaultRevealType = plan.DefaultRevealType.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Access Policy Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, URL_ACCESS_POLICY, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Access Policy on CipherTrust Manager: ",
			"Could not create Access Policy, unexpected error: "+err.Error(),
		)
		return
	}

	// Now let's add the userset policies if any provided as part of the create call
	if len(plan.UsersetPolicy) > 0 {
		for _, usersetPolicy := range plan.UsersetPolicy {
			var userSet AddUsersetAccessPolicyJSON
			if usersetPolicy.ErrorReplacementValue.ValueString() != "" && usersetPolicy.ErrorReplacementValue.ValueString() != types.StringNull().ValueString() {
				userSet.ErrorReplacementValue = usersetPolicy.ErrorReplacementValue.ValueString()
			}
			if usersetPolicy.MaskingFormatId.ValueString() != "" && usersetPolicy.MaskingFormatId.ValueString() != types.StringNull().ValueString() {
				userSet.MaskingFormatId = usersetPolicy.MaskingFormatId.ValueString()
			}
			if usersetPolicy.RevealType.ValueString() != "" && usersetPolicy.RevealType.ValueString() != types.StringNull().ValueString() {
				userSet.RevealType = usersetPolicy.RevealType.ValueString()
			}
			if usersetPolicy.UserSetId.ValueString() != "" && usersetPolicy.UserSetId.ValueString() != types.StringNull().ValueString() {
				userSet.UserSetId = usersetPolicy.UserSetId.ValueString()
			}

			usersetPolicyJSON, err := json.Marshal(usersetPolicy)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: Access Policy Userset",
					err.Error(),
				)
				return
			}

			r.client.PostDataV2(
				ctx,
				id,
				URL_ACCESS_POLICY+"/"+gjson.Get(response, "id").String()+"/user-set",
				usersetPolicyJSON)
		}
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_access_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceADPAccessPolicy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ADPAccessPolicyTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.ID.ValueString(), URL_ACCESS_POLICY)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Access Policy on CipherTrust Manager: ",
			"Could not read Access Policy id : ,"+state.Name.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.DefaultRevealType = types.StringValue(gjson.Get(response, "default_reveal_type").String())
	state.DefaultErrorReplacementValue = types.StringValue(gjson.Get(response, "default_error_replacement_value").String())
	state.DefaultMaskingFormatId = types.StringValue(gjson.Get(response, "default_masking_format_id").String())
	state.Description = types.StringValue(gjson.Get(response, "description").String())
	usersetPolicies := gjson.Get(response, "user_set_policy")

	var usersetPoliciesTFSDK []ADPAccessPolicyUsersetPolicyTFSDK

	// Iterate over the array in the JSON response
	usersetPolicies.ForEach(func(key, value gjson.Result) bool {
		userSetPolicy := ADPAccessPolicyUsersetPolicyTFSDK{
			ErrorReplacementValue: types.StringValue(value.Get("error_replacement_value").String()),
			UserSetId:             types.StringValue(value.Get("user_set_id").String()),
			RevealType:            types.StringValue(value.Get("reveal_type").String()),
			MaskingFormatId:       types.StringValue(value.Get("masking_format_id").String()),
		}
		usersetPoliciesTFSDK = append(usersetPoliciesTFSDK, userSetPolicy)
		return true // keep iterating
	})
	state.UsersetPolicy = usersetPoliciesTFSDK
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceADPAccessPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_access_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan ADPAccessPolicyTFSDK
	var payload CreateAccessPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.DefaultErrorReplacementValue.ValueString() != "" && plan.DefaultErrorReplacementValue.ValueString() != types.StringNull().ValueString() {
		payload.DefaultErrorReplacementValue = plan.DefaultErrorReplacementValue.ValueString()
	}
	if plan.DefaultMaskingFormatId.ValueString() != "" && plan.DefaultMaskingFormatId.ValueString() != types.StringNull().ValueString() {
		payload.DefaultMaskingFormatId = plan.DefaultMaskingFormatId.ValueString()
	}
	if plan.DefaultRevealType.ValueString() != "" && plan.DefaultRevealType.ValueString() != types.StringNull().ValueString() {
		payload.DefaultRevealType = plan.DefaultRevealType.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}
	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Access Policy Update",
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
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Error updating Access Policy on CipherTrust Manager: ",
			"Could not update Access Policy, unexpected error: "+err.Error(),
		)
		return
	}

	// Updating the userset if update_user_set_id is present and not null
	if plan.UpdateUsersetId.ValueString() != "" && plan.UpdateUsersetId.ValueString() != types.StringNull().ValueString() {
		var updateUsersetPayload UpdateUsersetAccessPolicyJSON
		if plan.ErrorReplacementValue.ValueString() != "" && plan.ErrorReplacementValue.ValueString() != types.StringNull().ValueString() {
			updateUsersetPayload.ErrorReplacementValue = plan.ErrorReplacementValue.ValueString()
		}
		if plan.MaskingFormatId.ValueString() != "" && plan.MaskingFormatId.ValueString() != types.StringNull().ValueString() {
			updateUsersetPayload.MaskingFormatId = plan.MaskingFormatId.ValueString()
		}
		if plan.RevealType.ValueString() != "" && plan.RevealType.ValueString() != types.StringNull().ValueString() {
			updateUsersetPayload.RevealType = plan.RevealType.ValueString()
		}

		updateUsersetPayloadJSON, err := json.Marshal(updateUsersetPayload)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Invalid data input: Userset Update",
				err.Error(),
			)
			return
		}

		responseUpdateUsersetAP, err := r.client.UpdateDataFullURL(
			ctx,
			plan.ID.ValueString(),
			URL_ACCESS_POLICY+"/"+plan.ID.ValueString()+"/user-set/"+plan.UpdateUsersetId.ValueString(),
			updateUsersetPayloadJSON,
			"updatedAt")
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Create]["+id+"]")
			resp.Diagnostics.AddError(
				"Error updating Access Policy on CipherTrust Manager: ",
				"Could not update Access Policy, unexpected error: "+err.Error(),
			)
			return
		}
		plan.UpdatedAt = types.StringValue(responseUpdateUsersetAP)
	}

	// Delete UserSet from Access policy if the delete_user_set_id is defined
	if plan.DeleteUsersetId.ValueString() != "" && plan.DeleteUsersetId.ValueString() != types.StringNull().ValueString() {
		r.client.DeleteByURL(
			ctx,
			plan.ID.ValueString(),
			URL_ACCESS_POLICY+"/"+plan.ID.ValueString()+"/user-set/"+plan.DeleteUsersetId.ValueString())
	}

	// Now let's add the userset policies if any provided as part of the create call
	if len(plan.UsersetPolicy) > 0 {
		for _, usersetPolicy := range plan.UsersetPolicy {
			var userSet AddUsersetAccessPolicyJSON
			if usersetPolicy.ErrorReplacementValue.ValueString() != "" && usersetPolicy.ErrorReplacementValue.ValueString() != types.StringNull().ValueString() {
				userSet.ErrorReplacementValue = usersetPolicy.ErrorReplacementValue.ValueString()
			}
			if usersetPolicy.MaskingFormatId.ValueString() != "" && usersetPolicy.MaskingFormatId.ValueString() != types.StringNull().ValueString() {
				userSet.MaskingFormatId = usersetPolicy.MaskingFormatId.ValueString()
			}
			if usersetPolicy.RevealType.ValueString() != "" && usersetPolicy.RevealType.ValueString() != types.StringNull().ValueString() {
				userSet.RevealType = usersetPolicy.RevealType.ValueString()
			}
			if usersetPolicy.UserSetId.ValueString() != "" && usersetPolicy.UserSetId.ValueString() != types.StringNull().ValueString() {
				userSet.UserSetId = usersetPolicy.UserSetId.ValueString()
			}

			usersetPolicyJSON, err := json.Marshal(usersetPolicy)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_access_policy.go -> Create]["+id+"]")
				resp.Diagnostics.AddError(
					"Invalid data input: Access Policy Userset",
					err.Error(),
				)
				return
			}

			r.client.PostDataV2(
				ctx,
				id,
				URL_ACCESS_POLICY+"/"+gjson.Get(response, "id").String()+"/user-set",
				usersetPolicyJSON)
		}
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_access_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceADPAccessPolicy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ADPAccessPolicyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, URL_ACCESS_POLICY, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_access_policy.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting Access Policy",
			"Could not delete Access Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceADPAccessPolicy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
