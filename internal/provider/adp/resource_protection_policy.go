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
	_ resource.Resource              = &resourceADPProtectionPolicy{}
	_ resource.ResourceWithConfigure = &resourceADPProtectionPolicy{}
)

func NewResourceADPProtectionPolicy() resource.Resource {
	return &resourceADPProtectionPolicy{}
}

type resourceADPProtectionPolicy struct {
	client *common.Client
}

func (r *resourceADPProtectionPolicy) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_adp_protection_policy"
}

// Schema defines the schema for the resource.
func (r *resourceADPProtectionPolicy) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A protection policy is an object that contains all the information needed to perform a cryptographic operation",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The unique identifier of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"access_policy_name": schema.StringAttribute{
				Description: "Access Policy associated with the protection policy.",
				Required:    true,
			},
			"algorithm": schema.StringAttribute{
				Description: "Protection policy algorithm.",
				Required:    true,
			},
			"key": schema.StringAttribute{
				Required:    true,
				Description: "Name of the Key.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique name for the protection policy.",
			},
			"aad": schema.StringAttribute{
				Optional:    true,
				Description: "Additional authenticated data for AES/GCM algorithm. This is an optional field",
			},
			"allow_small_input": schema.BoolAttribute{
				Optional:    true,
				Description: "Allow small input in protection policy. This parameter is only supported for FPE and RANDOM2 algorithms. By default, its value is true.",
			},
			"character_set_id": schema.StringAttribute{
				Optional:    true,
				Description: "Character set ID.",
			},
			"data_format": schema.StringAttribute{
				Optional:    true,
				Description: "The format in which the data to be protected will be provided.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"luhn"}...),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "The description of protection policy.",
			},
			"disable_versioning": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, versioning is not maintained for the protection policies. The default value is false.",
			},
			"iv": schema.StringAttribute{
				Optional:    true,
				Description: "IV to be used during crypto operations.",
			},
			"masking_format_id": schema.StringAttribute{
				Optional:    true,
				Description: "Static Masking Format ID.",
			},
			"prefix": schema.StringAttribute{
				Optional:    true,
				Description: "A static string to be added to the tokens. Maximum value of prefix can be 7.",
			},
			"random_nonce": schema.StringAttribute{
				Optional: true,
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"internal", "external"}...),
				},
				Description: "parameter to enable the random nonce. With random nonce, IV is not required as it generates the IV randomly. Random Nonce is only supported with AES/CBC and AES/GCM algorithms.",
			},
			"tag_length": schema.Int64Attribute{
				Optional:    true,
				Description: "Tag length required for AES/GCM algorithm. Valid values are 32 - 128 in multiples of 8, i.e 32,40,48,56, ... 128",
			},
			"tweak": schema.StringAttribute{
				Optional:    true,
				Description: "Tweak data to be used during crypto operations.",
			},
			"tweak_algorithm": schema.StringAttribute{
				Optional:    true,
				Description: "Tweak algorithm to be used during crypto operations.",
				Validators: []validator.String{
					stringvalidator.OneOf([]string{"SHA1",
						"SHA256",
						"None"}...),
				},
			},
			"use_external_versioning": schema.BoolAttribute{
				Optional:    true,
				Description: "If set to true, external versioning is enabled for the protection policy. The version details are stored in a separate external parameter. The default value is false.",
			},
			"uri":        schema.StringAttribute{Computed: true},
			"account":    schema.StringAttribute{Computed: true},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
			"version":    schema.StringAttribute{Computed: true},
			"key_name ":  schema.StringAttribute{Computed: true},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceADPProtectionPolicy) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_protection_policy.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan ADPProtectionPolicyTFSDK
	var payload ADPProtectionPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.AccessPolicyName = plan.AccessPolicyName.ValueString()
	payload.Algorithm = plan.Algorithm.ValueString()
	payload.Key = plan.Key.ValueString()
	payload.Name = plan.Name.ValueString()

	if plan.AAD.ValueString() != "" && plan.AAD.ValueString() != types.StringNull().ValueString() {
		payload.AAD = plan.AAD.ValueString()
	}
	if plan.AllowSmallInput.ValueBool() != types.BoolNull().ValueBool() {
		payload.AllowSmallInput = plan.AllowSmallInput.ValueBool()
	}
	if plan.CharacterSetId.ValueString() != "" && plan.CharacterSetId.ValueString() != types.StringNull().ValueString() {
		payload.CharacterSetId = plan.CharacterSetId.ValueString()
	}
	if plan.DataFormat.ValueString() != "" && plan.DataFormat.ValueString() != types.StringNull().ValueString() {
		payload.DataFormat = plan.DataFormat.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}
	if plan.DisableVersioning.ValueBool() != types.BoolNull().ValueBool() {
		payload.DisableVersioning = plan.DisableVersioning.ValueBool()
	}
	if plan.IV.ValueString() != "" && plan.IV.ValueString() != types.StringNull().ValueString() {
		payload.IV = plan.IV.ValueString()
	}
	if plan.MaskingFormatId.ValueString() != "" && plan.MaskingFormatId.ValueString() != types.StringNull().ValueString() {
		payload.MaskingFormatId = plan.MaskingFormatId.ValueString()
	}
	if plan.Prefix.ValueString() != "" && plan.Prefix.ValueString() != types.StringNull().ValueString() {
		payload.Prefix = plan.Prefix.ValueString()
	}
	if plan.RandomNonce.ValueString() != "" && plan.RandomNonce.ValueString() != types.StringNull().ValueString() {
		payload.RandomNonce = plan.RandomNonce.ValueString()
	}
	if plan.TagLength.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.TagLength = plan.TagLength.ValueInt64()
	}
	if plan.Tweak.ValueString() != "" && plan.Tweak.ValueString() != types.StringNull().ValueString() {
		payload.Tweak = plan.Tweak.ValueString()
	}
	if plan.TweakAlgorithm.ValueString() != "" && plan.TweakAlgorithm.ValueString() != types.StringNull().ValueString() {
		payload.TweakAlgorithm = plan.TweakAlgorithm.ValueString()
	}
	if plan.UseExternalVersioning.ValueBool() != types.BoolNull().ValueBool() {
		payload.UseExternalVersioning = plan.UseExternalVersioning.ValueBool()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_protection_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Protection Policy Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, URL_PROTECTION_POLICY, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_protection_policy.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Protection Policy on CipherTrust Manager: ",
			"Could not create Protection Policy, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.Name = types.StringValue(gjson.Get(response, "name").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Version = types.StringValue(gjson.Get(response, "version").String())
	plan.KeyName = types.StringValue(gjson.Get(response, "key_name").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_protection_policy.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceADPProtectionPolicy) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ADPProtectionPolicyTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.ReadDataByParam(ctx, id, state.Name.ValueString(), URL_PROTECTION_POLICY)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_protection_policy.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Protection Policy on CipherTrust Manager: ",
			"Could not read Protection Policy id : ,"+state.Name.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Version = types.StringValue(gjson.Get(response, "version").String())
	state.KeyName = types.StringValue(gjson.Get(response, "key_name").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Description = types.StringValue(gjson.Get(response, "description").String())
	state.Key = types.StringValue(gjson.Get(response, "key").String())
	state.IV = types.StringValue(gjson.Get(response, "iv").String())
	state.Tweak = types.StringValue(gjson.Get(response, "tweak").String())
	state.TweakAlgorithm = types.StringValue(gjson.Get(response, "tweak_algorithm").String())
	state.Algorithm = types.StringValue(gjson.Get(response, "algorithm").String())
	state.TagLength = types.Int64Value(gjson.Get(response, "tag_length").Int())
	state.AAD = types.StringValue(gjson.Get(response, "aad").String())
	state.RandomNonce = types.StringValue(gjson.Get(response, "random_nonce").String())
	state.CharacterSetId = types.StringValue(gjson.Get(response, "character_set_id").String())
	state.MaskingFormatId = types.StringValue(gjson.Get(response, "masking_format_id").String())
	state.UseExternalVersioning = types.BoolValue(gjson.Get(response, "use_external_versioning").Bool())
	state.DisableVersioning = types.BoolValue(gjson.Get(response, "disable_versioning").Bool())
	state.AccessPolicyName = types.StringValue(gjson.Get(response, "access_policy_name").String())
	state.Prefix = types.StringValue(gjson.Get(response, "prefix").String())
	state.DataFormat = types.StringValue(gjson.Get(response, "data_format").String())
	state.AllowSmallInput = types.BoolValue(gjson.Get(response, "allow_small_input").Bool())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_protection_policy.go -> Read]["+id+"]")
	// Set refreshed state
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceADPProtectionPolicy) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan ADPProtectionPolicyTFSDK
	var payload ADPProtectionPolicyJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.AAD.ValueString() != "" && plan.AAD.ValueString() != types.StringNull().ValueString() {
		payload.AAD = plan.AAD.ValueString()
	}
	if plan.AccessPolicyName.ValueString() != "" && plan.AccessPolicyName.ValueString() != types.StringNull().ValueString() {
		payload.AccessPolicyName = plan.AccessPolicyName.ValueString()
	}
	if plan.Algorithm.ValueString() != "" && plan.Algorithm.ValueString() != types.StringNull().ValueString() {
		payload.Algorithm = plan.Algorithm.ValueString()
	}
	if plan.AllowSmallInput.ValueBool() != types.BoolNull().ValueBool() {
		payload.AllowSmallInput = plan.AllowSmallInput.ValueBool()
	}
	if plan.CharacterSetId.ValueString() != "" && plan.CharacterSetId.ValueString() != types.StringNull().ValueString() {
		payload.CharacterSetId = plan.CharacterSetId.ValueString()
	}
	if plan.DataFormat.ValueString() != "" && plan.DataFormat.ValueString() != types.StringNull().ValueString() {
		payload.DataFormat = plan.DataFormat.ValueString()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}
	if plan.IV.ValueString() != "" && plan.IV.ValueString() != types.StringNull().ValueString() {
		payload.IV = plan.IV.ValueString()
	}
	if plan.Key.ValueString() != "" && plan.Key.ValueString() != types.StringNull().ValueString() {
		payload.Key = plan.Key.ValueString()
	}
	if plan.MaskingFormatId.ValueString() != "" && plan.MaskingFormatId.ValueString() != types.StringNull().ValueString() {
		payload.MaskingFormatId = plan.MaskingFormatId.ValueString()
	}
	if plan.Prefix.ValueString() != "" && plan.Prefix.ValueString() != types.StringNull().ValueString() {
		payload.Prefix = plan.Prefix.ValueString()
	}
	if plan.RandomNonce.ValueString() != "" && plan.RandomNonce.ValueString() != types.StringNull().ValueString() {
		payload.RandomNonce = plan.RandomNonce.ValueString()
	}
	if plan.TagLength.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.TagLength = plan.TagLength.ValueInt64()
	}
	if plan.Tweak.ValueString() != "" && plan.Tweak.ValueString() != types.StringNull().ValueString() {
		payload.Tweak = plan.Tweak.ValueString()
	}
	if plan.TweakAlgorithm.ValueString() != "" && plan.TweakAlgorithm.ValueString() != types.StringNull().ValueString() {
		payload.TweakAlgorithm = plan.TweakAlgorithm.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_protection_policy.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Protection Policy Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateDataV2(ctx, plan.Name.ValueString(), URL_PROTECTION_POLICY, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_protection_policy.go -> Update]["+plan.Name.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating Protection Policy on CipherTrust Manager: ",
			"Could not create Protection Policy, unexpected error: "+err.Error(),
		)
		return
	}
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	plan.Version = types.StringValue(gjson.Get(response, "version").String())
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceADPProtectionPolicy) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ADPProtectionPolicyTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, URL_PROTECTION_POLICY, state.Name.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.Name.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_protection_policy.go -> Delete]["+state.Name.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Protection Policy",
			"Could not delete Protection Policy, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceADPProtectionPolicy) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
