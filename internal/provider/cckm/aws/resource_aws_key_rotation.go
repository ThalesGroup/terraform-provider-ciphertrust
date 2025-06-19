package cckm

import (
	"context"
	"fmt"
	"time"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource              = &resourceAWSKeyRotation{}
	_ resource.ResourceWithConfigure = &resourceAWSKeyRotation{}
)

func NewResourceAWSKeyRotation() resource.Resource {
	return &resourceAWSKeyRotation{}
}

type resourceAWSKeyRotation struct {
	client *common.Client
}

func (r *resourceAWSKeyRotation) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_key_rotation"
}

func (r *resourceAWSKeyRotation) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceAWSKeyRotation) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this resource to create a new version of the key material. " +
			"This is only applicable to single or multi-region native symmetric keys. " +
			"This resource will only submit the request to AWS and AWS will rotate the key-material asynchronously. " +
			"Use the aws_key_rotation_list datasource to view key material rotation history of EXTERNAL SYMMETRIC_DEFAULT keys. " +
			"\n\n\n\nNote: This resource and the datasource are only available for CipherTrust Manager version 2.22 and greater.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS region, AWS key identifier and a unique ID separated by backslashes.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "A CipherTrust Manager AWS key resource ID.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Status of the request to rotate key material.",
			},
		},
	}
}

func (r *resourceAWSKeyRotation) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Create]["+id+"]")
	var (
		plan     AWSKeyRotationTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := plan.KeyID.ValueString()
	response = r.rotateKeyMaterial(ctx, keyID, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	kid := gjson.Get(response, "aws_param.KeyID").String()
	region := gjson.Get(response, "region").String()
	plan.ID = types.StringValue(encodeAWSKeyTerraformResourceID(region, kid) + "\\" + uuid.NewString())
	now := time.Now().UTC().Format("2006-01-02 15:04:05 MST")
	plan.Status = types.StringValue("A key material rotation request was sent to AWS on " + now + ".")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Trace(ctx, "[resource_aws_key_rotation.go -> Create][response:"+response)
}

func (r *resourceAWSKeyRotation) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Read]["+id+"]")
	var state AWSKeyRotationTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tflog.Trace(ctx, "[resource_aws_key_rotation.go -> Read][response:"+response)
}

func (r *resourceAWSKeyRotation) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

func (r *resourceAWSKeyRotation) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

func (r *resourceAWSKeyRotation) rotateKeyMaterial(ctx context.Context, id string, plan *AWSKeyRotationTFSDK, diags *diag.Diagnostics) string {
	tflog.Trace(ctx, "[resource_aws_key_rotation.go -> rotateKeyMaterial]["+id+"]")
	keyID := plan.KeyID.ValueString()
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotate-material", nil)
	if err != nil {
		msg := "Error rotating AWS key material."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Trace(ctx, "[resource_aws_key_rotation.go -> rotateKeyMaterial][response:"+response)
	return response
}
