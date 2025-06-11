package cckm

import (
	"context"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
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
		Description: "Use this resource to create an AWS key Rotation.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "AWS region and AWS key identifier separated by a backslash.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager Key ID.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "Status.",
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

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.Status = types.StringValue("Key rotation is in progress")
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
	/*id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Update]["+id+"]")
	var (
		plan     AWSKeyRotationTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := plan.KeyID.ValueString()
	_ = r.rotateKeyMaterial(ctx, keyID, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	var diags diag.Diagnostics
	plan.ID = gjson.Get(response, "id").String()
	r.setKeyState(ctx, response, &plan, &diags)
	for _, d := range diags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Trace(ctx, "[resource_aws_key_rotation.go -> Update][response:"+response)*/
}

func (r *resourceAWSKeyRotation) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	/*id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Delete]["+id+"]")
	var state AWSKeyTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, err := r.client.GetById(ctx, id, keyID, common.URL_AWS_KEY)
	if err != nil {
		msg := "Error reading AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	keyState := gjson.Get(response, "aws_param.KeyState").String()
	if keyState == "PendingDeletion" || keyState == "PendingReplicaDeletion" {
		msg := "AWS key is already pending deletion, it will be removed from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		return
	}
	removeKeyPolicyTemplateTag(ctx, id, r.client, response, &resp.Diagnostics)
	payload := ScheduleForDeletionJSON{
		Days: state.ScheduleForDeletionDays.ValueInt64(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error deleting AWS key, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err = r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/schedule-deletion", payloadJSON)
	if err != nil {
		msg := "Error deleting AWS key."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		if strings.Contains(err.Error(), "is pending deletion") {
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
		} else {
			tflog.Error(ctx, details)
			resp.Diagnostics.AddError(details, "")
		}
	}
	tflog.Trace(ctx, "[resource_aws_key_rotation.go -> Delete][response:"+response)*/
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
