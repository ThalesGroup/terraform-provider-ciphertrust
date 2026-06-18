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
	_ resource.Resource               = &resourceAWSKeyRotation{}
	_ resource.ResourceWithConfigure  = &resourceAWSKeyRotation{}
	_ resource.ResourceWithModifyPlan = &resourceAWSKeyRotation{}
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
			"If the AWS key is not found in CipherTrust Manager during refresh, an error is returned. " +
			"Use 'terraform state rm' to remove this resource from state if the key no longer exists. " +
			"\n\n\n\nNote: This resource and the datasource are only available for CipherTrust Manager version 2.20 and greater.",
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

// Create sends a key material rotation request to AWS and records the operation in Terraform state.
func (r *resourceAWSKeyRotation) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Create]["+id+"]")
	var (
		plan     AWSKeyRotationTFSDK
		response string
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	response = r.rotateKeyMaterial(ctx, id, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05 MST")
	plan.ID = types.StringValue(gjson.Get(response, "id").String() + "-" + now)
	plan.Status = types.StringValue("A key material rotation request was sent to AWS on " + now + ".")
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
	tflog.Debug(ctx, "[resource_aws_key_rotation.go -> Create][response:"+redactAWSResponse(response))
}

// Read refreshes the Terraform state for an AWS key by fetching the latest data from CipherTrust Manager.
// Returns an error if the key is not found (no kms_id is tracked by this resource, so preserveState is never set).
func (r *resourceAWSKeyRotation) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_key_rotation.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_key_rotation.go -> Read]["+id+"]")
	var state AWSKeyRotationTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	keyID := state.KeyID.ValueString()
	response, _ := getAwsKey(ctx, id, r.client, "", keyID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	readKeyState := gjson.Get(response, "aws_param.KeyState").String()
	if readKeyState == "PendingDeletion" || readKeyState == "PendingReplicaDeletion" {
		msg := "AWS key is pending deletion, removing rotation resource from state."
		details := utils.ApiError(msg, map[string]interface{}{"key_id": keyID})
		tflog.Warn(ctx, details)
		resp.Diagnostics.AddWarning(details, "")
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Update is a no-op; rotations are immutable once submitted and require replace.
func (r *resourceAWSKeyRotation) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
}

// Delete is a no-op; rotation records are removed from state only and do not affect the AWS key.
func (r *resourceAWSKeyRotation) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceAWSKeyRotation) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state AWSKeyRotationTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if plan.KeyID != state.KeyID {
		resp.Diagnostics.AddError(
			"Immutable attribute change detected",
			"The following attributes cannot be modified after creation: key_id. "+
				"Delete and recreate the resource to apply these changes.",
		)
	}
}

// rotateKeyMaterial calls the CipherTrust Manager rotate-material API for the specified AWS key.
func (r *resourceAWSKeyRotation) rotateKeyMaterial(ctx context.Context, id string, plan *AWSKeyRotationTFSDK, diags *diag.Diagnostics) string {
	keyID := plan.KeyID.ValueString()
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KEY+"/"+keyID+"/rotate-material", nil)
	if err != nil {
		msg := "Error rotating AWS key material."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "key_id": keyID})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return ""
	}
	tflog.Debug(ctx, "[resource_aws_key_rotation.go -> rotateKeyMaterial][response:"+redactAWSResponse(response))
	return response
}
