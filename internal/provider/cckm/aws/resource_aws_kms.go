package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
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
	_                      resource.Resource              = &resourceCCKMAWSKMS{}
	_                      resource.ResourceWithConfigure = &resourceCCKMAWSKMS{}
	kmsResourceDescription                                = `AWS Key Management Service (AWS KMS) is used to create and manage keys.

Use the APIs in this section to:

* List and add the AWS accounts and regions based on the connections.
* Get, delete, and update the AWS KMS account.
* Grant permissions to CCKM users to perform specific actions on the AWS KMS.`
)

func NewResourceCCKMAWSKMS() resource.Resource {
	return &resourceCCKMAWSKMS{}
}

type resourceCCKMAWSKMS struct {
	client *common.Client
}

func (r *resourceCCKMAWSKMS) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_kms"
}

func (r *resourceCCKMAWSKMS) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *resourceCCKMAWSKMS) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: kmsResourceDescription,
		Attributes: map[string]schema.Attribute{
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
			},
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the AWS account.",
			},
			"acls": schema.SetNestedAttribute{
				Computed:    true,
				Description: "List of ACLs that have been added to the KMS.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"actions": schema.SetAttribute{
							Computed:    true,
							Description: "Permitted actions.",
							ElementType: types.StringType,
						},
						"group": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager group.",
						},
						"user_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager user ID.",
						},
					},
				},
			},
			"application": schema.StringAttribute{
				Description: "The application this resource belongs to.",
				Computed:    true,
			},
			"arn": schema.StringAttribute{
				Computed:    true,
				Description: "Amazon Resource Name.",
			},
			"assume_role_arn": schema.StringAttribute{
				Optional:    true,
				Description: "Amazon Resource Name (ARN) of the role to be assumed.",
			},
			"assume_role_external_id": schema.StringAttribute{
				Optional:    true,
				Description: "External ID for the role to be assumed. This parameter can be specified only with \"assume_role_arn\".",
			},
			"aws_connection": schema.StringAttribute{
				Required:    true,
				Description: "Name or ID of the connection in which the account is managed.",
			},
			"auto_added": schema.BoolAttribute{
				Computed:    true,
				Description: "True if the KMS was added by a scheduler.",
			},
			"created_at": schema.StringAttribute{
				Description: "Date/time the application was created",
				Computed:    true,
			},
			"dev_account": schema.StringAttribute{
				Description: "The developer account which owns this resource's application.",
				Computed:    true,
			},
			"id": schema.StringAttribute{
				Description: "The unique identifier of the resource.",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique name for the KMS.",
			},
			"regions": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "AWS regions to be added to the KMS.",
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: "The status of the KMS, archived or active.",
			},
			"updated_at": schema.StringAttribute{
				Computed:    true,
				Description: "Date and time the KMS was last updated",
			},
			"uri": schema.StringAttribute{
				Computed:    true,
				Description: "A human-readable unique identifier of the resource.",
			},
		},
	}
}

func (r *resourceCCKMAWSKMS) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Create]["+id+"]")
	var (
		plan    KMSModelTFSDK
		payload KMSModelJSON
	)
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.AccountID = common.TrimString(plan.AccountID.String())
	payload.Connection = common.TrimString(plan.Connection.String())
	payload.Name = common.TrimString(plan.Name.String())
	payload.Regions = make([]string, 0, len(plan.Regions.Elements()))
	diags.Append(plan.Regions.ElementsAs(ctx, &payload.Regions, false)...)
	if diags.HasError() {
		return
	}
	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = common.TrimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = common.TrimString(plan.AssumeRoleExternalID.String())
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error creating AWS KMS, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "name": payload.Name})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KMS, payloadJSON)
	if err != nil {
		msg := "Error creating AWS KMS"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	r.setKmsState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error creating AWS KMS, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"kms id": plan.ID.ValueString()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCCKMAWSKMS) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Read]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Read]["+id+"]")
	var state KMSModelTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	response, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
	if err != nil {
		msg := "Error reading AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.setKmsState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error reading AWS KMS, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"kms id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Read]["+id+"]")
}

func (r *resourceCCKMAWSKMS) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Update]["+id+"]")
	var (
		plan    KMSModelTFSDK
		payload KMSModelJSON
	)
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.Regions = make([]string, 0, len(plan.Regions.Elements()))
	diags.Append(plan.Regions.ElementsAs(ctx, &payload.Regions, false)...)
	if diags.HasError() {
		return
	}
	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = common.TrimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = common.TrimString(plan.AssumeRoleExternalID.String())
	}
	if plan.Connection.ValueString() != "" && plan.Connection.ValueString() != types.StringNull().ValueString() {
		payload.Connection = common.TrimString(plan.Connection.String())
	}
	kmsID := plan.ID.ValueString()
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating AWS KMS, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	_, err = r.client.UpdateDataV2(ctx, kmsID, common.URL_AWS_KMS, payloadJSON)
	if err != nil {
		msg := "Error updating AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
	if err != nil {
		msg := "Error reading AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.setKmsState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS KMS, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"kms id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceCCKMAWSKMS) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Delete]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Delete]["+id+"]")
	var state KMSModelTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	_, err := r.client.DeleteByURL(ctx, kmsID, common.URL_AWS_KMS+"/"+kmsID)
	if err != nil {
		msg := "Error deleting AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
}

func (r *resourceCCKMAWSKMS) setKmsState(ctx context.Context, response string, state *KMSModelTFSDK, diags *diag.Diagnostics) {
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	acls.SetAclsStateFromJSON(ctx, gjson.Get(response, "acls"), &state.Acls, diags)
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.Arn = types.StringValue(gjson.Get(response, "arn").String())
	state.AutoAdded = types.BoolValue(gjson.Get(response, "auto_added").Bool())
	state.Connection = types.StringValue(gjson.Get(response, "connection").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Regions = utils.StringSliceJSONToListValue(gjson.Get(response, "regions").Array(), diags)
	state.Status = types.StringValue(gjson.Get(response, "status").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
}
