package cckm

import (
	"context"
	"encoding/json"
	"fmt"
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

const (
	KmsURL       = "api/v1/cckm/aws/kms"
	KmsWithIDURL = "api/v1/cckm/aws/kms/%s"
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
			"id": schema.StringAttribute{
				Description: "The unique identifier of the resource",
				Computed:    true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"uri": schema.StringAttribute{
				Description: "A human readable unique identifier of the resource",
				Computed:    true,
			},
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
			},
			"dev_account": schema.StringAttribute{
				Description: "The developer account which owns this resource's application.",
				Computed:    true,
			},
			"application": schema.StringAttribute{
				Description: "The application this resource belongs to.",
				Computed:    true,
			},
			"created_at": schema.StringAttribute{
				Description: "Date/time the application was created",
				Computed:    true,
			},
			"updated_at": schema.StringAttribute{
				Description: "Date/time the application was updated",
				Computed:    true,
			},
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "ID of the AWS account.",
			},
			"aws_connection": schema.StringAttribute{
				Required:    true,
				Description: "Name or ID of the connection in which the account is managed.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Unique name for the KMS.",
			},
			"regions": schema.ListAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "AWS regions to be added to the CCKM.",
			},
			"assume_role_arn": schema.StringAttribute{
				Optional:    true,
				Description: "Amazon Resource Name (ARN) of the role to be assumed.",
			},
			"assume_role_external_id": schema.StringAttribute{
				Optional:    true,
				Description: "External ID for the role to be assumed. This parameter can be specified only with \"assume_role_arn\".",
			},
			"arn": schema.StringAttribute{
				Computed:    true,
				Description: "Amazon Resource Name.",
			},
		},
	}
}

func (r *resourceCCKMAWSKMS) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Create]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Create]["+id+"]")
	var plan KMSModelTFSDK
	var payload KMSModelJSON
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
		msg := "Error creating 'ciphertrust_aws_kms', error marshaling payload."
		details := map[string]interface{}{"name": payload.Name, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	response, err := r.client.PostDataV2(ctx, id, KmsURL, payloadJSON)
	if err != nil {
		msg := "Error creating 'ciphertrust_aws_kms', error posting payload."
		details := map[string]interface{}{"name": payload.Name, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	r.setKmsState(response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		details := map[string]interface{}{"kms id": plan.ID.ValueString()}
		msg := "Error creating 'ciphertrust_aws_kms', failed to set resource state."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
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
	response, err := r.client.GetById(ctx, id, kmsID, KmsURL)
	if err != nil {
		details := map[string]interface{}{"kms id": kmsID, "error": err.Error()}
		msg := "Error reading 'ciphertrust_aws_kms'."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setKmsState(response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		details := map[string]interface{}{"kms id": kmsID}
		msg := "Error reading 'ciphertrust_aws_kms', failed to set resource state."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Read]["+id+"]")
}

func (r *resourceCCKMAWSKMS) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Update]["+id+"]")
	var plan KMSModelTFSDK
	var payload KMSModelJSON
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
		msg := "Error updating 'ciphertrust_aws_kms', error marshaling payload."
		details := map[string]interface{}{"kms id": kmsID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	response, err := r.client.UpdateDataV2(ctx, kmsID, KmsURL, payloadJSON)
	if err != nil {
		msg := "Error updating 'ciphertrust_aws_kms', error posting payload."
		details := map[string]interface{}{"kms id": kmsID, "payload": fmt.Sprintf("%+v", payload), "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
	r.setKmsState(response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		details := map[string]interface{}{"kms id": kmsID}
		msg := "Error updating 'ciphertrust_aws_kms', failed to set resource state."
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
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
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Update]["+id+"]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Update]["+id+"]")
	var state KMSModelTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	_, err := r.client.DeleteByURL(ctx, kmsID, fmt.Sprintf(KmsWithIDURL, kmsID))
	if err != nil {
		msg := "Error deleting 'ciphertrust_aws_kms'."
		details := map[string]interface{}{"key_id": kmsID, "error": err.Error()}
		tflog.Error(ctx, msg, details)
		resp.Diagnostics.AddError(msg, apiDetail(details))
		return
	}
}

func (r *resourceCCKMAWSKMS) setKmsState(response string, state *KMSModelTFSDK, diags *diag.Diagnostics) {
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	state.Connection = types.StringValue(gjson.Get(response, "connection").String())
	state.Arn = types.StringValue(gjson.Get(response, "arn").String())
	state.Regions = flattenStringSliceJSON(gjson.Get(response, "regions").Array(), diags)
}
