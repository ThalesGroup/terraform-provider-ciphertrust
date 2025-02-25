package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource              = &resourceCCKMAWSKMS{}
	_ resource.ResourceWithConfigure = &resourceCCKMAWSKMS{}

	description_resource = `AWS Key Management Service (AWS KMS) is used to create and manage keys.

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

// Schema defines the schema for the resource.
func (r *resourceCCKMAWSKMS) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: description_resource,
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
			"connection": schema.StringAttribute{
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
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCCKMAWSKMS) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Create]["+id+"]")

	// Retrieve values from plan
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

	var regionsArr []string
	for _, region := range plan.Regions {
		regionsArr = append(regionsArr, region.ValueString())
	}
	payload.Regions = regionsArr

	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = common.TrimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = common.TrimString(plan.AssumeRoleExternalID.String())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_kms.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS KMS Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KMS, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_kms.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating AWS KMS on CipherTrust Manager: ",
			"Could not create AWS KMS, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	plan.URI = types.StringValue(gjson.Get(response, "uri").String())
	plan.Account = types.StringValue(gjson.Get(response, "account").String())
	plan.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	plan.Application = types.StringValue(gjson.Get(response, "application").String())
	plan.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	plan.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCCKMAWSKMS) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state KMSModelTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AWS_KMS)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_kms.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading AWS KMS on CipherTrust Manager: ",
			"Could not read AWS KMS id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	state.ID = types.StringValue(gjson.Get(response, "id").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	state.Connection = types.StringValue(gjson.Get(response, "connection").String())
	state.AssumeRoleARN = types.StringValue(gjson.Get(response, "assume_role_arn").String())
	state.AssumeRoleExternalID = types.StringValue(gjson.Get(response, "assume_role_external_id").String())

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Read]["+id+"]")
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCCKMAWSKMS) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan KMSModelTFSDK
	var payload KMSModelJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var regionsArr []string
	for _, region := range plan.Regions {
		regionsArr = append(regionsArr, region.ValueString())
	}
	payload.Regions = regionsArr

	if plan.AssumeRoleARN.ValueString() != "" && plan.AssumeRoleARN.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleARN = common.TrimString(plan.AssumeRoleARN.String())
	}
	if plan.AssumeRoleExternalID.ValueString() != "" && plan.AssumeRoleExternalID.ValueString() != types.StringNull().ValueString() {
		payload.AssumeRoleExternalID = common.TrimString(plan.AssumeRoleExternalID.String())
	}
	if plan.Connection.ValueString() != "" && plan.Connection.ValueString() != types.StringNull().ValueString() {
		payload.Connection = common.TrimString(plan.Connection.String())
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_kms.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: AWS KMS Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_AWS_KMS, payloadJSON, "updatedAt")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_aws_kms.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating AWS KMS on CipherTrust Manager: ",
			"Could not update AWS KMS, unexpected error: "+err.Error(),
		)
		return
	}
	plan.ID = types.StringValue(response)
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

}

// Delete deletes the resource and removes the Terraform state on success.
func (r *resourceCCKMAWSKMS) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state KMSModelTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete existing order
	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AWS_KMS, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting AWS KMS",
			"Could not delete AWS KMS, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCCKMAWSKMS) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
