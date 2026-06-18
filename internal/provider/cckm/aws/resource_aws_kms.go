package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	_ resource.Resource                = &resourceCCKMAWSKMS{}
	_ resource.ResourceWithConfigure   = &resourceCCKMAWSKMS{}
	_ resource.ResourceWithImportState = &resourceCCKMAWSKMS{}
	_ resource.ResourceWithModifyPlan  = &resourceCCKMAWSKMS{}
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
		Description: "Use this resource to create and manage KMS keys for AWS accounts in CipherTrust Manager. " +
			"If the KMS is not found during refresh it is removed from state automatically.",
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
				Description: "(Updatable) Amazon Resource Name (ARN) of the role to be assumed.",
			},
			"assume_role_external_id": schema.StringAttribute{
				Optional:    true,
				Description: "(Updatable) External ID for the role to be assumed. This parameter can be specified only with \"assume_role_arn\".",
			},
			"aws_connection": schema.StringAttribute{
				Required:    true,
				Description: "(Updatable) Name or ID of the connection in which the account is managed.",
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
				Description: "(Updatable) AWS regions to be added to the KMS.",
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

// Create registers a new AWS KMS connection in CipherTrust Manager and sets Terraform state.
func (r *resourceCCKMAWSKMS) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Create]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Create]["+id+"]")
	var (
		plan    KMSModelTFSDK
		payload KMSModelJSON
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload.AccountID = common.TrimString(plan.AccountID.String())
	payload.Connection = common.TrimString(plan.Connection.String())
	payload.Name = common.TrimString(plan.Name.String())
	payload.Regions = make([]string, 0, len(plan.Regions.Elements()))
	resp.Diagnostics.Append(plan.Regions.ElementsAs(ctx, &payload.Regions, false)...)
	if resp.Diagnostics.HasError() {
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
	tflog.Debug(ctx, "[resource_aws_kms.go -> Create][response:"+redactAWSResponse(response)+"]")
	plan.ID = types.StringValue(gjson.Get(response, "id").String())
	r.setKmsState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error creating AWS KMS, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"kms id": plan.ID.ValueString()})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state for an AWS KMS by fetching the latest data from CipherTrust Manager.
func (r *resourceCCKMAWSKMS) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Read]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Read]["+id+"]")
	var state KMSModelTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	// Save the prior connection value before setKmsState overwrites it.
	priorConn := state.Connection.ValueString()
	response, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
	if err != nil {
		if strings.Contains(err.Error(), notFoundError) {
			msg := "AWS KMS was not found. It will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID})
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
			resp.State.RemoveResource(ctx)
			return
		}
		msg := "Error reading AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	tflog.Debug(ctx, "[resource_aws_kms.go -> Read][response:"+redactAWSResponse(response)+"]")
	r.setKmsState(ctx, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	// Preserve the user-supplied aws_connection form (name or UUID) when it resolves
	// to the same connection that the API reports, so configs using either form do
	// not produce spurious plan drift after every refresh.
	// Only overwrite when the connection has genuinely changed out-of-band.
	apiConnName := gjson.Get(response, "connection").String()
	if priorConn != "" && priorConn != apiConnName {
		connResp, connErr := r.client.GetById(ctx, id, priorConn, common.URL_AWS_CONNECTION)
		if connErr == nil && gjson.Get(connResp, "name").String() == apiConnName {
			// Same connection, different representation - restore the prior value so
			// that users who specify a UUID do not see spurious drift.
			state.Connection = types.StringValue(priorConn)
		}
		// else: genuine out-of-band change - keep the API name that setKmsState set.
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update applies plan changes (regions, connection, assume-role) to an existing AWS KMS registration.
func (r *resourceCCKMAWSKMS) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Update]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Update]["+id+"]")
	var (
		plan    KMSModelTFSDK
		state   KMSModelTFSDK
		payload KMSModelJSON
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	if _, kmsErr := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS); kmsErr != nil {
		if strings.Contains(kmsErr.Error(), notFoundError) {
			msg := "AWS KMS was not found. It will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID})
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
			resp.State.RemoveResource(ctx)
			return
		}
		msg := "Error updating AWS KMS, failed to read AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": kmsErr.Error(), "kms_id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	payload.Regions = make([]string, 0, len(plan.Regions.Elements()))
	resp.Diagnostics.Append(plan.Regions.ElementsAs(ctx, &payload.Regions, false)...)
	if resp.Diagnostics.HasError() {
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
	tflog.Debug(ctx, "[resource_aws_kms.go -> Update][response:"+redactAWSResponse(response)+"]")
	r.setKmsState(ctx, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS KMS, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"kms id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Delete removes an AWS KMS registration from CipherTrust Manager.
// If the KMS is not found (HTTP 404) when destroy runs, a warning is emitted and the resource is
// removed from state rather than returning an error.
func (r *resourceCCKMAWSKMS) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> Delete]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> Delete]["+id+"]")
	var state KMSModelTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	if _, kmsErr := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS); kmsErr != nil {
		if strings.Contains(kmsErr.Error(), notFoundError) {
			msg := "AWS KMS was not found. It will be removed from state."
			details := utils.ApiError(msg, map[string]interface{}{"kms_id": kmsID})
			tflog.Warn(ctx, details)
			resp.Diagnostics.AddWarning(details, "")
			return // Terraform removes from state when Delete returns without error.
		}
		msg := "Error deleting AWS KMS, failed to read AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": kmsErr.Error(), "kms_id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	_, err := r.client.DeleteByURL(ctx, id, common.URL_AWS_KMS+"/"+kmsID)
	if err != nil {
		msg := "Error deleting AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		tflog.Error(ctx, details)
		resp.Diagnostics.AddError(details, "")
	}
}

// ModifyPlan errors at plan time if any immutable attribute is changed on an existing resource,
// preventing silent in-place updates to fields that cannot be modified after creation.
func (r *resourceCCKMAWSKMS) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip create and destroy operations.
	if req.Plan.Raw.IsNull() || req.State.Raw.IsNull() {
		return
	}

	var plan, state KMSModelTFSDK

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var changed []string

	if plan.AccountID != state.AccountID {
		changed = append(changed, "account_id")
	}
	if plan.Name != state.Name {
		changed = append(changed, "name")
	}

	if len(changed) > 0 {
		resp.Diagnostics.AddError(
			"Immutable attribute change detected",
			fmt.Sprintf(
				"The following attributes cannot be modified after creation: %s. "+
					"Delete and recreate the resource to apply these changes.",
				strings.Join(changed, ", "),
			),
		)
	}
}

// ImportState imports an existing AWS KMS into Terraform state using its resource ID.
func (r *resourceCCKMAWSKMS) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	tflog.Debug(ctx, common.MSG_METHOD_START+"[resource_aws_kms.go -> ImportState]["+id+"]")
	defer tflog.Debug(ctx, common.MSG_METHOD_END+"[resource_aws_kms.go -> ImportState]["+id+"]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setKmsState populates the Terraform state for an AWS KMS from an API response JSON string.
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
