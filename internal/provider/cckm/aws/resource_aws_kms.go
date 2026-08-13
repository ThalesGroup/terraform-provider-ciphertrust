package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/mutex"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

const kmsStatusArchived = "ARCHIVED"

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
		Description: "Use this resource to create and manage KMS keys for AWS accounts in CipherTrust Manager.",
		Attributes: map[string]schema.Attribute{
			"account": schema.StringAttribute{
				Description: "The account which owns this resource.",
				Computed:    true,
			},
			"account_id": schema.StringAttribute{
				Required:    true,
				Description: "(Immutable) ID of the AWS account.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
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
			"archive": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Set to true to archive the KMS. An archived KMS is not deleted but cannot be used to manage keys. Set to false to recover the KMS and set its status back to Active, after which it can be used for all operations. Cannot be set to true at creation time; archive the KMS via update after it has been created. **Only available on CipherTrust Manager - not supported on CDSPaaS.**",
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
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager AWS connection ID.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"connection_name": schema.StringAttribute{
				Computed:    true,
				Description: "The connection name as returned by CipherTrust Manager. Always reflects the current server-side value; changes here indicate an out-of-band connection update.",
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
				Description: "(Immutable) Unique name for the KMS.",
				PlanModifiers: []planmodifier.String{
					modifiers.ImmutableString(),
				},
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

// Create registers a new AWS KMS connection in CipherTrust Manager and sets Terraform state.
func (r *resourceCCKMAWSKMS) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_kms.go -> Create][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_kms.go -> Create][" + id + "]")
	var (
		plan    KMSModelTFSDK
		payload KMSModelJSON
	)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	connResponse, connErr := r.client.GetById(ctx, id, common.TrimString(plan.ConnectionID.String()), common.URL_AWS_CONNECTION)
	if connErr != nil {
		msg := "Error creating AWS KMS, failed to read AWS connection by 'connection_id'."
		details := utils.ApiError(msg, map[string]interface{}{"error": connErr.Error(), "connection_id": plan.ConnectionID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	if gjson.Get(connResponse, "id").String() != plan.ConnectionID.ValueString() {
		msg := "Error creating AWS KMS: connection_id must be a resource ID of an AWS connection."
		details := utils.ApiError(msg, map[string]interface{}{"connection_id": plan.ConnectionID.ValueString()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	connAccount := gjson.Get(connResponse, "account").String()
	mutexKey := fmt.Sprintf("aws-kms-%s", connAccount)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

	payload.AccountID = common.TrimString(plan.AccountID.String())
	payload.Connection = common.TrimString(plan.ConnectionID.String())
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
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	response, err := r.client.PostDataV2(ctx, id, common.URL_AWS_KMS, payloadJSON)
	if err != nil {
		msg := "Error creating AWS KMS"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error()})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	r.client.Log.Debug("[resource_aws_kms.go -> Create][response:" + redactAWSResponse(response) + "]")
	kmsID := gjson.Get(response, "id").String()
	plan.ID = types.StringValue(kmsID)

	// Always re-read so state reflects the current server status.
	response, err = r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
	if err != nil {
		msg := "Error reading AWS KMS after create."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	var stateDiags diag.Diagnostics
	r.setKmsState(ctx, id, response, &plan, &stateDiags)
	for _, d := range stateDiags {
		resp.Diagnostics.AddWarning(d.Summary(), d.Detail())
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

// Read refreshes the Terraform state for an AWS KMS by fetching the latest data from CipherTrust Manager.
// A 404 is treated as an error so state is preserved until the resource is explicitly removed
// (terraform destroy or removed from config).
func (r *resourceCCKMAWSKMS) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_kms.go -> Read][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_kms.go -> Read][" + id + "]")
	var state KMSModelTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	response := getAwsKms(ctx, id, r.client, kmsID, "reading", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_aws_kms.go -> Read][response:" + redactAWSResponse(response) + "]")
	r.setKmsState(ctx, id, response, &state, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update applies plan changes (regions, connection, assume-role) to an existing AWS KMS registration.
func (r *resourceCCKMAWSKMS) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_kms.go -> Update][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_kms.go -> Update][" + id + "]")
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
	if plan.ConnectionID.ValueString() != state.ConnectionID.ValueString() {
		connResp, connErr := r.client.GetById(ctx, id, common.TrimString(plan.ConnectionID.String()), common.URL_AWS_CONNECTION)
		if connErr != nil {
			msg := "Error updating AWS KMS, failed to read AWS connection by 'connection_id'."
			details := utils.ApiError(msg, map[string]interface{}{"error": connErr.Error(), "connection_id": plan.ConnectionID.ValueString()})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
		if gjson.Get(connResp, "id").String() != plan.ConnectionID.ValueString() {
			msg := "Error updating AWS KMS: connection_id must be a resource ID of an AWS connection."
			details := utils.ApiError(msg, map[string]interface{}{"connection_id": plan.ConnectionID.ValueString()})
			r.client.Log.Error(details)
			resp.Diagnostics.AddError(details, "")
			return
		}
	}
	kmsID := state.ID.ValueString()
	kmsResponse := getAwsKms(ctx, id, r.client, kmsID, "updating", &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	r.client.Log.Debug("[resource_aws_kms.go -> Update][get response:" + redactAWSResponse(kmsResponse) + "]")

	kmsAccount := gjson.Get(kmsResponse, "account").String()
	mutexKey := fmt.Sprintf("aws-kms-%s", kmsAccount)
	mutex.CckmMutex.Lock(mutexKey)
	defer mutex.CckmMutex.Unlock(mutexKey)

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
	if plan.ConnectionID.ValueString() != "" && plan.ConnectionID.ValueString() != types.StringNull().ValueString() {
		payload.Connection = common.TrimString(plan.ConnectionID.String())
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error updating AWS KMS, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms id": kmsID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}
	// Recover before the PATCH so the KMS is active and can accept other updates.
	currentlyArchived := gjson.Get(kmsResponse, "status").String() == kmsStatusArchived
	if !plan.Archive.IsNull() && !plan.Archive.ValueBool() && currentlyArchived {
		recoverKMS(ctx, id, r.client, kmsID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	_, err = r.client.UpdateDataV2(ctx, kmsID, common.URL_AWS_KMS, payloadJSON)
	if err != nil {
		msg := "Error updating AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms id": kmsID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	// Archive after the PATCH so it is the last operation.
	if !plan.Archive.IsNull() && plan.Archive.ValueBool() && !currentlyArchived {
		archiveKMS(ctx, id, r.client, kmsID, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// Always re-read so state reflects the current server status.
	response, err := r.client.GetById(ctx, id, kmsID, common.URL_AWS_KMS)
	if err != nil {
		msg := "Error reading AWS KMS after update."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms id": kmsID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
		return
	}

	r.client.Log.Debug("[resource_aws_kms.go -> Update][response:" + redactAWSResponse(response) + "]")
	r.setKmsState(ctx, id, response, &plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		msg := "Error updating AWS KMS, failed to set resource state."
		details := utils.ApiError(msg, map[string]interface{}{"kms id": kmsID})
		r.client.Log.Error(details)
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
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_kms.go -> Delete][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_kms.go -> Delete][" + id + "]")
	var state KMSModelTFSDK
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	kmsID := state.ID.ValueString()
	if getAwsKms(ctx, id, r.client, kmsID, "deleting", &resp.Diagnostics) == "" {
		return // 404 warning added (Terraform removes state) or non-404 error added (state kept).
	}
	_, err := r.client.DeleteByURL(ctx, id, common.URL_AWS_KMS+"/"+kmsID)
	if err != nil {
		msg := "Error deleting AWS KMS."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		r.client.Log.Error(details)
		resp.Diagnostics.AddError(details, "")
	}
}

// ModifyPlan enforces create-time restrictions and errors at plan time if any immutable
// attribute is changed on an existing resource.
func (r *resourceCCKMAWSKMS) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Skip destroy.
	if req.Plan.Raw.IsNull() {
		return
	}

	// Create-time validations: reject archive = true on a new resource.
	if req.State.Raw.IsNull() {
		var plan KMSModelTFSDK
		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
		if !resp.Diagnostics.HasError() && !plan.Archive.IsNull() && plan.Archive.ValueBool() {
			resp.Diagnostics.AddError(
				"Invalid create-time configuration",
				"\"archive\" cannot be set to true at creation time. "+
					"Create the KMS first, then set archive = true via update.",
			)
		}
		return
	}

	// CDSPaaS does not support archiving a KMS.
	if r.client != nil && r.client.IsCDSPaaS {
		var plan KMSModelTFSDK
		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
		if !resp.Diagnostics.HasError() && !plan.Archive.IsNull() && !plan.Archive.IsUnknown() && plan.Archive.ValueBool() {
			resp.Diagnostics.AddAttributeError(
				path.Root("archive"),
				"'archive' is not supported on CDSPaaS",
				"The 'archive' attribute is only supported on on-premises CipherTrust Manager. "+
					"CDSPaaS does not support archiving a KMS; this attribute must be omitted or set to false.",
			)
		}
	}
}

// ImportState imports an existing AWS KMS into Terraform state using its resource ID.
func (r *resourceCCKMAWSKMS) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := uuid.New().String()
	r.client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_kms.go -> ImportState][" + id + "]")
	defer r.client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_kms.go -> ImportState][" + id + "]")
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setKmsState populates the Terraform state for an AWS KMS from an API response JSON string.
// connection_id and connection_name are resolved via resolveConnectionByIDOrName using the
// connection field returned in the API response (maybe a UUID or a name).
func (r *resourceCCKMAWSKMS) setKmsState(ctx context.Context, reqID string, response string, state *KMSModelTFSDK, diags *diag.Diagnostics) {
	state.Account = types.StringValue(gjson.Get(response, "account").String())
	acls.SetAclsStateFromJSON(ctx, gjson.Get(response, "acls"), &state.Acls, diags)
	state.AccountID = types.StringValue(gjson.Get(response, "account_id").String())
	state.Application = types.StringValue(gjson.Get(response, "application").String())
	state.Arn = types.StringValue(gjson.Get(response, "arn").String())
	state.AutoAdded = types.BoolValue(gjson.Get(response, "auto_added").Bool())
	state.DevAccount = types.StringValue(gjson.Get(response, "devAccount").String())
	state.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	state.Name = types.StringValue(gjson.Get(response, "name").String())
	state.Regions = utils.StringSliceJSONToListValue(gjson.Get(response, "regions").Array(), diags)
	state.Status = types.StringValue(gjson.Get(response, "status").String())
	state.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	state.URI = types.StringValue(gjson.Get(response, "uri").String())
	state.Archive = types.BoolValue(gjson.Get(response, "status").String() == kmsStatusArchived)
	r.resolveConnectionByIDOrName(ctx, reqID, gjson.Get(response, "connection").String(), state, diags)
}

// resolveConnectionByIDOrName resolves an AWS connection from the value stored in the API
// "connection" field, which may be a UUID or a human-readable name. It first attempts a
// GetById lookup; on a 404 it falls back to a name-based list query. Both connection_id
// and connection_name are written into state. An error is added to diags if all lookups fail.
func (r *resourceCCKMAWSKMS) resolveConnectionByIDOrName(ctx context.Context, reqID string, connValue string, state *KMSModelTFSDK, diags *diag.Diagnostics) {
	if connValue == "" {
		return
	}
	// Try lookup by ID first.
	connResp, err := r.client.GetById(ctx, reqID, connValue, common.URL_AWS_CONNECTION)
	if err != nil && !strings.Contains(err.Error(), notFoundError) {
		msg := "Error resolving AWS connection by ID."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": connValue})
		diags.AddError(details, "")
		return
	}
	if err == nil {
		state.ConnectionID = types.StringValue(gjson.Get(connResp, "id").String())
		state.ConnectionName = types.StringValue(gjson.Get(connResp, "name").String())
		return
	}
	// 404 - fall back to lookup by name.
	listResp, err := r.client.GetAll(ctx, reqID, common.URL_AWS_CONNECTION+"?name="+connValue)
	if err != nil {
		msg := "Error resolving AWS connection by name."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": connValue})
		diags.AddError(details, "")
		return
	}
	resources := gjson.Get(listResp, "resources").Array()
	if len(resources) == 0 {
		msg := "AWS connection not found by ID or name."
		details := utils.ApiError(msg, map[string]interface{}{"connection": connValue})
		diags.AddError(details, "")
		return
	}
	connID := resources[0].Get("id").String()
	if connID == "" {
		msg := "AWS connection found by name but ID is empty."
		details := utils.ApiError(msg, map[string]interface{}{"connection": connValue})
		diags.AddError(details, "")
		return
	}
	state.ConnectionID = types.StringValue(connID)
	state.ConnectionName = types.StringValue(resources[0].Get("name").String())
}

// archiveKMS archives a KMS registration.
func archiveKMS(ctx context.Context, id string, client *common.Client, kmsID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_kms.go -> archiveKMS][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_kms.go -> archiveKMS][" + id + "]")
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KMS+"/"+kmsID+"/archive")
	if err != nil {
		msg := "Error archiving AWS KMS"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Info(fmt.Sprintf("[resource_aws_kms.go -> archiveKMS] KMS archived successfully. kms_id: %s", kmsID))
	client.Log.Debug("[resource_aws_kms.go -> archiveKMS][response:" + redactAWSResponse(response) + "]")
}

// recoverKMS recovers an archived KMS registration.
func recoverKMS(ctx context.Context, id string, client *common.Client, kmsID string, diags *diag.Diagnostics) {
	client.Log.Debug(common.MSG_METHOD_START + "[resource_aws_kms.go -> recoverKMS][" + id + "]")
	defer client.Log.Debug(common.MSG_METHOD_END + "[resource_aws_kms.go -> recoverKMS][" + id + "]")
	response, err := client.PostNoData(ctx, id, common.URL_AWS_KMS+"/"+kmsID+"/recover")
	if err != nil {
		msg := "Error recovering AWS KMS"
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "kms_id": kmsID})
		client.Log.Error(details)
		diags.AddError(details, "")
		return
	}
	client.Log.Info(fmt.Sprintf("[resource_aws_kms.go -> recoverKMS] KMS recovered successfully. kms_id: %s", kmsID))
	client.Log.Debug("[resource_aws_kms.go -> recoverKMS][response:" + redactAWSResponse(response) + "]")
}
