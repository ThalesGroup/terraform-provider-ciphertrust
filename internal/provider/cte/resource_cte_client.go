package cte

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"

	// "github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_                           resource.Resource              = &resourceCTEClient{}
	_                           resource.ResourceWithConfigure = &resourceCTEClient{}
	CtePasswordGenarationMethod                                = []string{"GENERATE", "MANUAL"}
	CteClientType                                              = []string{"FS", "CTE-U"}

	CTEResourceDescription = `CipherTrust Transparent Encryption (CTE) delivers data-at-rest encryption with centralized key management, privileged user access control, and detailed data access audit logging. This protects data wherever it resides—on-premises, across multiple clouds, and within big data.

	CTE:

	- Encrypts files and raw data
	- Controls which users can decrypt and access that data
	- Controls which processes and executables can decrypt and encrypt that data
	- Generates fine-grained audit trails on those processes, executables, and users`
)

func NewResourceCTEClient() resource.Resource {
	return &resourceCTEClient{}
}

type resourceCTEClient struct {
	client *common.Client
}

func (r *resourceCTEClient) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cte_client"
}

// Schema defines the schema for the resource.
func (r *resourceCTEClient) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: CTEResourceDescription,
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier of a CTE client to be generated on successful creation of Client",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name to uniquely identify the client. This name will be visible on the CipherTrust Manager.",
			},
			"client_locked": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the CTE client is locked. The default value is false. Enable this option to lock the configuration of the CTE Agent on the client. Set to true to lock the configuration, set to false to unlock. Locking the Agent configuration prevents updates to any policies on the client.",
			},
			"client_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Type of CTE Client. The default value is FS. Valid values are CTE-U and FS.",
				Validators: []validator.String{
					stringvalidator.OneOf(CteClientType...),
				},
			},
			"communication_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether communication with the client is enabled. The default value is false. Can be set to true only if registration_allowed is true.",
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Description: "Description to identify the client.",
			},
			"password": schema.StringAttribute{
				Optional:    true,
				Description: "Password for the client. Required when password_creation_method is MANUAL.",
			},
			"password_creation_method": schema.StringAttribute{
				Required:    true,
				Description: "Password creation method for the client. Valid values are MANUAL and GENERATE. The default value is GENERATE.",
				Validators: []validator.String{
					stringvalidator.OneOf(CtePasswordGenarationMethod...),
				},
			},
			"profile_identifier": schema.StringAttribute{
				Optional:    true,
				Description: "Identifier of the Client Profile to be associated with the client. If not provided, the default profile will be linked.",
			},
			"registration_allowed": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether client's registration with the CipherTrust Manager is allowed. The default value is false. Set to true to allow registration.",
			},
			"system_locked": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the system is locked. The default value is false. Enable this option to lock the important operating system files of the client. When enabled, patches to the operating system of the client will fail due to the protection of these files.",
			},
			"client_mfa_enabled": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether MFA is enabled on the client.",
			},
			"del_client": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether to mark the client for deletion from the CipherTrust Manager. The default value is false.",
			},
			"disable_capability": schema.StringAttribute{
				Optional:    true,
				Description: "Client capability to be disabled. Only EKP - Encryption Key Protection can be disabled.",
			},
			"dynamic_parameters": schema.StringAttribute{
				Optional:    true,
				Description: "Array of parameters to be updated after the client is registered. Specify the parameters in the name-value pair JSON format strings. Make sure to specify all the parameters even if you want to update one or more parameters. For example, if there are two parameters in the CTE client list and you want to update the value of \"param1\", then specify the correct value (one from the \"allowed_values\") in the \"current_value\" field, and keep the remaining parameters intact.",
			},
			"enable_domain_sharing": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether domain sharing is enabled for the client.",
			},
			"enabled_capabilities": schema.StringAttribute{
				Optional:    true,
				Description: "Client capabilities to be enabled. Separate values with comma. Valid values are LDT and EKP",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Labels are key/value pairs used to group resources. They are based on Kubernetes Labels, see https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/.",
			},
			"lgcs_access_only": schema.BoolAttribute{
				Optional:    true,
				Description: "Whether the client can be added to an LDT communication group. If lgcs_access_only is set to false, the client can be added to an LDT communication group. Only available on Windows clients.",
			},
			"max_num_cache_log": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum number of logs to cache.",
			},
			"max_space_cache_log": schema.Int64Attribute{
				Optional:    true,
				Description: "Maximum space for the cached logs.",
			},
			"profile_id": schema.StringAttribute{
				Optional:    true,
				Description: "ID of the profile that contains logger, logging, and QOS configuration.",
			},
			"protection_mode": schema.StringAttribute{
				Optional:    true,
				Description: "Update protection mode for windows client. This change is irreversible. The valid value is \"CTE RWP\"",
			},
			"shared_domain_list": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "List of domains in which the client needs to be shared.",
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceCTEClient) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_cte_client.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan CTEClientTFSDK
	var payload CTEClientJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	payload.Name = common.TrimString(plan.Name.ValueString())
	if plan.ClientLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.ClientLocked = plan.ClientLocked.ValueBool()
	}
	if plan.ClientType.ValueString() != "" && plan.ClientType.ValueString() != types.StringNull().ValueString() {
		payload.ClientType = common.TrimString(plan.ClientType.String())
	} else {
		plan.ClientType = types.StringValue("FS")
		payload.ClientType = common.TrimString(plan.ClientType.String())
	}
	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = common.TrimString(plan.Password.String())
	}
	if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
		payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.String())
	}
	if plan.ProfileIdentifier.ValueString() != "" && plan.ProfileIdentifier.ValueString() != types.StringNull().ValueString() {
		payload.ProfileIdentifier = common.TrimString(plan.ProfileIdentifier.String())
	}
	if plan.RegistrationAllowed.ValueBool() != types.BoolNull().ValueBool() {
		payload.RegistrationAllowed = plan.RegistrationAllowed.ValueBool()
	}
	if plan.SystemLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.SystemLocked = plan.SystemLocked.ValueBool()
	}
	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostData(ctx, id, common.URL_CTE_CLIENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client on CipherTrust Manager: ",
			"Could not create CTE Client, unexpected error: "+err.Error(),
		)
		return
	}

	plan.ID = types.StringValue(response)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

// Read refreshes the Terraform state with the latest data.
func (r *resourceCTEClient) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state CTEClientTFSDK
	id := uuid.New().String()

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	_, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_CTE_CLIENT)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading CTE Client on CipherTrust Manager: ",
			"Could not read CTE Client id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client.go -> Read]["+id+"]")
}

// Update updates the resource and sets the updated Terraform state on success.
func (r *resourceCTEClient) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan CTEClientTFSDK
	var payload CTEClientJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ClientLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.ClientLocked = plan.ClientLocked.ValueBool()
	}
	if plan.CommunicationEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.CommunicationEnabled = plan.CommunicationEnabled.ValueBool()
	}
	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = common.TrimString(plan.Description.String())
	}
	if plan.Password.ValueString() != "" && plan.Password.ValueString() != types.StringNull().ValueString() {
		payload.Password = common.TrimString(plan.Password.String())
	}
	if plan.PasswordCreationMethod.ValueString() != "" && plan.PasswordCreationMethod.ValueString() != types.StringNull().ValueString() {
		payload.PasswordCreationMethod = common.TrimString(plan.PasswordCreationMethod.String())
	}
	if plan.RegistrationAllowed.ValueBool() != types.BoolNull().ValueBool() {
		payload.RegistrationAllowed = plan.RegistrationAllowed.ValueBool()
	}
	if plan.SystemLocked.ValueBool() != types.BoolNull().ValueBool() {
		payload.SystemLocked = plan.SystemLocked.ValueBool()
	}
	if plan.ClientMFAEnabled.ValueBool() != types.BoolNull().ValueBool() {
		payload.ClientMFAEnabled = plan.ClientMFAEnabled.ValueBool()
	}
	if plan.DelClient.ValueBool() != types.BoolNull().ValueBool() {
		payload.DelClient = plan.DelClient.ValueBool()
	}
	if plan.DisableCapability.ValueString() != "" && plan.DisableCapability.ValueString() != types.StringNull().ValueString() {
		payload.DisableCapability = common.TrimString(plan.DisableCapability.String())
	}
	if plan.DynamicParameters.ValueString() != "" && plan.DynamicParameters.ValueString() != types.StringNull().ValueString() {
		payload.DynamicParameters = common.TrimString(plan.DynamicParameters.String())
	}
	if plan.EnableDomainSharing.ValueBool() != types.BoolNull().ValueBool() {
		payload.EnableDomainSharing = plan.EnableDomainSharing.ValueBool()
	}
	if plan.EnabledCapabilities.ValueString() != "" && plan.EnabledCapabilities.ValueString() != types.StringNull().ValueString() {
		payload.EnabledCapabilities = common.TrimString(plan.EnabledCapabilities.String())
	}
	if plan.LGCSAccessOnly.ValueBool() != types.BoolNull().ValueBool() {
		payload.LGCSAccessOnly = plan.LGCSAccessOnly.ValueBool()
	}
	if plan.MaxNumCacheLog.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxNumCacheLog = plan.MaxNumCacheLog.ValueInt64()
	}
	if plan.MaxSpaceCacheLog.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.MaxSpaceCacheLog = plan.MaxSpaceCacheLog.ValueInt64()
	}
	if plan.ProfileID.ValueString() != "" && plan.ProfileID.ValueString() != types.StringNull().ValueString() {
		payload.ProfileID = common.TrimString(plan.ProfileID.String())
	}
	if plan.ProtectionMode.ValueString() != "" && plan.ProtectionMode.ValueString() != types.StringNull().ValueString() {
		payload.ProtectionMode = common.TrimString(plan.ProtectionMode.String())
	}
	if plan.SharedDomainList != nil {
		for _, domain := range plan.SharedDomainList {
			payload.SharedDomainList = append(payload.SharedDomainList, domain.ValueString())
		}
	}
	// Add labels to payload
	labelsPayload := make(map[string]interface{})
	for k, v := range plan.Labels.Elements() {
		labelsPayload[k] = v.(types.String).ValueString()
	}
	payload.Labels = labelsPayload

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Update",
			err.Error(),
		)
		return
	}

	response, err := r.client.UpdateData(ctx, plan.ID.ValueString(), common.URL_CTE_CLIENT, payloadJSON, "id")
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error creating CTE Client on CipherTrust Manager: ",
			"Could not update CTE Client, unexpected error: "+err.Error(),
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
func (r *resourceCTEClient) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state CTEClientTFSDK
	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	DelClient := DelClientJSON{
		DelClient:      true,
		ForceDelClient: true,
	}
	PayloadJSON, err := json.Marshal(DelClient)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_cte_client.go -> Update][]")
		resp.Diagnostics.AddError(
			"Invalid data input: CTE Client Update %s "+state.ID.ValueString(),
			err.Error(),
		)
		return
	}
	// Delete existing order using custom url
	url := fmt.Sprintf("%s/%s/%s/%s", r.client.CipherTrustURL, common.URL_CTE_CLIENT, state.ID.ValueString(), "delete")
	output, err := r.client.DeleteByID(ctx, "PATCH", state.ID.ValueString(), url, PayloadJSON)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_cte_client.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
	if err != nil {
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust CTE Client",
			"Could not delete CTE Client, unexpected error: "+err.Error(),
		)
		return
	}
}

func (d *resourceCTEClient) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
