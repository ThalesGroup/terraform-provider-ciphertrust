package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/modifiers"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

var (
	azureStackConnectionTypeDescription = `Azure stack connection type

	Options:

		AAD
		ADFS
`
	cloudNameDescription = `Name of the cloud.

	Options:

		AzureCloud
		AzureChinaCloud
		AzureUSGovernment
		AzureStack
`
)

func NewResourceAzureConnection() resource.Resource {
	return &resourceAzureConnection{}
}

type resourceAzureConnection struct {
	client *common.Client
}

func (r *resourceAzureConnection) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_connection"
}

// Schema defines the schema for the resource.
func (r *resourceAzureConnection) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The APIs in this section deal with connections to the Azure cloud. The following operations can be performed:\n* Create/Delete/Get/Update an Azure connection.\n* List all Azure connections.\n* Test an existing Azure connection.\n*Test a connection that hasn't been created yet by passing in the connection parameters.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"client_id": schema.StringAttribute{
				Computed:    true,
				Optional:    true,
				Description: "Unique Identifier (client ID) for the Azure application.",
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "(Immutable) Unique connection name.",
				PlanModifiers: []planmodifier.String{modifiers.ImmutableString()},
			},
			"tenant_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Tenant ID of the Azure application.",
			},
			"active_directory_endpoint": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Azure stack active directory authority URL",
			},
			"azure_stack_connection_type": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: azureStackConnectionTypeDescription,
				Validators: []validator.String{
					stringvalidator.OneOf("AAD", "ADFS"),
				},
			},
			"azure_stack_server_cert": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Azure stack server certificate.The certificate should be provided in \\n (newline) format.",
			},
			"cert_duration": schema.Int64Attribute{
				Optional:    true,
				Computed:    true,
				Description: "Duration in days for which the azure certificate is valid, default (730 i.e. 2 Years).",
			},
			"certificate": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "User has the option to upload external certificate for Azure Cloud connection. This option cannot be used with option is_certificate_used and client_secret.User first has to generate a new Certificate Signing Request (CSR) in POST /v1/connectionmgmt/connections/csr. The generated CSR can be signed with any internal or external CA. The Certificate must have an RSA key strength of 2048 or 4096. User can also update the new external certificate in the existing connection. Any unused certificate will automatically deleted in 24 hours.The certificate should be provided in \\n (newline) format.",
			},
			"client_secret": schema.StringAttribute{
				Optional:  true,
				Computed:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
				Description: "Secret key for the Azure application. Required in Azure Stack connection. " +
					"Write-only: CM never returns this field on GET, so its live value cannot be verified " +
					"after apply and out-of-band changes are not detectable by terraform plan. " +
					"Omitting this attribute in a later apply leaves the previously configured secret " +
					"untouched (no diff). Once set, this field cannot be cleared back to empty by explicitly " +
					"setting it to \"\": CM does not support clearing it, and the provider rejects the attempt " +
					"at apply time rather than silently leaving state and CM's live value out of sync. To " +
					"rotate the secret, set a new value.",
			},
			"cloud_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: cloudNameDescription,
				Validators: []validator.String{
					stringvalidator.OneOf("AzureCloud", "AzureChinaCloud", "AzureUSGovernment", "AzureStack"),
				},
			},
			"description": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Description about the connection. Note: once set, this field cannot be cleared back to empty — CM does not honour empty-string PATCH requests for this field.",
				PlanModifiers: []planmodifier.String{
					modifiers.UseStateWhenClearingString(),
				},
			},
			"external_certificate_used": schema.BoolAttribute{
				Computed:    true,
				Description: "true if the certificate associated with the connection is generated externally, false otherwise.",
			},
			"is_certificate_used": schema.BoolAttribute{
				Optional:    true,
				Computed:    true,
				Description: "User has the option to choose the Certificate Authentication method instead of Client Secret for Azure Cloud connection. In order to use the Certificate, set it to true. Once the connection is created, in the response user will get a certificate. By default, the certificate is valid for 2 Years. User can update the certificate in the existing connection by setting it to true.",
				PlanModifiers: []planmodifier.Bool{
					boolplanmodifier.UseStateForUnknown(),
				},
			},
			"key_vault_dns_suffix": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Azure stack key vault dns suffix",
			},
			"labels": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: labelsDescription,
				PlanModifiers: []planmodifier.Map{
					modifiers.UseStateWhenClearingMap(),
				},
			},
			"management_url": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Azure stack management URL",
			},
			"meta": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: "Optional end-user or service data stored with the connection. Note: once set, this field cannot be cleared back to empty — CM does not honour empty-object PATCH requests for this field.",
				PlanModifiers: []planmodifier.Map{
					modifiers.UseStateWhenClearingMap(),
				},
			},
			"products": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Computed:    true,
				Description: productsDescription,
				Validators: []validator.List{
					listvalidator.ValueStringsAre(
						stringvalidator.OneOf("cckm", "ddc", "cte", "data discovery", "backup/restore", "logger", "hsm_anchored_domain", "csm"),
					),
				},
			},
			"resource_manager_url": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Azure stack resource manager URL.",
			},
			"vault_resource_url": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Azure stack vault service resource URL.",
			},
			"certificate_thumbprint": schema.StringAttribute{
				Computed:    true,
				Description: "Thumbprint of the certificate associated with the connection, when certificate-based authentication is used.",
			},
			//common response parameters (read-only)
			"uri": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"account": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			// updated_at intentionally has no UseStateForUnknown(): CM sets a fresh
			// timestamp on every successful update, so showing it as "known after
			// apply" is accurate, not spurious drift.
			"updated_at": schema.StringAttribute{Computed: true},
			"service": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"category": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"resource_url": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_connection_ok": schema.BoolAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"last_connection_error": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_connection_at": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// Create creates the resource and sets the initial Terraform state.
func (r *resourceAzureConnection) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Create]["+id+"]")

	// Retrieve values from plan
	var plan AzureConnectionTFSDK
	var payload AzureConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if plan.ClientID.ValueString() != "" && plan.ClientID.ValueString() != types.StringNull().ValueString() {
		payload.ClientID = plan.ClientID.ValueString()
	}

	if plan.Name.ValueString() != "" && plan.Name.ValueString() != types.StringNull().ValueString() {
		payload.Name = plan.Name.ValueString()
	}

	if plan.TenantID.ValueString() != "" && plan.TenantID.ValueString() != types.StringNull().ValueString() {
		payload.TenantID = plan.TenantID.ValueString()
	}

	if plan.ActiveDirectoryEndpoint.ValueString() != "" && plan.ActiveDirectoryEndpoint.ValueString() != types.StringNull().ValueString() {
		payload.ActiveDirectoryEndpoint = plan.ActiveDirectoryEndpoint.ValueString()
	}

	if plan.AzureStackConnectionType.ValueString() != "" && plan.AzureStackConnectionType.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackConnectionType = plan.AzureStackConnectionType.ValueString()
	}

	if plan.AzureStackServerCert.ValueString() != "" && plan.AzureStackServerCert.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackServerCert = plan.AzureStackServerCert.ValueString()
	}

	if plan.CertDuration.ValueInt64() != types.Int64Null().ValueInt64() {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}

	if plan.Certificate.ValueString() != "" && plan.Certificate.ValueString() != types.StringNull().ValueString() {
		payload.Certificate = plan.Certificate.ValueString()
	}

	if plan.ClientSecret.ValueString() != "" && plan.ClientSecret.ValueString() != types.StringNull().ValueString() {
		payload.ClientSecret = plan.ClientSecret.ValueString()
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if !plan.IsCertificateUsed.IsNull() && !plan.IsCertificateUsed.IsUnknown() {
		payload.IsCertificateUsed = plan.IsCertificateUsed.ValueBool()
	}

	if plan.KeyVaultDNSSuffix.ValueString() != "" && plan.KeyVaultDNSSuffix.ValueString() != types.StringNull().ValueString() {
		payload.KeyVaultDNSSuffix = plan.KeyVaultDNSSuffix.ValueString()
	}

	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		azureLabelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			azureLabelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = azureLabelsPayload
	}

	if plan.ManagementURL.ValueString() != "" && plan.ManagementURL.ValueString() != types.StringNull().ValueString() {
		payload.ManagementURL = plan.ManagementURL.ValueString()
	}

	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		azureMetadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			azureMetadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = azureMetadataPayload
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var azureProducts []string
		diags = plan.Products.ElementsAs(ctx, &azureProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			tflog.Debug(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = azureProducts
	}

	if plan.ResourceManagerURL.ValueString() != "" && plan.ResourceManagerURL.ValueString() != types.StringNull().ValueString() {
		payload.ResourceManagerURL = plan.ResourceManagerURL.ValueString()
	}

	if plan.VaultResourceURL.ValueString() != "" && plan.VaultResourceURL.ValueString() != types.StringNull().ValueString() {
		payload.VaultResourceURL = plan.VaultResourceURL.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Azure connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AZURE_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error creating Azure Connection on CipherTrust Manager: ",
			"Could not create azure connection, unexpected error: "+err.Error(),
		)
		return
	}

	// Re-fetch the resource via GET so that state reflects what CM actually stored,
	// rather than relying on the POST response body which may omit fields like labels.
	newID := gjson.Get(response, "id").String()
	tflog.Debug(ctx, "[resource_azure_connection.go -> Create] fetching created resource id="+newID)
	response, err = r.client.GetById(ctx, id, newID, common.URL_AZURE_CONNECTION)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Create]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Azure Connection after creation: ",
			"Could not read back azure connection id: "+newID+", unexpected error: "+err.Error(),
		)
		return
	}

	tflog.Debug(ctx, "[resource_azure_connection.go -> Create Output]["+response+"]")
	getAzureParamsFromResponse(response, &resp.Diagnostics, &plan)

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Create]["+id+"]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceAzureConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AzureConnectionTFSDK
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Read]["+id+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AZURE_CONNECTION)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			tflog.Debug(ctx, "[resource_azure_connection.go -> Read] connection not found, removing from state ["+id+"]")
			resp.State.RemoveResource(ctx)
			return
		}
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Error reading Azure Connection on CipherTrust Manager: ",
			"Could not read azure connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Debug(ctx, "resource_azure_connection.go: response :"+response)

	getAzureParamsFromResponse(response, &resp.Diagnostics, &state)
	// required parameters are fetched separately
	state.Name = types.StringValue(gjson.Get(response, "name").String())

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Read]["+id+"]")
	return
}

func (r *resourceAzureConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Update]["+id+"]")
	var plan AzureConnectionTFSDK
	var state AzureConnectionTFSDK
	var payload AzureConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags = req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if clientSecretClearBlocked(state, plan) {
		resp.Diagnostics.AddError(
			"client_secret cannot be cleared",
			"CipherTrust Manager does not support clearing client_secret once it has been set: the "+
				"previously configured secret would remain active on CM even though Terraform state "+
				"would show it as cleared. To rotate the secret, set client_secret to a new value. "+
				"To remove client_secret-based auth entirely, destroy and recreate the connection.",
		)
		return
	}

	if plan.ActiveDirectoryEndpoint.ValueString() != "" && plan.ActiveDirectoryEndpoint.ValueString() != types.StringNull().ValueString() {
		payload.ActiveDirectoryEndpoint = plan.ActiveDirectoryEndpoint.ValueString()
	}

	if plan.AzureStackConnectionType.ValueString() != "" && plan.AzureStackConnectionType.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackConnectionType = plan.AzureStackConnectionType.ValueString()
	}

	if plan.AzureStackServerCert.ValueString() != "" && plan.AzureStackServerCert.ValueString() != types.StringNull().ValueString() {
		payload.AzureStackServerCert = plan.AzureStackServerCert.ValueString()
	}

	if plan.CertDuration.ValueInt64() != 0 {
		payload.CertDuration = plan.CertDuration.ValueInt64()
	}

	if plan.Certificate.ValueString() != "" && plan.Certificate.ValueString() != types.StringNull().ValueString() {
		payload.Certificate = plan.Certificate.ValueString()
	}

	if plan.ClientID.ValueString() != "" && plan.ClientID.ValueString() != types.StringNull().ValueString() {
		payload.ClientID = plan.ClientID.ValueString()
	}

	if plan.ClientSecret.ValueString() != "" && plan.ClientSecret.ValueString() != types.StringNull().ValueString() {
		payload.ClientSecret = plan.ClientSecret.ValueString()
	}

	if plan.CloudName.ValueString() != "" && plan.CloudName.ValueString() != types.StringNull().ValueString() {
		payload.CloudName = plan.CloudName.ValueString()
	}

	if plan.Description.ValueString() != "" && plan.Description.ValueString() != types.StringNull().ValueString() {
		payload.Description = plan.Description.ValueString()
	}

	if !plan.IsCertificateUsed.IsNull() && !plan.IsCertificateUsed.IsUnknown() {
		payload.IsCertificateUsed = plan.IsCertificateUsed.ValueBool()
	}

	if plan.ExternalCertificateUsed.ValueBool() != types.BoolNull().ValueBool() {
		payload.ExternalCertificateUsed = plan.ExternalCertificateUsed.ValueBool()
	}

	if plan.KeyVaultDNSSuffix.ValueString() != "" && plan.KeyVaultDNSSuffix.ValueString() != types.StringNull().ValueString() {
		payload.KeyVaultDNSSuffix = plan.KeyVaultDNSSuffix.ValueString()
	}

	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		azureLabelsPayload := make(map[string]interface{})
		for k, v := range plan.Labels.Elements() {
			azureLabelsPayload[k] = v.(types.String).ValueString()
		}
		payload.Labels = azureLabelsPayload
	}

	if plan.ManagementURL.ValueString() != "" && plan.ManagementURL.ValueString() != types.StringNull().ValueString() {
		payload.ManagementURL = plan.ManagementURL.ValueString()
	}

	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		azureMetadataPayload := make(map[string]interface{})
		for k, v := range plan.Meta.Elements() {
			azureMetadataPayload[k] = v.(types.String).ValueString()
		}
		payload.Meta = azureMetadataPayload
	}

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var azureProducts []string
		diags = plan.Products.ElementsAs(ctx, &azureProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			tflog.Debug(ctx, fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
			return
		}
		payload.Products = azureProducts
	}

	if plan.ResourceManagerURL.ValueString() != "" && plan.ResourceManagerURL.ValueString() != types.StringNull().ValueString() {
		payload.ResourceManagerURL = plan.ResourceManagerURL.ValueString()
	}

	if plan.TenantID.ValueString() != "" && plan.TenantID.ValueString() != types.StringNull().ValueString() {
		payload.TenantID = plan.TenantID.ValueString()
	}
	if plan.VaultResourceURL.ValueString() != "" && plan.VaultResourceURL.ValueString() != types.StringNull().ValueString() {
		payload.VaultResourceURL = plan.VaultResourceURL.ValueString()
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Update]["+id+"]")
		resp.Diagnostics.AddError(
			"Invalid data input: Azure connection update",
			err.Error(),
		)
		return
	}

	_, err = r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_AZURE_CONNECTION, payloadJSON)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error updating Azure Connection on CipherTrust Manager: ",
			"Could not update azure connection, unexpected error: "+err.Error(),
		)
		return
	}

	// Re-fetch the resource via GET so that state reflects what CM actually stored,
	// rather than relying on the PATCH response body which may omit fields like labels.
	tflog.Debug(ctx, "[resource_azure_connection.go -> Update] fetching updated resource id="+plan.ID.ValueString())
	response, err := r.client.GetById(ctx, id, plan.ID.ValueString(), common.URL_AZURE_CONNECTION)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [resource_azure_connection.go -> Update]["+plan.ID.ValueString()+"]")
		resp.Diagnostics.AddError(
			"Error reading Azure Connection after update: ",
			"Could not read back azure connection id: "+plan.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Debug(ctx, fmt.Sprintf("Response: %s", response))
	getAzureParamsFromResponse(response, &resp.Diagnostics, &plan)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceAzureConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AzureConnectionTFSDK
	tflog.Trace(ctx, common.MSG_METHOD_START+"[resource_azure_connection.go -> Delete]["+state.ID.ValueString()+"]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AZURE_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			tflog.Debug(ctx, "Azure connection already deleted out-of-band on CM")
			return
		}
		tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Azure Connection",
			"Could not delete azure connection, unexpected error: "+err.Error(),
		)
		return
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[resource_azure_connection.go -> Delete]["+state.ID.ValueString()+"]["+output+"]")
}

func (d *resourceAzureConnection) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// clientSecretClearBlocked reports whether the plan is attempting to clear a
// previously-set client_secret. CM never returns this write-only field on GET, so the
// provider cannot verify whether a clear PATCH actually took effect. Rather than writing
// an unverifiable null into state (per TFIN-364-class bug), Update rejects the attempt
// outright.
func clientSecretClearBlocked(state, plan AzureConnectionTFSDK) bool {
	hadSecret := !state.ClientSecret.IsNull() && state.ClientSecret.ValueString() != ""
	clearing := plan.ClientSecret.IsNull() || plan.ClientSecret.ValueString() == ""
	return hadSecret && clearing
}

func getAzureParamsFromResponse(response string, diag *diag.Diagnostics, data *AzureConnectionTFSDK) {
	// Common parameters for all connections
	data.ID = types.StringValue(gjson.Get(response, "id").String())
	data.URI = types.StringValue(gjson.Get(response, "uri").String())
	data.Account = types.StringValue(gjson.Get(response, "account").String())
	data.UpdatedAt = types.StringValue(gjson.Get(response, "updatedAt").String())
	data.CreatedAt = types.StringValue(gjson.Get(response, "createdAt").String())
	data.Category = types.StringValue(gjson.Get(response, "category").String())
	data.Service = types.StringValue(gjson.Get(response, "service").String())
	data.ResourceURL = types.StringValue(gjson.Get(response, "resource_url").String())
	data.LastConnectionOK = types.BoolValue(gjson.Get(response, "last_connection_ok").Bool())
	data.LastConnectionError = types.StringValue(gjson.Get(response, "last_connection_error").String())
	data.LastConnectionAt = types.StringValue(gjson.Get(response, "last_connection_at").String())

	// Parameters for azure connection
	data.Certificate = types.StringValue(gjson.Get(response, "certificate").String())
	data.CertificateThumbprint = types.StringValue(gjson.Get(response, "certificate_thumbprint").String())
	data.ExternalCertificateUsed = types.BoolValue(gjson.Get(response, "external_certificate_used").Bool())
	data.IsCertificateUsed = types.BoolValue(gjson.Get(response, "is_certificate_used").Bool())
	data.Description = types.StringValue(gjson.Get(response, "description").String())
	data.TenantID = types.StringValue(gjson.Get(response, "tenant_id").String())
	data.ClientID = types.StringValue(gjson.Get(response, "client_id").String())
	data.CloudName = types.StringValue(gjson.Get(response, "cloud_name").String())
	data.ActiveDirectoryEndpoint = types.StringValue(gjson.Get(response, "active_directory_endpoint").String())
	data.VaultResourceURL = types.StringValue(gjson.Get(response, "vault_resource_url").String())
	data.ResourceManagerURL = types.StringValue(gjson.Get(response, "resource_manager_url").String())
	data.KeyVaultDNSSuffix = types.StringValue(gjson.Get(response, "key_vault_dns_suffix").String())
	data.ManagementURL = types.StringValue(gjson.Get(response, "management_url").String())
	data.AzureStackServerCert = types.StringValue(gjson.Get(response, "azure_stack_server_cert").String())
	data.AzureStackConnectionType = types.StringValue(gjson.Get(response, "azure_stack_connection_type").String())
	data.Labels = common.ParseMap(response, diag, "labels")
	data.Meta = common.ParseMap(response, diag, "meta")
	// Update cert_duration from the CM response.
	// - Non-zero: always use the value CM returned (covers certificate connections and drift detection).
	// - Zero + field is still unknown: CM doesn't use cert_duration for client_secret connections and
	//   returns 0. If the user never configured the field, it arrives here as unknown (Terraform marks
	//   Computed fields unknown during planning). We must resolve it to a known value (null) or
	//   Terraform will error with "provider still indicated an unknown value after apply".
	// - Zero + field already has a known value: the user configured cert_duration (e.g. 730) but CM
	//   returned 0 — preserve the user's planned value to avoid a perpetual drift on every apply.
	if certDuration := gjson.Get(response, "cert_duration").Int(); certDuration != 0 {
		data.CertDuration = types.Int64Value(certDuration)
	} else if data.CertDuration.IsUnknown() {
		data.CertDuration = types.Int64Null()
	}
	data.Products = common.ParseArray(response, "products")
	// client_secret is now Optional+Computed (so omitting it in a later apply preserves the
	// prior state value via UseStateForUnknown instead of being read as an intent to clear).
	// On Create, a connection that never sets client_secret (e.g. certificate-based auth) has
	// no prior state to fall back on, so it arrives here still unknown — resolve it to null or
	// Terraform errors with "provider produced an unknown value after apply". CM never returns
	// this write-only field, so there is nothing to read it back from either way.
	if data.ClientSecret.IsUnknown() {
		data.ClientSecret = types.StringNull()
	}
}
