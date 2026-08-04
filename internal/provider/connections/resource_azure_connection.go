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

var (
	_ resource.Resource                   = &resourceAzureConnection{}
	_ resource.ResourceWithConfigure      = &resourceAzureConnection{}
	_ resource.ResourceWithValidateConfig = &resourceAzureConnection{}
)

func NewResourceAzureConnection() resource.Resource {
	return &resourceAzureConnection{}
}

// ValidateConfig enforces cross-field constraints that cannot be expressed with
// per-attribute validators (TFIN-564).
func (r *resourceAzureConnection) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config AzureConnectionTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// azure_stack_server_cert is required by CM when cloud_name = "AzureStack".
	// CM returns an unhelpful message-less 422 without it — catch this at plan time.
	if config.CloudName.ValueString() == "AzureStack" &&
		(config.AzureStackServerCert.IsNull() || config.AzureStackServerCert.ValueString() == "") {
		resp.Diagnostics.AddError(
			"azure_stack_server_cert required for AzureStack",
			"CipherTrust Manager requires azure_stack_server_cert when cloud_name is \"AzureStack\". "+
				"Set azure_stack_server_cert to a valid PEM certificate.",
		)
	}
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
				Sensitive: true,
				WriteOnly: true,
				Description: "Secret key for the Azure application. Required in Azure Stack connection. " +
					"Write-only: never stored in Terraform state or plan artifacts (requires Terraform 1.11+). " +
					"CM never returns this field on GET, so Terraform cannot detect out-of-band rotation on its " +
					"own; to resend a rotated secret, change `client_secret` and bump `client_secret_version` in " +
					"the same apply. Once set, this field cannot be cleared back to empty by explicitly setting " +
					"it to \"\": CM does not support clearing it, and the provider rejects the attempt at apply " +
					"time rather than silently leaving state and CM's live value out of sync.",
			},
			"client_secret_version": schema.Int64Attribute{
				Optional: true,
				Description: "Arbitrary version number stored in state and used to trigger re-sending " +
					"`client_secret` to CipherTrust Manager. Since `client_secret` is write-only, Terraform " +
					"cannot detect a change in its value on its own; increment this on every apply where you " +
					"want the current `client_secret` value re-sent.",
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
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_azure_connection.go -> Create][" + id + "]")

	// Retrieve values from plan
	var plan AzureConnectionTFSDK
	var payload AzureConnectionJSON

	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// client_secret is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Create() ever runs, so plan.ClientSecret is always
	// null here. req.Config is populated fresh from the HCL configuration on every RPC
	// (not derived from the nullified plan), so it reliably carries the actual value.
	var config AzureConnectionTFSDK
	diags = req.Config.Get(ctx, &config)
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

	if v := config.ClientSecret.ValueString(); v != "" {
		payload.ClientSecret = v
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
			r.client.Log.Debug(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_azure_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Azure connection Creation",
			err.Error(),
		)
		return
	}

	response, err := r.client.PostDataV2(ctx, id, common.URL_AZURE_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_azure_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error creating Azure Connection on CipherTrust Manager: ",
			"Could not create azure connection, unexpected error: "+err.Error(),
		)
		return
	}

	// Re-fetch the resource via GET so that state reflects what CM actually stored,
	// rather than relying on the POST response body which may omit fields like labels.
	newID := gjson.Get(response, "id").String()
	r.client.Log.Debug("[resource_azure_connection.go -> Create] fetching created resource id=" + newID)
	response, err = r.client.GetById(ctx, id, newID, common.URL_AZURE_CONNECTION)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_azure_connection.go -> Create][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading Azure Connection after creation: ",
			"Could not read back azure connection id: "+newID+", unexpected error: "+err.Error(),
		)
		return
	}

	r.client.Log.Debug("[resource_azure_connection.go -> Create Output][" + response + "]")
	getAzureParamsFromResponse(response, &resp.Diagnostics, &plan)

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_azure_connection.go -> Create][" + id + "]")
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceAzureConnection) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state AzureConnectionTFSDK
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_azure_connection.go -> Read][" + id + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	response, err := r.client.GetById(ctx, id, state.ID.ValueString(), common.URL_AZURE_CONNECTION)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			resp.Diagnostics.AddError(
				fmt.Sprintf(common.NotFoundReadErrorSummaryFmt, "Azure Connection"),
				fmt.Sprintf(common.NotFoundReadErrorDetailFmt, "Azure Connection", state.ID.ValueString()),
			)
			return
		}
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_azure_connection.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Error reading Azure Connection on CipherTrust Manager: ",
			"Could not read azure connection id : ,"+state.ID.ValueString()+"unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Debug("resource_azure_connection.go: response :" + response)

	getAzureParamsFromResponse(response, &resp.Diagnostics, &state)
	// required parameters are fetched separately
	state.Name = types.StringValue(gjson.Get(response, "name").String())

	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_azure_connection.go -> Read][" + id + "]")
	return
}

func (r *resourceAzureConnection) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	id := uuid.New().String()
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_azure_connection.go -> Update][" + id + "]")
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

	// client_secret is write-only: the framework nulls it out of PlannedState during
	// PlanResourceChange, before Update() ever runs, so plan.ClientSecret is always
	// null here. req.Config is populated fresh from the HCL configuration on every RPC
	// (not derived from the nullified plan), so it reliably carries the actual value.
	var config AzureConnectionTFSDK
	diags = req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if clientSecretClearBlocked(state, plan, config.ClientSecret) {
		resp.Diagnostics.AddError(
			"client_secret cannot be cleared",
			"CipherTrust Manager does not support clearing client_secret once it has been set: the "+
				"previously configured secret would remain active on CM even though Terraform state "+
				"would show it as cleared. To rotate the secret, set client_secret to a new value and "+
				"bump client_secret_version. To remove client_secret-based auth entirely, destroy and "+
				"recreate the connection.",
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

	// client_secret is write-only (never stored in state), so its own value can never be
	// diffed against a prior value — client_secret_version is the explicit, state-tracked
	// signal that the caller wants the current client_secret value re-sent to CM.
	if !plan.ClientSecretVersion.Equal(state.ClientSecretVersion) {
		if v := config.ClientSecret.ValueString(); v != "" {
			payload.ClientSecret = v
		}
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

	// labels / meta: CM's PATCH merges rather than replaces. ApplyNullDeletes sends
	// null for keys present in prior state but absent from the new plan, so CM removes
	// them — matching Terraform's declarative "replace" semantics (TFIN-567).
	azureLabelsPayload := make(map[string]interface{})
	if !plan.Labels.IsNull() && !plan.Labels.IsUnknown() {
		for k, v := range plan.Labels.Elements() {
			azureLabelsPayload[k] = v.(types.String).ValueString()
		}
	}
	ApplyNullDeletes(azureLabelsPayload, state.Labels.Elements())
	payload.Labels = azureLabelsPayload

	if plan.ManagementURL.ValueString() != "" && plan.ManagementURL.ValueString() != types.StringNull().ValueString() {
		payload.ManagementURL = plan.ManagementURL.ValueString()
	}

	azureMetadataPayload := make(map[string]interface{})
	if !plan.Meta.IsNull() && !plan.Meta.IsUnknown() {
		for k, v := range plan.Meta.Elements() {
			azureMetadataPayload[k] = v.(types.String).ValueString()
		}
	}
	ApplyNullDeletes(azureMetadataPayload, state.Meta.Elements())
	payload.Meta = azureMetadataPayload

	if !plan.Products.IsNull() && !plan.Products.IsUnknown() {
		var azureProducts []string
		diags = plan.Products.ElementsAs(ctx, &azureProducts, false)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			r.client.Log.Debug(fmt.Sprintf("Error converting products: %v", resp.Diagnostics.Errors()))
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
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_azure_connection.go -> Update][" + id + "]")
		resp.Diagnostics.AddError(
			"Invalid data input: Azure connection update",
			err.Error(),
		)
		return
	}

	_, err = r.client.UpdateDataV2(ctx, plan.ID.ValueString(), common.URL_AZURE_CONNECTION, payloadJSON)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_azure_connection.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error updating Azure Connection on CipherTrust Manager: ",
			"Could not update azure connection, unexpected error: "+err.Error(),
		)
		return
	}

	// Re-fetch the resource via GET so that state reflects what CM actually stored,
	// rather than relying on the PATCH response body which may omit fields like labels.
	r.client.Log.Debug("[resource_azure_connection.go -> Update] fetching updated resource id=" + plan.ID.ValueString())
	response, err := r.client.GetById(ctx, id, plan.ID.ValueString(), common.URL_AZURE_CONNECTION)
	if err != nil {
		r.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [resource_azure_connection.go -> Update][" + plan.ID.ValueString() + "]")
		resp.Diagnostics.AddError(
			"Error reading Azure Connection after update: ",
			"Could not read back azure connection id: "+plan.ID.ValueString()+", unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Debug(fmt.Sprintf("Response: %s", response))
	getAzureParamsFromResponse(response, &resp.Diagnostics, &plan)

	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *resourceAzureConnection) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state AzureConnectionTFSDK
	r.client.Log.Trace(common.MSG_METHOD_START + "[resource_azure_connection.go -> Delete][" + state.ID.ValueString() + "]")

	diags := req.State.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	url := fmt.Sprintf("%s/%s/%s", r.client.CipherTrustURL, common.URL_AZURE_CONNECTION, state.ID.ValueString())
	output, err := r.client.DeleteByID(ctx, "DELETE", state.ID.ValueString(), url, nil)
	if err != nil {
		if strings.Contains(err.Error(), "status: 404") {
			r.client.Log.Debug("Azure connection already deleted out-of-band on CM")
			resp.Diagnostics.AddWarning(
				common.NotFoundDeleteWarningSummary,
				common.NotFoundDeleteWarningDetail,
			)
			return
		}
		r.client.Log.Trace(common.MSG_METHOD_END + "[resource_azure_connection.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
		resp.Diagnostics.AddError(
			"Error Deleting CipherTrust Azure Connection",
			"Could not delete azure connection, unexpected error: "+err.Error(),
		)
		return
	}
	r.client.Log.Trace(common.MSG_METHOD_END + "[resource_azure_connection.go -> Delete][" + state.ID.ValueString() + "][" + output + "]")
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

// clientSecretClearBlocked reports whether the caller is attempting to clear a
// previously-set client_secret. client_secret is write-only, so neither plan nor state
// ever holds its value directly — client_secret_version being previously set is the
// signal that a secret exists, and a version bump with no accompanying value in config
// is the signal that the caller intends to clear it. CM never returns this write-only
// field on GET, so the provider cannot verify whether a clear PATCH actually took
// effect. Rather than writing an unverifiable null into state, Update rejects the
// attempt outright.
func clientSecretClearBlocked(state, plan AzureConnectionTFSDK, configSecret types.String) bool {
	hadSecret := !state.ClientSecretVersion.IsNull()
	versionBumped := !plan.ClientSecretVersion.Equal(state.ClientSecretVersion)
	clearing := versionBumped && (configSecret.IsNull() || configSecret.ValueString() == "")
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
	// external_certificate_used: Computed-only — no user config to preserve.
	// Use the CM value when present; otherwise default to false.
	if res := gjson.Get(response, "external_certificate_used"); res.Exists() {
		data.ExternalCertificateUsed = types.BoolValue(res.Bool())
	} else {
		data.ExternalCertificateUsed = types.BoolValue(false)
	}
	// is_certificate_used: Optional+Computed. When CM omits the field from its
	// response (documented for certificate-auth connections, TFIN-562), the only
	// case worth preserving is when the user explicitly configured true — that is
	// the signal that this is a certificate-based connection. In every other case
	// (unknown, null, or false) resolve to false so the Computed attribute is always
	// a known value after apply.
	if res := gjson.Get(response, "is_certificate_used"); res.Exists() {
		data.IsCertificateUsed = types.BoolValue(res.Bool())
	} else if !data.IsCertificateUsed.IsNull() && !data.IsCertificateUsed.IsUnknown() && data.IsCertificateUsed.ValueBool() {
		// User explicitly set is_certificate_used=true — CM omits it from the
		// response for certificate-based connections. Preserve the configured value.
	} else {
		data.IsCertificateUsed = types.BoolValue(false)
	}
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
	// client_secret is write-only — the framework nulls it from outgoing state/plan
	// artifacts automatically, but null it explicitly too for clarity.
	data.ClientSecret = types.StringNull()
}
