package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceAzureVaultDetails{}
	_ datasource.DataSourceWithConfigure = &dataSourceAzureVaultDetails{}
)

// NewDataSourceAzureVaultDetails returns a new instance of the
// ciphertrust_azure_vault_details data source.
func NewDataSourceAzureVaultDetails() datasource.DataSource {
	return &dataSourceAzureVaultDetails{}
}

type dataSourceAzureVaultDetails struct {
	client *common.Client
}

func (d *dataSourceAzureVaultDetails) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*common.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *CipherTrust.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)
		return
	}
	d.client = client
}

func (d *dataSourceAzureVaultDetails) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_vault_details"
}

func (d *dataSourceAzureVaultDetails) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve details of all Azure vaults " +
			"available to a CipherTrust Manager Azure connection in a given subscription. " +
			"Results are returned as a map keyed by vault name.",
		Attributes: map[string]schema.Attribute{
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager Azure connection name or ID.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"subscription_id": schema.StringAttribute{
				Required:    true,
				Description: "Azure subscription ID to list vaults from.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`\S`),
						"must contain at least one non-whitespace character",
					),
				},
			},
			"managed_hsms": schema.BoolAttribute{
				Optional:    true,
				Description: "When true, retrieves Azure Managed HSM vaults instead of standard Key Vaults.",
			},
			"vaults": schema.MapNestedAttribute{
				Computed:    true,
				Description: "Map of vault name to vault details for all vaults in the subscription.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Vault name.",
						},
						"azure_vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "Azure resource ID of the vault.",
						},
						"vault_type": schema.StringAttribute{
							Computed:    true,
							Description: "Azure resource type.",
						},
						"location": schema.StringAttribute{
							Computed:    true,
							Description: "Azure region where the vault is located.",
						},
						"tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Azure tags applied to the vault.",
						},
						"vault_properties": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Azure vault properties.",
							Attributes: map[string]schema.Attribute{
								"tenant_id": schema.StringAttribute{
									Computed:    true,
									Description: "Azure Active Directory tenant ID for the vault.",
								},
								"vault_uri": schema.StringAttribute{
									Computed:    true,
									Description: "URI for performing operations on keys and secrets in this vault.",
								},
								"enabled_for_deployment": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether Azure Virtual Machines may retrieve certificates stored as secrets.",
								},
								"enabled_for_disk_encryption": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether Azure Disk Encryption may retrieve secrets from the vault.",
								},
								"enabled_for_template_deployment": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether Azure Resource Manager may retrieve secrets from the vault.",
								},
								"enable_soft_delete": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether soft delete is enabled for the vault.",
								},
								"create_mode": schema.StringAttribute{
									Computed:    true,
									Description: "Vault create mode.",
								},
								"enable_purge_protection": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether protection against purge is enabled.",
								},
								"soft_delete_retention_in_days": schema.Int64Attribute{
									Computed:    true,
									Description: "Soft delete data retention period in days.",
								},
								"enable_rbac_authorization": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether RBAC is used for data action authorization.",
								},
								"sku": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "SKU details for the vault.",
									Attributes: map[string]schema.Attribute{
										"family": schema.StringAttribute{
											Computed:    true,
											Description: "SKU family name.",
										},
										"name": schema.StringAttribute{
											Computed:    true,
											Description: "SKU name.",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// Read retrieves all Azure vault details for the given connection and subscription,
// auto-paginating until all results are collected, and saves them to state as a
// map keyed by vault name.
func (d *dataSourceAzureVaultDetails) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_vault_details.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_vault_details.go -> Read][" + id + "]")

	var state models.AzureVaultDetailsTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := common.URL_AZURE + "/get-vaults"
	if !state.ManagedHSMs.IsNull() && state.ManagedHSMs.ValueBool() {
		endpoint = common.URL_AZURE + "/get-managed-hsms"
	}

	payload := models.AzureVaultInputJSON{
		Connection:     state.ConnectionID.ValueString(),
		SubscriptionID: state.SubscriptionID.ValueString(),
		Limit:          1000,
	}

	var allVaults []models.AzureVaultDataJSON
	for {
		page := d.fetchPage(ctx, id, endpoint, payload, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		if page == nil {
			break
		}
		allVaults = append(allVaults, page.Vaults...)
		if page.NextLink == nil || *page.NextLink == "" {
			break
		}
		nl := *page.NextLink
		payload.NextLink = &nl
	}

	vaultMap := make(map[string]models.AzureVaultDetailTFSDK, len(allVaults))
	for _, v := range allVaults {
		var tags types.Map
		if len(v.Tags) > 0 {
			tv, d := types.MapValueFrom(ctx, types.StringType, v.Tags)
			resp.Diagnostics.Append(d...)
			if resp.Diagnostics.HasError() {
				return
			}
			tags = tv
		} else {
			tags = types.MapNull(types.StringType)
		}

		entry := models.AzureVaultDetailTFSDK{
			Name:         types.StringValue(v.Name),
			AzureVaultID: types.StringValue(v.AzureVaultID),
			VaultType:    types.StringValue(v.Type),
			Location:     types.StringValue(v.Location),
			Tags:         tags,
			VaultProperties: models.AzureVaultPropertiesTFSDK{
				TenantID: types.StringValue(v.Properties.TenantID),
				Sku: models.AzureSkuTFSDK{
					Family: types.StringValue(v.Properties.Sku.Family),
					Name:   types.StringValue(v.Properties.Sku.Name),
				},
				VaultURI:                     types.StringValue(v.Properties.VaultURI),
				EnabledForDeployment:         types.BoolValue(v.Properties.EnabledForDeployment),
				EnabledForDiskEncryption:     types.BoolValue(v.Properties.EnabledForDiskEncryption),
				EnabledForTemplateDeployment: types.BoolValue(v.Properties.EnabledForTemplateDeployment),
				EnableSoftDelete:             types.BoolValue(v.Properties.EnableSoftDelete),
				CreateMode:                   types.StringValue(v.Properties.CreateMode),
				EnablePurgeProtection:        types.BoolValue(v.Properties.EnablePurgeProtection),
				SoftDeleteRetentionInDays:    types.Int64Value(int64(v.Properties.SoftDeleteRetentionInDays)),
				EnableRbacAuthorization:      types.BoolValue(v.Properties.EnableRbacAuthorization),
			},
		}
		vaultMap[v.Name] = entry
	}
	state.Vaults = vaultMap

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// fetchPage marshals payload into JSON, calls the given CM Azure vault endpoint,
// and unmarshals the response. Returns nil and appends an error on any failure.
func (d *dataSourceAzureVaultDetails) fetchPage(ctx context.Context, id string, endpoint string, payload models.AzureVaultInputJSON, diags *diag.Diagnostics) *models.AzureVaultOutputJSON {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading Azure vault details, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	response, err := d.client.PostDataV2(ctx, id, endpoint, payloadJSON)
	if err != nil {
		msg := "Error reading Azure vault details."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	var output models.AzureVaultOutputJSON
	err = json.Unmarshal([]byte(response), &output)
	if err != nil {
		msg := "Error reading Azure vault details, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection": payload.Connection})
		d.client.Log.Error(details)
		diags.AddError(details, "")
		return nil
	}
	return &output
}
