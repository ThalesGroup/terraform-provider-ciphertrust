package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const azureCertificateListFiltersTable = "\n\n> **Note:** Although some filters represent integers or booleans, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"-1\"` rather than `-1`.\n\n" +
	"| filter               | type    | description |\n" +
	"|----------------------|---------|-------------|\n" +
	"| skip                 | integer | Index of the first result to return (default: 0). |\n" +
	"| limit                | integer | Maximum number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort                 | string  | Fields to sort by. Prefix with `-` for descending order (for example, `-createdAt`). |\n" +
	"| id                   | string  | Filter by CipherTrust Manager resource ID. |\n" +
	"| key_vault            | string  | Filter by key vault name. |\n" +
	"| key_vault_id         | string  | Filter by CipherTrust Manager vault resource ID. |\n" +
	"| cert_name            | string  | Filter by Azure certificate name. |\n" +
	"| cloud_name           | string  | Filter by cloud name (for example, `AzureCloud`). |\n" +
	"| region               | string  | Filter by region. |\n" +
	"| curve                | string  | Filter by EC curve (for example, `P-256`). The value is not case-sensitive. |\n" +
	"| status               | string  | Filter by certificate status. |\n" +
	"| backup               | string  | Filter by backup. |\n" +
	"| enabled              | boolean | Filter by the enabled attribute. |\n" +
	"| deleted_in_azure     | boolean | Filter by whether the certificate has been deleted in Azure. |\n" +
	"| soft_deleted_in_azure | boolean | Filter by whether the certificate has been soft-deleted in Azure. |\n" +
	"| algorithm            | string  | Filter by algorithm type (for example, `RSA` or `EC`). The value is not case-sensitive. |\n" +
	"| cid                  | string  | Filter by Azure certificate identifier. |\n" +
	"| kid                  | string  | Filter by Azure key identifier. |\n" +
	"| sid                  | string  | Filter by Azure secret identifier. |\n" +
	"| gone                 | boolean | Filter by gone. |\n" +
	"| version              | string  | Filter by version. Use `\"-1\"` to return only the latest version of each certificate. |\n" +
	"| tags                 | string  | A valid JSON value. Certificates whose tags contain the JSON value are returned. |\n" +
	"| cert_material_origin | string  | Filter by certificate material origin. |\n" +
	"| cert_source          | string  | Filter by certificate source. |"

var (
	_ datasource.DataSource                     = &dataSourceAzureCertificateList{}
	_ datasource.DataSourceWithConfigure        = &dataSourceAzureCertificateList{}
	_ datasource.DataSourceWithConfigValidators = &dataSourceAzureCertificateList{}

	azureCertificateListValidFilterKeys = map[string]struct{}{
		"skip": {}, "limit": {}, "sort": {},
		"id": {}, "key_vault": {}, "key_vault_id": {}, "cert_name": {}, "cloud_name": {},
		"region": {}, "curve": {}, "status": {}, "backup": {}, "enabled": {},
		"deleted_in_azure": {}, "soft_deleted_in_azure": {}, "algorithm": {}, "cid": {}, "kid": {}, "sid": {}, "gone": {},
		"version": {}, "tags": {}, "cert_material_origin": {}, "cert_source": {},
	}
)

// NewDataSourceAzureCertificateList returns a new instance of the ciphertrust_azure_certificate_list data source.
func NewDataSourceAzureCertificateList() datasource.DataSource {
	return &dataSourceAzureCertificateList{}
}

type dataSourceAzureCertificateList struct {
	client *common.Client
}

// ConfigValidators rejects unrecognized filter keys at plan time.
func (d *dataSourceAzureCertificateList) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{azureCertificateListFilterValidator{}}
}

type azureCertificateListFilterValidator struct{}

func (v azureCertificateListFilterValidator) Description(_ context.Context) string {
	return "Validates that all filter keys are supported."
}

func (v azureCertificateListFilterValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v azureCertificateListFilterValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config models.AzureCertificateListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Filters.IsNull() || config.Filters.IsUnknown() {
		return
	}
	valid := make([]string, 0, len(azureCertificateListValidFilterKeys))
	for k := range azureCertificateListValidFilterKeys {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	for k := range config.Filters.Elements() {
		if _, ok := azureCertificateListValidFilterKeys[k]; !ok {
			resp.Diagnostics.AddError(
				"Unrecognized filter key",
				fmt.Sprintf("%q is not a supported filter key. Supported keys are: %s.", k, strings.Join(valid, ", ")),
			)
		}
	}
}

func (d *dataSourceAzureCertificateList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_certificate_list"
}

func (d *dataSourceAzureCertificateList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceAzureCertificateList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of Azure certificates known to CipherTrust Manager. " +
			"Supply a `filters` map to narrow the results. Each certificate version is a separate entry, " +
			"so use the `version` filter with the value `-1` to return only the latest version of each certificate.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters " +
					"for listing Azure certificates." + azureCertificateListFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of certificates matching the given filters.",
			},
			"certificates": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of Azure certificates.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the certificate version.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the certificate in Azure.",
						},
						"vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager resource ID of the vault that contains the certificate.",
						},
						"vault_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the Azure vault that contains the certificate.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "Azure cloud of the vault.",
						},
						"region": schema.StringAttribute{
							Computed:    true,
							Description: "Azure region of the vault.",
						},
						"tenant": schema.StringAttribute{
							Computed:    true,
							Description: "Azure tenant of the vault.",
						},
						"status": schema.StringAttribute{
							Computed:    true,
							Description: "Status of the certificate.",
						},
						"version": schema.StringAttribute{
							Computed:    true,
							Description: "Azure version of the certificate.",
						},
						"version_count": schema.Int64Attribute{
							Computed:    true,
							Description: "Number of versions of the certificate.",
						},
						"deleted": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the certificate is deleted.",
						},
						"gone": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the certificate no longer exists in Azure.",
						},
						"cert_soft_deleted_in_azure": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the certificate is soft-deleted in Azure.",
						},
						"soft_delete_enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether soft delete is enabled on the vault.",
						},
						"cert_material_origin": schema.StringAttribute{
							Computed:    true,
							Description: "Origin of the certificate material.",
						},
						"cert_source": schema.StringAttribute{
							Computed:    true,
							Description: "Source of the certificate.",
						},
						"backup": schema.StringAttribute{
							Computed:    true,
							Description: "Backup of the certificate.",
						},
						"backup_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate was last backed up.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate was created in CipherTrust Manager.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate was last updated in CipherTrust Manager.",
						},
						"synced_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate was last synchronized with Azure.",
						},
						"rotated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate was last rotated.",
						},
						"azure_created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate was created in Azure.",
						},
						"azure_updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate was last updated in Azure.",
						},
						"azure_expire_at": schema.StringAttribute{
							Computed:    true,
							Description: "Time the certificate expires.",
						},
						"cert": schema.StringAttribute{
							Computed:    true,
							Description: "Base64 encoded certificate.",
						},
						"cid": schema.StringAttribute{
							Computed:    true,
							Description: "Azure certificate identifier.",
						},
						"kid": schema.StringAttribute{
							Computed:    true,
							Description: "Azure key identifier.",
						},
						"sid": schema.StringAttribute{
							Computed:    true,
							Description: "Azure secret identifier.",
						},
						"thumbprint": schema.StringAttribute{
							Computed:    true,
							Description: "Thumbprint of the certificate.",
						},
						"recovery_level": schema.StringAttribute{
							Computed:    true,
							Description: "Soft delete recovery level.",
						},
						"recoverable_days": schema.Int64Attribute{
							Computed:    true,
							Description: "Number of days a deleted certificate can be recovered.",
						},
						"azure_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Azure parameters of the certificate.",
							Attributes: map[string]schema.Attribute{
								"tags": schema.MapAttribute{
									Computed:    true,
									ElementType: types.StringType,
									Description: "Tags of the certificate in Azure.",
								},
								"policy": schema.SingleNestedAttribute{
									Computed:    true,
									Description: "Certificate policy.",
									Attributes: map[string]schema.Attribute{
										"issuer": schema.SingleNestedAttribute{
											Computed:    true,
											Description: "Issuer of the certificate.",
											Attributes: map[string]schema.Attribute{
												"name": schema.StringAttribute{
													Computed:    true,
													Description: "Issuer name.",
												},
												"certificate_type": schema.StringAttribute{
													Computed:    true,
													Description: "Certificate type as supported by the issuer.",
												},
												"cert_transparency": schema.BoolAttribute{
													Computed:    true,
													Description: "Whether the certificate is published to certificate transparency logs.",
												},
											},
										},
										"key_props": schema.SingleNestedAttribute{
											Computed:    true,
											Description: "Key properties of the certificate.",
											Attributes: map[string]schema.Attribute{
												"kty": schema.StringAttribute{
													Computed:    true,
													Description: "Key type.",
												},
												"curve": schema.StringAttribute{
													Computed:    true,
													Description: "Elliptic curve name.",
												},
												"exportable": schema.BoolAttribute{
													Computed:    true,
													Description: "Whether the private key can be exported.",
												},
												"key_size": schema.Int64Attribute{
													Computed:    true,
													Description: "Size of an RSA key.",
												},
												"reuse_key": schema.BoolAttribute{
													Computed:    true,
													Description: "Whether the same key pair is used when the certificate is renewed.",
												},
											},
										},
										"x509_props": schema.SingleNestedAttribute{
											Computed:    true,
											Description: "X509 properties of the certificate.",
											Attributes: map[string]schema.Attribute{
												"subject": schema.StringAttribute{
													Computed:    true,
													Description: "Subject name.",
												},
												"enhanced_key_usage": schema.ListAttribute{
													Computed:    true,
													ElementType: types.StringType,
													Description: "Enhanced key usage object identifiers.",
												},
												"key_usage": schema.ListAttribute{
													Computed:    true,
													ElementType: types.StringType,
													Description: "Allowed key usages.",
												},
												"validity_months": schema.Int64Attribute{
													Computed:    true,
													Description: "Number of months the certificate is valid for.",
												},
												"sans": schema.SingleNestedAttribute{
													Computed:    true,
													Description: "Subject alternative names.",
													Attributes: map[string]schema.Attribute{
														"dns_names": schema.ListAttribute{
															Computed:    true,
															ElementType: types.StringType,
															Description: "Domain names.",
														},
														"emails": schema.ListAttribute{
															Computed:    true,
															ElementType: types.StringType,
															Description: "Email addresses.",
														},
														"user_principal_names": schema.ListAttribute{
															Computed:    true,
															ElementType: types.StringType,
															Description: "User principal names.",
														},
													},
												},
											},
										},
										"attributes": schema.SingleNestedAttribute{
											Computed:    true,
											Description: "Attributes of the certificate.",
											Attributes: map[string]schema.Attribute{
												"enabled": schema.BoolAttribute{
													Computed:    true,
													Description: "Whether the certificate is enabled.",
												},
												"activation_date": schema.StringAttribute{
													Computed:    true,
													Description: "Date of certificate activation in UTC time in RFC3339 format.",
												},
												"expiration_date": schema.StringAttribute{
													Computed:    true,
													Description: "Date of certificate expiry in UTC time in RFC3339 format.",
												},
											},
										},
										"lifetime_actions": schema.ListNestedAttribute{
											Computed:    true,
											Description: "Actions taken at a point in the lifetime of the certificate.",
											NestedObject: schema.NestedAttributeObject{
												Attributes: map[string]schema.Attribute{
													"trigger": schema.SingleNestedAttribute{
														Computed:    true,
														Description: "When the action is taken.",
														Attributes: map[string]schema.Attribute{
															"lifetime_percentage": schema.Int64Attribute{
																Computed:    true,
																Description: "Percentage of the lifetime at which the action is taken.",
															},
															"days_before_expiry": schema.Int64Attribute{
																Computed:    true,
																Description: "Days before expiry at which the action is taken.",
															},
														},
													},
													"action": schema.SingleNestedAttribute{
														Computed:    true,
														Description: "Action to take.",
														Attributes: map[string]schema.Attribute{
															"action_type": schema.StringAttribute{
																Computed:    true,
																Description: "Type of action. For example AutoRenew or EmailContacts.",
															},
														},
													},
												},
											},
										},
										"secret_props": schema.SingleNestedAttribute{
											Computed:    true,
											Description: "Secret properties of the certificate.",
											Attributes: map[string]schema.Attribute{
												"content_type": schema.StringAttribute{
													Computed:    true,
													Description: "Content type of the certificate secret.",
												},
											},
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

// Read lists Azure certificates from the CipherTrust Manager database, optionally
// filtered by the key:value pairs in the filters attribute, and saves the results to state.
func (d *dataSourceAzureCertificateList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_certificate_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_certificate_list.go -> Read][" + id + "]")

	var state models.AzureCertificateListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		if val, ok := v.(types.String); ok {
			if k == "curve" {
				filters.Add("crv", strings.ToUpper(val.ValueString()))
				filters.Add("crv", strings.ToLower(val.ValueString()))
				continue
			}
			// The Terraform filter is named soft_deleted_in_azure, the CCKM query parameter is cert_soft_deleted_in_azure.
			if k == "soft_deleted_in_azure" {
				k = "cert_soft_deleted_in_azure"
			}
			// CCKM stores the algorithm as RSA or rsa (and EC or ec) depending on how the certificate was
			// created, and the filter is case-sensitive. Send the lower and upper case forms of the value
			// given so that certificates match whichever form is stored.
			if k == "algorithm" {
				filters.Add(k, strings.ToLower(val.ValueString()))
				filters.Add(k, strings.ToUpper(val.ValueString()))
				continue
			}
			filters.Add(k, val.ValueString())
		}
	}

	jsonStr, err := d.client.ListWithFilters(ctx, id, azureCertificatesEndpoint, filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_certificate_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Unable to read Azure certificates from CipherTrust Manager", err.Error())
		return
	}

	var page models.AzureCertificateListPageJSON
	if err = json.Unmarshal([]byte(jsonStr), &page); err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_certificate_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Unable to read Azure certificates from CipherTrust Manager", err.Error())
		return
	}

	state.Certificates = make([]models.AzureCertificateListEntryTFSDK, 0, len(page.Resources))
	for _, raw := range page.Resources {
		entry, entryErr := azureCertificateListEntryToTFSDK(raw)
		if entryErr != nil {
			d.client.Log.Debug(common.ERR_METHOD_END + entryErr.Error() + " [data_source_azure_certificate_list.go -> Read][" + id + "]")
			resp.Diagnostics.AddError("Unable to read Azure certificates from CipherTrust Manager", entryErr.Error())
			return
		}
		state.Certificates = append(state.Certificates, entry)
	}
	state.Matched = types.Int64Value(page.Total)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// azureCertificateListEntryToTFSDK converts one listed certificate. It reuses azureCertificateSetState
// so the values match the ciphertrust_azure_certificate resource. Absent values are null.
func azureCertificateListEntryToTFSDK(raw json.RawMessage) (models.AzureCertificateListEntryTFSDK, error) {
	cert := AzureCertificateTFSDK{
		Name:        types.StringNull(),
		VaultID:     types.StringNull(),
		AzureParams: types.ObjectNull(azureCertParamsAttrTypes),
	}
	if err := azureCertificateSetState(string(raw), &cert); err != nil {
		return models.AzureCertificateListEntryTFSDK{}, err
	}
	return models.AzureCertificateListEntryTFSDK{
		ID:                     cert.ID,
		Name:                   cert.Name,
		VaultID:                cert.VaultID,
		VaultName:              cert.VaultName,
		CloudName:              cert.CloudName,
		Region:                 cert.Region,
		Tenant:                 cert.Tenant,
		Status:                 cert.Status,
		Version:                cert.Version,
		VersionCount:           cert.VersionCount,
		Deleted:                cert.Deleted,
		Gone:                   cert.Gone,
		CertSoftDeletedInAzure: cert.CertSoftDeletedInAzure,
		SoftDeleteEnabled:      cert.SoftDeleteEnabled,
		CertMaterialOrigin:     cert.CertMaterialOrigin,
		CertSource:             cert.CertSource,
		Backup:                 cert.Backup,
		BackupAt:               cert.BackupAt,
		CreatedAt:              cert.CreatedAt,
		UpdatedAt:              cert.UpdatedAt,
		SyncedAt:               cert.SyncedAt,
		RotatedAt:              cert.RotatedAt,
		AzureCreatedAt:         cert.AzureCreatedAt,
		AzureUpdatedAt:         cert.AzureUpdatedAt,
		AzureExpireAt:          cert.AzureExpireAt,
		Cert:                   cert.Cert,
		Cid:                    cert.Cid,
		Kid:                    cert.Kid,
		Sid:                    cert.Sid,
		Thumbprint:             cert.Thumbprint,
		RecoveryLevel:          cert.RecoveryLevel,
		RecoverableDays:        cert.RecoverableDays,
		AzureParams:            cert.AzureParams,
	}, nil
}
