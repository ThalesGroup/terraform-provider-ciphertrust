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

const azureSecretListFiltersTable = "\n\n> **Note:** Although some filters represent integers or booleans, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"-1\"` rather than `-1`.\n\n" +
	"| filter           | type    | description |\n" +
	"|------------------|---------|-------------|\n" +
	"| skip             | integer | Index of the first result to return (default: 0). |\n" +
	"| limit            | integer | Maximum number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort             | string  | Fields to sort by. Prefix with `-` for descending order (for example, `-createdAt`). |\n" +
	"| id               | string  | Filter by CipherTrust Manager resource ID. |\n" +
	"| key_vault        | string  | Filter by key vault name. |\n" +
	"| key_vault_id     | string  | Filter by CipherTrust Manager vault resource ID. |\n" +
	"| secret_name      | string  | Filter by Azure secret name. |\n" +
	"| region           | string  | Filter by region. |\n" +
	"| status           | string  | Filter by secret status. |\n" +
	"| backup           | string  | Filter by backup. |\n" +
	"| enabled          | boolean | Filter by the enabled attribute. |\n" +
	"| deleted_in_azure | boolean | Filter by whether the secret has been deleted in Azure. |\n" +
	"| secret_id        | string  | Filter by Azure secret identifier. |\n" +
	"| gone             | boolean | Filter by gone. |\n" +
	"| version          | string  | Filter by version. Use `\"-1\"` to return only the latest version of each secret. |\n" +
	"| tags             | string  | A valid JSON value. Secrets whose tags contain the JSON value are returned. |\n" +
	"| managed          | boolean | Filter by whether the secret is managed by CipherTrust Manager. |"

var (
	_ datasource.DataSource                     = &dataSourceAzureSecretList{}
	_ datasource.DataSourceWithConfigure        = &dataSourceAzureSecretList{}
	_ datasource.DataSourceWithConfigValidators = &dataSourceAzureSecretList{}

	azureSecretListValidFilterKeys = map[string]struct{}{
		"skip": {}, "limit": {}, "sort": {},
		"id": {}, "key_vault": {}, "key_vault_id": {}, "secret_name": {}, "region": {},
		"status": {}, "backup": {}, "enabled": {}, "deleted_in_azure": {}, "secret_id": {},
		"gone": {}, "version": {}, "tags": {}, "managed": {},
	}
)

// NewDataSourceAzureSecretList returns a new instance of the ciphertrust_azure_secret_list data source.
func NewDataSourceAzureSecretList() datasource.DataSource {
	return &dataSourceAzureSecretList{}
}

type dataSourceAzureSecretList struct {
	client *common.Client
}

// ConfigValidators rejects unrecognized filter keys at plan time.
func (d *dataSourceAzureSecretList) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{azureSecretListFilterValidator{}}
}

type azureSecretListFilterValidator struct{}

func (v azureSecretListFilterValidator) Description(_ context.Context) string {
	return "Validates that all filter keys are supported."
}

func (v azureSecretListFilterValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v azureSecretListFilterValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config models.AzureSecretListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Filters.IsNull() || config.Filters.IsUnknown() {
		return
	}
	valid := make([]string, 0, len(azureSecretListValidFilterKeys))
	for k := range azureSecretListValidFilterKeys {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	for k := range config.Filters.Elements() {
		if _, ok := azureSecretListValidFilterKeys[k]; !ok {
			resp.Diagnostics.AddError(
				"Unrecognized filter key",
				fmt.Sprintf("%q is not a supported filter key. Supported keys are: %s.", k, strings.Join(valid, ", ")),
			)
		}
	}
}

func (d *dataSourceAzureSecretList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_secret_list"
}

func (d *dataSourceAzureSecretList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func azureSecretListStr(description string) schema.StringAttribute {
	return schema.StringAttribute{Computed: true, Description: description}
}

func (d *dataSourceAzureSecretList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of Azure secrets known to CipherTrust Manager. " +
			"Supply a `filters` map to narrow the results. Each secret version is a separate entry, " +
			"so use the `version` filter with the value `-1` to return only the latest version of each secret. " +
			"The secret value is never returned.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters " +
					"for listing Azure secrets." + azureSecretListFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of secrets that match the filters. It can be larger than the number returned when limit is used.",
			},
			"secrets": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The secrets that match the filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                           azureSecretListStr("CipherTrust Manager resource ID of the secret."),
						"name":                         azureSecretListStr("Name of the secret in Azure."),
						"vault_id":                     azureSecretListStr("CipherTrust Manager resource ID of the vault that holds the secret."),
						"vault_name":                   azureSecretListStr("Name of the Azure vault that contains the secret."),
						"cloud_name":                   azureSecretListStr("Azure cloud the secret belongs to."),
						"region":                       azureSecretListStr("Azure region of the key vault."),
						"tenant":                       azureSecretListStr("Azure tenant ID."),
						"status":                       azureSecretListStr("Status of the secret."),
						"version":                      azureSecretListStr("Version of the secret."),
						"version_count":                schema.Int64Attribute{Computed: true, Description: "Number of versions of the secret."},
						"deleted":                      schema.BoolAttribute{Computed: true, Description: "Whether the secret is deleted."},
						"gone":                         schema.BoolAttribute{Computed: true, Description: "Whether the secret is gone from Azure."},
						"secret_soft_deleted_in_azure": schema.BoolAttribute{Computed: true, Description: "Whether the secret is soft-deleted in Azure."},
						"soft_delete_enabled":          schema.BoolAttribute{Computed: true, Description: "Whether soft delete is enabled on the key vault."},
						"backup":                       azureSecretListStr("Backup of the secret."),
						"backup_at":                    azureSecretListStr("Time the secret was backed up."),
						"created_at":                   azureSecretListStr("Time the secret was created in CipherTrust Manager."),
						"updated_at":                   azureSecretListStr("Time the secret was last updated in CipherTrust Manager."),
						"synced_at":                    azureSecretListStr("Time the secret was last synchronized."),
						"azure_created_at":             azureSecretListStr("Time the secret was created in Azure."),
						"azure_updated_at":             azureSecretListStr("Time the secret was last updated in Azure."),
						"secret_id":                    azureSecretListStr("Azure secret identifier."),
						"content_type":                 azureSecretListStr("Content type of the secret."),
						"enabled":                      schema.BoolAttribute{Computed: true, Description: "Whether the secret is enabled."},
						"recoverable_days":             schema.Int64Attribute{Computed: true, Description: "Days a deleted secret can be recovered."},
						"recovery_level":               azureSecretListStr("Recovery level of the secret."),
						"tags":                         azureSecretListStr("Tags of the secret as a JSON string."),
					},
				},
			},
		},
	}
}

// Read lists Azure secrets from the CipherTrust Manager database, optionally
// filtered by the key:value pairs in the filters attribute, and saves the results to state.
func (d *dataSourceAzureSecretList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_secret_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_secret_list.go -> Read][" + id + "]")

	var state models.AzureSecretListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		if val, ok := v.(types.String); ok {
			filters.Add(k, val.ValueString())
		}
	}

	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_AZURE+"/secrets", filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_secret_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Unable to read Azure secrets from CipherTrust Manager", err.Error())
		return
	}

	var page models.AzureSecretListPageJSON
	if err = json.Unmarshal([]byte(jsonStr), &page); err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_secret_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Unable to read Azure secrets from CipherTrust Manager", err.Error())
		return
	}

	state.Secrets = make([]models.AzureSecretListEntryTFSDK, 0, len(page.Resources))
	for _, raw := range page.Resources {
		entry, entryErr := azureSecretListEntryToTFSDK(raw)
		if entryErr != nil {
			d.client.Log.Debug(common.ERR_METHOD_END + entryErr.Error() + " [data_source_azure_secret_list.go -> Read][" + id + "]")
			resp.Diagnostics.AddError("Unable to read Azure secrets from CipherTrust Manager", entryErr.Error())
			return
		}
		state.Secrets = append(state.Secrets, entry)
	}
	state.Matched = types.Int64Value(page.Total)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// azureSecretListEntryToTFSDK converts one listed secret. It reuses azureSecretSetState so the values
// match the ciphertrust_azure_secret resource. The secret value is not read. Absent values are null.
func azureSecretListEntryToTFSDK(raw json.RawMessage) (models.AzureSecretListEntryTFSDK, error) {
	secret := AzureSecretTFSDK{
		Name:        types.StringNull(),
		VaultID:     types.StringNull(),
		AzureParams: types.ObjectNull(azureSecretParamsAttrTypes),
	}
	if err := azureSecretSetState(string(raw), &secret); err != nil {
		return models.AzureSecretListEntryTFSDK{}, err
	}
	params := objectAttrs(secret.AzureParams)
	attributes := objectAttrs(params["attributes"])

	tags := types.StringNull()
	if tagMap, ok := params["tags"].(types.Map); ok && !tagMap.IsNull() && !tagMap.IsUnknown() {
		values := make(map[string]string, len(tagMap.Elements()))
		for k, v := range tagMap.Elements() {
			if s, isString := v.(types.String); isString {
				values[k] = s.ValueString()
			}
		}
		encoded, err := json.Marshal(values)
		if err != nil {
			return models.AzureSecretListEntryTFSDK{}, err
		}
		tags = types.StringValue(string(encoded))
	}

	enabled := types.BoolNull()
	if b, ok := attributes["enabled"].(types.Bool); ok {
		enabled = b
	}
	recoverableDays := types.Int64Null()
	if n, ok := params["recoverable_days"].(types.Int64); ok {
		recoverableDays = n
	}

	return models.AzureSecretListEntryTFSDK{
		ID:                       secret.ID,
		Name:                     secret.Name,
		VaultID:                  secret.VaultID,
		VaultName:                secret.VaultName,
		CloudName:                secret.CloudName,
		Region:                   secret.Region,
		Tenant:                   secret.Tenant,
		Status:                   secret.Status,
		Version:                  secret.Version,
		VersionCount:             secret.VersionCount,
		Deleted:                  secret.Deleted,
		Gone:                     secret.Gone,
		SecretSoftDeletedInAzure: secret.SecretSoftDeletedInAzure,
		SoftDeleteEnabled:        secret.SoftDeleteEnabled,
		Backup:                   secret.Backup,
		BackupAt:                 secret.BackupAt,
		CreatedAt:                secret.CreatedAt,
		UpdatedAt:                secret.UpdatedAt,
		SyncedAt:                 secret.SyncedAt,
		AzureCreatedAt:           secret.AzureCreatedAt,
		AzureUpdatedAt:           secret.AzureUpdatedAt,
		SecretID:                 attrString(params, "secret_id"),
		ContentType:              attrString(params, "content_type"),
		Enabled:                  enabled,
		RecoverableDays:          recoverableDays,
		RecoveryLevel:            attrString(params, "recovery_level"),
		Tags:                     tags,
	}, nil
}
