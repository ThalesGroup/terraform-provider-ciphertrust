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
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const azureKeyListFiltersTable = "\n\n> **Note:** Although some filters represent integers or booleans, " +
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
	"| key_name             | string  | Filter by Azure key name. |\n" +
	"| cloud_name           | string  | Filter by cloud name (for example, `AzureCloud`). |\n" +
	"| region               | string  | Filter by region. |\n" +
	"| crv                  | string  | Filter by EC curve. |\n" +
	"| status               | string  | Filter by key status. |\n" +
	"| backup               | string  | Filter by backup. |\n" +
	"| enabled              | boolean | Filter by the enabled attribute. |\n" +
	"| key_size             | integer | Filter by key size. |\n" +
	"| job_config_id        | string  | Filter by the ID of the scheduler configuration job. |\n" +
	"| backup_job_config_id | string  | Filter by the ID of the key backup scheduler configuration job. |\n" +
	"| deleted_in_azure     | boolean | Filter by whether the key has been deleted in Azure. |\n" +
	"| algorithm            | string  | Filter by algorithm type. |\n" +
	"| kid                  | string  | Filter by Azure key identifier. |\n" +
	"| gone                 | boolean | Filter by gone. |\n" +
	"| version              | string  | Filter by version. Use `\"-1\"` to return only the latest version of each key. |\n" +
	"| rotation_job_enabled | boolean | Filter by whether a rotation job is enabled. |\n" +
	"| tags                 | string  | A valid JSON value. Keys whose tags contain the JSON value are returned. |\n" +
	"| key_material_origin  | string  | Filter by key material origin. |\n" +
	"| managed              | boolean | Filter by whether the key is managed by Azure vaults. |\n" +
	"| external_key_id      | string  | Filter by external key ID. |"

var (
	_ datasource.DataSource                     = &dataSourceAzureKeyList{}
	_ datasource.DataSourceWithConfigure        = &dataSourceAzureKeyList{}
	_ datasource.DataSourceWithConfigValidators = &dataSourceAzureKeyList{}

	azureKeyListValidFilterKeys = map[string]struct{}{
		"skip": {}, "limit": {}, "sort": {},
		"id": {}, "key_vault": {}, "key_vault_id": {}, "key_name": {}, "cloud_name": {},
		"region": {}, "crv": {}, "status": {}, "backup": {}, "enabled": {}, "key_size": {},
		"job_config_id": {}, "backup_job_config_id": {}, "deleted_in_azure": {}, "algorithm": {},
		"kid": {}, "gone": {}, "version": {}, "rotation_job_enabled": {}, "tags": {},
		"key_material_origin": {}, "managed": {}, "external_key_id": {},
	}
)

// NewDataSourceAzureKeyList returns a new instance of the ciphertrust_azure_key_list data source.
func NewDataSourceAzureKeyList() datasource.DataSource {
	return &dataSourceAzureKeyList{}
}

type dataSourceAzureKeyList struct {
	client *common.Client
}

// ConfigValidators rejects unrecognized filter keys at plan time.
func (d *dataSourceAzureKeyList) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{azureKeyListFilterValidator{}}
}

type azureKeyListFilterValidator struct{}

func (v azureKeyListFilterValidator) Description(_ context.Context) string {
	return "Validates that all filter keys are supported."
}

func (v azureKeyListFilterValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v azureKeyListFilterValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config models.AzureKeyListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Filters.IsNull() || config.Filters.IsUnknown() {
		return
	}
	valid := make([]string, 0, len(azureKeyListValidFilterKeys))
	for k := range azureKeyListValidFilterKeys {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	for k := range config.Filters.Elements() {
		if _, ok := azureKeyListValidFilterKeys[k]; !ok {
			resp.Diagnostics.AddError(
				"Unrecognized filter key",
				fmt.Sprintf("%q is not a supported filter key. Supported keys are: %s.", k, strings.Join(valid, ", ")),
			)
		}
	}
}

func (d *dataSourceAzureKeyList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_key_list"
}

func (d *dataSourceAzureKeyList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

// Read lists Azure keys from the CipherTrust Manager database, optionally
// filtered by the key:value pairs in the filters attribute, and saves the results to state.
func (d *dataSourceAzureKeyList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_key_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_key_list.go -> Read][" + id + "]")

	var state models.AzureKeyListTFSDK
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

	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_AZURE+"/keys", filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_key_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Unable to read Azure keys from CipherTrust Manager", err.Error())
		return
	}

	var page models.AzureKeyListPageJSON
	if err = json.Unmarshal([]byte(jsonStr), &page); err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_key_list.go -> Read][" + id + "]")
		resp.Diagnostics.AddError("Unable to read Azure keys from CipherTrust Manager", err.Error())
		return
	}

	state.Keys = make([]models.AzureKeyListEntryTFSDK, 0, len(page.Resources))
	for _, k := range page.Resources {
		state.Keys = append(state.Keys, azureKeyListEntryToTFSDK(k))
	}
	state.Matched = types.Int64Value(page.Total)

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// azureKeyListEntryToTFSDK converts one AzureKeyListEntryJSON to its TFSDK equivalent.
// Values that are absent from the response are returned as null.
func azureKeyListEntryToTFSDK(k models.AzureKeyListEntryJSON) models.AzureKeyListEntryTFSDK {
	optString := func(s string) types.String {
		if s == "" {
			return types.StringNull()
		}
		return types.StringValue(s)
	}
	keySize := types.Int64Null()
	if k.KeySize != 0 {
		keySize = types.Int64Value(k.KeySize)
	}
	return models.AzureKeyListEntryTFSDK{
		ID:                types.StringValue(k.ID),
		Name:              types.StringValue(k.KeyName),
		VaultName:         optString(k.KeyVault),
		VaultID:           optString(k.KeyVaultID),
		CloudName:         optString(k.CloudName),
		Region:            optString(k.Region),
		Status:            optString(k.Status),
		Version:           optString(k.Version),
		Kid:               optString(k.AzureParam.Key.Kid),
		Kty:               optString(k.AzureParam.Key.Kty),
		Curve:             optString(k.AzureParam.Key.Crv),
		KeySize:           keySize,
		Enabled:           types.BoolValue(k.AzureParam.Attributes.Enabled),
		KeyMaterialOrigin: optString(k.KeyMaterialOrigin),
		Tenant:            optString(k.Tenant),
		Gone:              types.BoolValue(k.Gone),
		Deleted:           types.BoolValue(k.Deleted),
		CreatedAt:         optString(k.CreatedAt),
		UpdatedAt:         optString(k.UpdatedAt),
		SyncedAt:          optString(k.SyncedAt),
	}
}
