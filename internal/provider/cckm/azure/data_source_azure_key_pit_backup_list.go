package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/azure/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const azureKeyPitBackupListFiltersTable = "\n\n> **Note:** Although some filters represent integers or booleans, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"true\"` rather than `true`.\n\n" +
	"| filter            | type    | description |\n" +
	"|-------------------|---------|-------------|\n" +
	"| skip              | integer | Index of the first result to return. If `skip` or `limit` is set, only one page is requested. |\n" +
	"| limit             | integer | Maximum number of results to return (default: 10). If `skip` or `limit` is set, only one page is requested. |\n" +
	"| sort              | string  | Fields to sort by. Prefix with `-` for descending order (default: `-createdAt`). |\n" +
	"| backup_id         | string  | Filter by CipherTrust Manager resource ID of the PIT backup. |\n" +
	"| name              | string  | Filter by backup name. |\n" +
	"| backup            | string  | Filter by the CipherTrust Manager opaque object ID of the backup. |\n" +
	"| vault_name        | string  | Filter by Azure vault name. |\n" +
	"| subscription_id   | string  | Filter by subscription ID. |\n" +
	"| subscription_name | string  | Filter by subscription name. |\n" +
	"| region            | string  | Filter by region. |\n" +
	"| type              | string  | Filter by backup type. |\n" +
	"| gone              | boolean | Filter by gone. |\n" +
	"| tenant            | string  | Filter by tenant. |\n" +
	"| cloud_name        | string  | Filter by cloud name (for example, `AzureCloud`). |"

var (
	_ datasource.DataSource                     = &dataSourceAzureKeyPitBackupList{}
	_ datasource.DataSourceWithConfigure        = &dataSourceAzureKeyPitBackupList{}
	_ datasource.DataSourceWithConfigValidators = &dataSourceAzureKeyPitBackupList{}

	azureKeyPitBackupListValidFilterKeys = map[string]struct{}{
		"skip": {}, "limit": {}, "sort": {},
		"backup_id": {}, "name": {}, "backup": {}, "vault_name": {},
		"subscription_id": {}, "subscription_name": {}, "region": {},
		"type": {}, "gone": {}, "tenant": {}, "cloud_name": {},
	}
)

// NewDataSourceAzureKeyPitBackupList returns a new instance of the ciphertrust_azure_key_pit_backup_list data source.
func NewDataSourceAzureKeyPitBackupList() datasource.DataSource {
	return &dataSourceAzureKeyPitBackupList{}
}

type dataSourceAzureKeyPitBackupList struct {
	client *common.Client
}

// ConfigValidators rejects unrecognized filter keys at plan time.
func (d *dataSourceAzureKeyPitBackupList) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{azureKeyPitBackupListFilterValidator{}}
}

type azureKeyPitBackupListFilterValidator struct{}

func (v azureKeyPitBackupListFilterValidator) Description(_ context.Context) string {
	return "Validates that all filter keys are supported."
}

func (v azureKeyPitBackupListFilterValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v azureKeyPitBackupListFilterValidator) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config models.AzureKeyPitBackupListTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() || config.Filters.IsNull() || config.Filters.IsUnknown() {
		return
	}
	valid := make([]string, 0, len(azureKeyPitBackupListValidFilterKeys))
	for k := range azureKeyPitBackupListValidFilterKeys {
		valid = append(valid, k)
	}
	sort.Strings(valid)
	for k := range config.Filters.Elements() {
		if _, ok := azureKeyPitBackupListValidFilterKeys[k]; !ok {
			resp.Diagnostics.AddError(
				"Unrecognized filter key",
				fmt.Sprintf("%q is not a supported filter key. Supported keys are: %s.", k, strings.Join(valid, ", ")),
			)
		}
	}
}

func (d *dataSourceAzureKeyPitBackupList) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_key_pit_backup_list"
}

func (d *dataSourceAzureKeyPitBackupList) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceAzureKeyPitBackupList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to list the Point In Time (PIT) backups of an Azure key known to CipherTrust Manager. " +
			"The `id` of a returned backup can be used as `restore_key.backup_id` in the ciphertrust_azure_key resource. " +
			"Unless `skip` or `limit` is set in `filters`, all pages are retrieved.",
		Attributes: map[string]schema.Attribute{
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager resource ID of the Azure key whose PIT backups are listed.",
			},
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters " +
					"for listing Azure key PIT backups." + azureKeyPitBackupListFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of backups matching the given filters.",
			},
			"backups": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of PIT backups of the key.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                azureKeyListStringAttr("CipherTrust Manager resource ID of the PIT backup."),
						"name":              azureKeyListStringAttr("Name of the backup."),
						"description":       azureKeyListStringAttr("Description of the backup."),
						"type":              azureKeyListStringAttr("Type of the backup."),
						"backup":            azureKeyListStringAttr("CipherTrust Manager opaque object ID holding the backup."),
						"key_name":          azureKeyListStringAttr("Azure name of the backed up key."),
						"key_vault":         azureKeyListStringAttr("Key vault of the backed up key in the format vault_name::subscription_id."),
						"vault_name":        azureKeyListStringAttr("Name of the key vault the key belongs to."),
						"subscription_id":   azureKeyListStringAttr("Azure subscription ID."),
						"subscription_name": azureKeyListStringAttr("Azure subscription name."),
						"region":            azureKeyListStringAttr("Azure region of the key vault."),
						"cloud_name":        azureKeyListStringAttr("Cloud name as returned by CipherTrust Manager."),
						"tenant":            azureKeyListStringAttr("Azure tenant ID."),
						"created_at":        azureKeyListStringAttr("Time the backup was created in CipherTrust Manager."),
						"updated_at":        azureKeyListStringAttr("Time the backup was last updated in CipherTrust Manager."),
						"gone": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the backed up key no longer exists in Azure.",
						},
					},
				},
			},
		},
	}
}

// azureKeyPitBackupListPageSize is the page size used when all backups are retrieved.
const azureKeyPitBackupListPageSize = 100

// Read lists the PIT backups of an Azure key. If skip or limit is given in filters a single
// request is made with those values. Otherwise all pages are retrieved.
func (d *dataSourceAzureKeyPitBackupList) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_azure_key_pit_backup_list.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_azure_key_pit_backup_list.go -> Read][" + id + "]")

	var state models.AzureKeyPitBackupListTFSDK
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
	if !filters.Has("sort") {
		filters.Set("sort", "-createdAt")
	}
	singlePage := filters.Has("skip") || filters.Has("limit")

	endpoint := common.URL_AZURE + "/keys/" + state.KeyID.ValueString() + "/backups"
	entries := make([]models.AzureKeyPitBackupListEntryTFSDK, 0)
	var total int64
	skip := 0
	for {
		if !singlePage {
			filters.Set("skip", strconv.Itoa(skip))
			filters.Set("limit", strconv.Itoa(azureKeyPitBackupListPageSize))
		}
		jsonStr, err := d.client.ListWithFilters(ctx, id, endpoint, filters)
		if err != nil {
			d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_key_pit_backup_list.go -> Read][" + id + "]")
			resp.Diagnostics.AddError("Unable to read Azure key PIT backups from CipherTrust Manager", err.Error())
			return
		}
		var page models.AzureKeyPitBackupListPageJSON
		if err = json.Unmarshal([]byte(jsonStr), &page); err != nil {
			d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_azure_key_pit_backup_list.go -> Read][" + id + "]")
			resp.Diagnostics.AddError("Unable to read Azure key PIT backups from CipherTrust Manager", err.Error())
			return
		}
		total = page.Total
		for _, b := range page.Resources {
			entries = append(entries, azureKeyPitBackupListEntryToTFSDK(b))
		}
		skip += len(page.Resources)
		if singlePage || len(page.Resources) == 0 || int64(skip) >= total {
			break
		}
	}

	state.Backups = entries
	state.Matched = types.Int64Value(total)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// azureKeyPitBackupListEntryToTFSDK converts one AzureKeyPitBackupListEntryJSON to its TFSDK equivalent.
// Values that are absent from the response are returned as null.
func azureKeyPitBackupListEntryToTFSDK(b models.AzureKeyPitBackupListEntryJSON) models.AzureKeyPitBackupListEntryTFSDK {
	return models.AzureKeyPitBackupListEntryTFSDK{
		ID:               types.StringValue(b.ID),
		Name:             azureKeyOptString(b.Name),
		Description:      azureKeyOptString(b.Description),
		Type:             azureKeyOptString(b.Type),
		Backup:           azureKeyOptString(b.Backup),
		KeyName:          azureKeyOptString(b.KeyName),
		KeyVault:         azureKeyOptString(b.KeyVault),
		VaultName:        azureKeyOptString(b.VaultName),
		SubscriptionID:   azureKeyOptString(b.SubscriptionID),
		SubscriptionName: azureKeyOptString(b.SubscriptionName),
		Region:           azureKeyOptString(b.Region),
		CloudName:        azureKeyOptString(b.CloudName),
		Tenant:           azureKeyOptString(b.Tenant),
		Gone:             types.BoolValue(b.Gone),
		CreatedAt:        azureKeyOptString(b.CreatedAt),
		UpdatedAt:        azureKeyOptString(b.UpdatedAt),
	}
}
