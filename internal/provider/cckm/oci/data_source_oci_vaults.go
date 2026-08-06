package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

const ociVaultsFiltersTable = "\n\n> **Note:** Although some filters represent integers or booleans, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"true\"` rather than `true`, and `\"-1\"` rather than `-1`.\n\n" +
	"| filter              | type    | description |\n" +
	"|---------------------|---------|-------------|\n" +
	"| skip                | integer | Index of the first result to return (default: 0). |\n" +
	"| limit               | integer | Max number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort                | string  | Fields to sort by. Valid sort fields are `display_name`, `vault_name`, `updatedAt`, and `createdAt`. Prefix with `-` for descending order (for example, `-createdAt`). |\n" +
	"| id                  | string  | Filter by CipherTrust Manager internal ID. |\n" +
	"| display_name        | string  | Filter by vault display name. |\n" +
	"| vault_name          | string  | Filter by vault name. |\n" +
	"| linked_state        | boolean | Filter by whether the vault is in a linked state (`true` or `false`). |\n" +
	"| issuer_id           | string  | Filter by issuer ID. |\n" +
	"| state               | string  | Filter by state (for external vaults only). |\n" +
	"| external_vault_type | string  | Filter by external vault type. |\n" +
	"| cloud_name          | string  | Filter by cloud name. |\n" +
	"| vault_id            | string  | Filter by vault OCID. |\n" +
	"| vault_type          | string  | Filter by vault type. Valid values are `DEFAULT`, `EXTERNAL`, and `VIRTUAL_PRIVATE`. |\n" +
	"| tenancy             | string  | Filter by OCI tenancy. |\n" +
	"| compartment_name    | string  | Filter by compartment name. |\n" +
	"| lifecycle_state     | string  | Filter by lifecycle state. |\n" +
	"| region              | string  | Filter by region. |\n" +
	"| source_key_tier     | string  | Filter by source key tier. Valid only for the `EXTERNAL` vault type. |\n" +
	"| blocked             | boolean | Filter by whether the vault is blocked (`true` or `false`). |"

var (
	_ datasource.DataSource              = &dataSourceOCIVault{}
	_ datasource.DataSourceWithConfigure = &dataSourceOCIVault{}
)

func NewDataSourceOCIVault() datasource.DataSource {
	return &dataSourceOCIVault{}
}

type dataSourceOCIVault struct {
	client *common.Client
}

type OCIVaultDataSourceModel struct {
	Filters types.Map           `tfsdk:"filters"`
	Matched types.Int64         `tfsdk:"matched"`
	Vaults  []models.VaultTFSDK `tfsdk:"vaults"`
}

func (d *dataSourceOCIVault) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_vault_list"
}

func (d *dataSourceOCIVault) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *dataSourceOCIVault) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI vaults stored in CipherTrust Manager. " +
			"Supply a `filters` map of key/value pairs matching the CipherTrust Manager API query parameters " +
			"for listing OCI vaults (such as `vault_name`, `vault_type`, or `tenancy`). " +
			"Set `limit = \"-1\"` to return all matching vaults.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters for listing OCI vaults." + ociVaultsFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The total number of records matching the given filters.",
			},
			"vaults": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of OCI vaults stored in CipherTrust Manager.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
					"account": schema.StringAttribute{
						Computed:    true,
						Description: "The account that owns this resource.",
					},
					"acls": schema.SetNestedAttribute{
						Computed:    true,
						Description: "ACLs associated with the vault.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"actions": schema.SetAttribute{
										Computed:    true,
										Description: "Permitted actions.",
										ElementType: types.StringType,
									},
									"group": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager group name.",
									},
									"user_id": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager user ID.",
									},
								},
							},
						},
						"bucket_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the OCI bucket.",
						},
						"bucket_namespace": schema.StringAttribute{
							Computed:    true,
							Description: "Namespace of the OCI bucket.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager cloud name.",
						},
					"compartment_name": schema.StringAttribute{
						Computed:    true,
						Description: "The compartment's name.",
					},
						"compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's OCID.",
						},
						"connection_id": schema.StringAttribute{
							Computed:    true,
							Description: "The connection ID of this vault.",
						},
						"connection_name": schema.StringAttribute{
							Computed:    true,
							Description: "The connection name of this vault.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the vault was created in CipherTrust Manager.",
						},
						"defined_tags": schema.SetNestedAttribute{
							Computed:    true,
							Description: "The defined tags of the vault.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
								"tag": schema.StringAttribute{
									Computed:    true,
									Description: "The tag's namespace.",
								},
								"values": schema.MapAttribute{
									Computed:    true,
									ElementType: types.StringType,
									Description: "The key:value pairs associated with the tag.",
								},
								},
							},
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "The freeform tags of the vault.",
						},
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's CipherTrust Manager resource ID.",
						},
					"is_primary": schema.BoolAttribute{
						Computed:    true,
						Description: "Whether the vault is a primary vault (as opposed to a replica vault).",
					},
						"lifecycle_state": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's current lifecycle state.",
						},
						"management_endpoint": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's management endpoint.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's name.",
						},
						"refreshed_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the vault was last refreshed.",
						},
						"region": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's region.",
						},
						"replication_id": schema.StringAttribute{
							Computed:    true,
							Description: "The replication ID associated with a vault operation.",
						},
					"restored_from_vault_id": schema.StringAttribute{
						Computed:    true,
						Description: "The OCID of the vault from which this vault was restored.",
					},
						"tenancy": schema.StringAttribute{
							Computed:    true,
							Description: "The tenancy name.",
						},
						"time_created": schema.StringAttribute{
							Computed:    true,
							Description: "The time the vault was created.",
						},
						"vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's OCID.",
						},
						"vault_type": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's type.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the vault was last updated.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager's unique identifier for the resource.",
						},
					"wrappingkey_id": schema.StringAttribute{
						Computed:    true,
						Description: "The vault's wrapping key OCID.",
					},
					},
				},
			},
		},
	}
}

// Read lists OCI vaults from CipherTrust Manager, optionally filtered by the
// key:value pairs in the filters attribute, and saves the results to state.
func (d *dataSourceOCIVault) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_oci_vaults.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_oci_vaults.go -> Read][" + id + "]")
	var state OCIVaultDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		val, ok := v.(types.String)
		if ok {
			filters.Add(k, val.ValueString())
		}
	}
	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_OCI+"/vaults/", filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_vaults.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read OCI vaults from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var vaults models.DataSourceVaultsJSON
	err = json.Unmarshal([]byte(jsonStr), &vaults)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_vaults.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read OCI vaults from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for ndx, vault := range vaults.Resources {
		vaultTFSDK := models.VaultTFSDK{
			ConnectionID: types.StringValue(vault.Connection),
			VaultCommonTFSDK: models.VaultCommonTFSDK{
				ID:                  types.StringValue(vault.ID),
				URI:                 types.StringValue(vault.URI),
				Account:             types.StringValue(vault.Account),
				CreatedAt:           types.StringValue(vault.CreatedAt),
				UpdatedAt:           types.StringValue(vault.UpdatedAt),
				CompartmentID:       types.StringValue(vault.CompartmentID),
				DisplayName:         types.StringValue(vault.DisplayName),
				VaultID:             types.StringValue(vault.VaultID),
				LifecycleState:      types.StringValue(vault.LifecycleState),
				ManagementEndpoint:  types.StringValue(vault.ManagementEndpoint),
				TimeCreated:         types.StringValue(vault.TimeCreated),
				CloudName:           types.StringValue(vault.CloudName),
				ConnectionName:      types.StringValue(vault.Connection),
				VaultType:           types.StringValue(vault.VaultType),
				WrappingkeyID:       types.StringValue(vault.WrappingkeyID),
				RestoredFromVaultID: types.StringValue(vault.RestoredFromVaultID),
				ReplicationID:       types.StringValue(vault.ReplicationID),
				IsPrimary:           types.BoolValue(vault.IsPrimary),
				RefreshedAt:         types.StringValue(vault.RefreshedAt),
				Tenancy:             types.StringValue(vault.Tenancy),
				Region:              types.StringValue(vault.Region),
				CompartmentName:     types.StringValue(vault.CompartmentName),
			},
		}
		bucketName := ""
		if vault.BucketName != nil {
			bucketName = *vault.BucketName
		}
		bucketNamespace := ""
		if vault.BucketNamespace != nil {
			bucketNamespace = *vault.BucketNamespace
		}
		resourceJSON := gjson.Get(jsonStr, "resources").Array()[ndx].String()
		vaultTFSDK.BucketParamsTFSDK = models.BucketParamsTFSDK{
			BucketName:      types.StringValue(bucketName),
			BucketNamespace: types.StringValue(bucketNamespace),
		}
		acls.SetAclsStateFromJSON(ctx, gjson.Get(resourceJSON, "acls"), &vaultTFSDK.Acls, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setFreeformTagsState(ctx, vault.FreeformTags, &vaultTFSDK.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsState(ctx, vault.DefinedTags, &vaultTFSDK.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Vaults = append(state.Vaults, vaultTFSDK)
	}
	state.Matched = types.Int64Value(gjson.Get(jsonStr, "total").Int())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
