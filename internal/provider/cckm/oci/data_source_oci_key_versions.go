package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/oci/models"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

const ociKeyVersionsFiltersTable = "\n\n> **Note:** Although some filters represent integers or booleans, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"true\"` rather than `true`, and `\"-1\"` rather than `-1`.\n\n" +
	"| filter     | type    | description |\n" +
	"|------------|---------|-------------|\n" +
	"| skip       | integer | Index of the first result to return (default: 0). |\n" +
	"| limit      | integer | Max number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort       | string  | Fields to sort by. Valid sort fields are `version_id`, `origin`, `key_id`, `updatedAt`, and `createdAt`. Prefix with `-` for descending order (for example, `-createdAt`). |\n" +
	"| version_id | string  | Filter by key version OCID. |\n" +
	"| id         | string  | Filter by CipherTrust Manager internal ID. |\n" +
	"| origin     | string  | Filter by OCI key version origin. |\n" +
	"| is_primary | boolean | Filter by whether the key version belongs to a primary vault (`true` or `false`). |"

var (
	_ datasource.DataSource              = &dataSourceOCIVersions{}
	_ datasource.DataSourceWithConfigure = &dataSourceOCIVersions{}
)

func NewDataSourceOCIVersions() datasource.DataSource {
	return &dataSourceOCIVersions{}
}

func (d *dataSourceOCIVersions) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceOCIVersions struct {
	client *common.Client
}

type KeyVersionsDataSourceModel struct {
	KeyID       types.String                       `tfsdk:"key_id"`
	Filters     types.Map                          `tfsdk:"filters"`
	KeyVersions []models.DataSourceKeyVersionTFSDK `tfsdk:"versions"`
	Matched     types.Int64                        `tfsdk:"matched"`
}

func (d *dataSourceOCIVersions) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_key_version_list"
}

func (d *dataSourceOCIVersions) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI key versions stored in CipherTrust Manager. " +
			"Supply the `key_id` of the parent key and an optional `filters` map of key/value pairs matching " +
			"the CipherTrust Manager API query parameters for listing OCI key versions " +
			"(such as `version_id` or `origin`). " +
			"Set `limit = \"-1\"` to return all matching key versions.",
		Attributes: map[string]schema.Attribute{
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager resource ID of the key whose versions to list.",
			},
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters for listing OCI key versions." + ociKeyVersionsFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The total number of records matching the given filters.",
			},
			"versions": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of OCI key versions stored in CipherTrust Manager.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
					"account": schema.StringAttribute{
						Computed:    true,
						Description: "The account that owns this resource.",
					},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the key version was created in CipherTrust Manager.",
						},
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The version's CipherTrust Manager resource ID.",
						},
						"key_material_origin": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager origin of the key version's material.",
						},
					"refreshed_at": schema.StringAttribute{
						Computed:    true,
						Description: "Date/time the key version was refreshed.",
					},
						"source_key_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager key ID used to create the version.",
						},
						"source_key_name": schema.StringAttribute{
							Computed:    true,
							Description: "Name of the key used to create the version.",
						},
						"source_key_tier": schema.StringAttribute{
							Computed:    true,
							Description: "Source of the key used to create the version.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the key version was last updated.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager's unique identifier for the resource.",
						},
						"oci_key_version_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "OCI key version attributes.",
							Attributes: map[string]schema.Attribute{
								"compartment_id": schema.StringAttribute{
									Computed:    true,
									Description: "The compartment's OCID.",
								},
								"is_primary": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the key belongs to a primary vault or a replica vault.",
								},
								"key_id": schema.StringAttribute{
									Computed:    true,
									Description: "The key's OCID.",
								},
								"lifecycle_state": schema.StringAttribute{
									Computed:    true,
									Description: "The key version's current lifecycle state.",
								},
								"origin": schema.StringAttribute{
									Computed:    true,
									Description: "CipherTrust Manager origin of the key version's material.",
								},
							"public_key": schema.StringAttribute{
								Computed:    true,
								Description: "The key version's public key.",
							},
								"replication_id": schema.StringAttribute{
									Computed:    true,
									Description: "The replication ID associated with a key version operation.",
								},
							"restored_from_key_version_id": schema.StringAttribute{
								Computed:    true,
								Description: "The OCID of the key version from which this key version was restored.",
							},
								"time_created": schema.StringAttribute{
									Computed:    true,
									Description: "The time the key version was created.",
								},
								"time_of_deletion": schema.StringAttribute{
									Computed:    true,
									Description: "The time when the key version will be deleted.",
								},
								"vault_id": schema.StringAttribute{
									Computed:    true,
									Description: "The vault's OCID.",
								},
							"version_id": schema.StringAttribute{
								Computed:    true,
								Description: "The key version's OCID.",
							},
							},
						},
					"byok_key_version_params": schema.SingleNestedAttribute{
						Computed:    true,
						Description: "Attributes for BYOK key versions.",
							Attributes: map[string]schema.Attribute{
								"oci_key_id": schema.StringAttribute{
									Computed:    true,
									Description: "The key's OCID.",
								},
								"partition_id": schema.StringAttribute{
									Computed:    true,
									Description: "HSM-Luna partition ID.",
								},
								"partition_label": schema.StringAttribute{
									Computed:    true,
									Description: "HSM-Luna partition label.",
								},
								"state": schema.StringAttribute{
									Computed:    true,
									Description: "The current state of the key version.",
								},
							},
						},
					},
				},
			},
		},
	}
}

// Read lists OCI key versions for the given key_id from CipherTrust Manager,
// optionally filtered by the key:value pairs in the filters attribute,
// and saves the results to state.
func (d *dataSourceOCIVersions) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_oci_key_versions.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_oci_key_versions.go -> Read][" + id + "]")
	var state KeyVersionsDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	keyID := state.KeyID.ValueString()
	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		val, ok := v.(types.String)
		if ok {
			filters.Add(k, val.ValueString())
		}
	}
	response, err := d.client.ListWithFilters(ctx, id, common.URL_OCI+"/keys/"+keyID+"/versions", filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_key_versions.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read OCI key versions from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var versions models.DataSourceKeyVersionsJSON
	err = json.Unmarshal([]byte(response), &versions)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_key_versions.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read OCI key versions from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for _, version := range versions.Resources {

		keyVersionTFSDK := models.DataSourceKeyVersionTFSDK{
			Account:           types.StringValue(version.Account),
			CreatedAt:         types.StringValue(version.CreatedAt),
			ID:                types.StringValue(version.ID),
			KeyMaterialOrigin: types.StringValue(version.KeyMaterialOrigin),
			RefreshedAt:       types.StringValue(version.RefreshedAt),
			SourceKeyID:       types.StringValue(version.SourceKeyID),
			SourceKeyName:     types.StringValue(version.SourceKeyName),
			SourceKeyTier:     types.StringValue(version.SourceKeyTier),
			UpdatedAt:         types.StringValue(version.UpdatedAt),
			URI:               types.StringValue(version.URI),
		}

		keyVersionParams := models.KeyVersionParamsTFSDK{
			CompartmentID:            types.StringValue(version.CompartmentID),
			IsPrimary:                types.BoolValue(version.IsPrimary),
			KeyID:                    types.StringValue(version.KeyID),
			LifecycleState:           types.StringValue(version.LifecycleState),
			Origin:                   types.StringValue(version.Origin),
			PublicKey:                types.StringValue(version.PublicKey),
			ReplicationID:            types.StringValue(version.ReplicationID),
			RestoredFromKeyVersionID: types.StringValue(version.RestoredFromKeyVersionID),
			TimeCreated:              types.StringValue(version.TimeCreated),
			TimeOfDeletion:           types.StringValue(version.TimeOfDeletion),
			VaultID:                  types.StringValue(version.VaultID),
			VersionID:                types.StringValue(version.VersionID),
		}
		setOciKeyVersionParamsState(ctx, &keyVersionParams, &keyVersionTFSDK.KeyVersionParams, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}

		byokKeyVersionParams := models.DataSourceBYOKKeyVersionParamsTFSDK{
			OCIKeyID:       types.StringValue(version.OCIKeyID),
			PartitionID:    types.StringValue(version.PartitionID),
			PartitionLabel: types.StringValue(version.PartitionLabel),
			State:          types.StringValue(version.State),
		}
		setBYOKKeyVersionParams(ctx, &byokKeyVersionParams, &keyVersionTFSDK.BYOKKeyVersionParams, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.KeyVersions = append(state.KeyVersions, keyVersionTFSDK)
	}
	state.Matched = types.Int64Value(gjson.Get(response, "total").Int())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
