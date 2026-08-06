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
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/tidwall/gjson"
)

const ociKeysFiltersTable = "\n\n> **Note:** Although some filters represent integers or booleans, " +
	"all filter values must be specified as strings. " +
	"For example, use `\"true\"` rather than `true`, and `\"-1\"` rather than `-1`.\n\n" +
	"| filter                    | type    | description |\n" +
	"|---------------------------|---------|-------------|\n" +
	"| skip                      | integer | Index of the first result to return (default: 0). |\n" +
	"| limit                     | integer | Max number of results to return (default: 10). Use `\"-1\"` to return all matches. |\n" +
	"| sort                      | string  | Fields to sort by. Valid sort fields are `display_name`, `region`, `key_id`, `algorithm`, `length`, `updatedAt`, `createdAt`, `time_created`, `time_of_deletion`, `linked_state`, `blocked`, `local_hyok_key_id`, and `name`. Prefix with `-` for descending order (for example, `-createdAt`). |\n" +
	"| id                        | string  | Filter by CipherTrust Manager internal ID of the OCI key. |\n" +
	"| key_name                  | string  | Filter by OCI key display name or OCI HYOK key name. |\n" +
	"| algorithm                 | string  | Filter by OCI key algorithm. |\n" +
	"| length                    | integer | Filter by OCI key length. |\n" +
	"| key_id                    | string  | Filter by OCI key OCID. |\n" +
	"| vault_name                | string  | Filter by OCI vault name. |\n" +
	"| protection_mode           | string  | Filter by OCI key protection mode. |\n" +
	"| job_config_id             | string  | Filter by job config ID. |\n" +
	"| lifecycle_state           | string  | Filter by OCI key lifecycle state. |\n" +
	"| tenancy                   | string  | Filter by OCI tenancy. |\n" +
	"| compartment_name          | string  | Filter by compartment name. |\n" +
	"| vault_id                  | string  | Filter by vault OCID. |\n" +
	"| cckm_vault_id             | string  | Filter by CipherTrust Manager vault ID. |\n" +
	"| curve_id                  | string  | Filter by curve ID. |\n" +
	"| gone                      | string  | Filter by gone status. |\n" +
	"| region                    | string  | Filter by region. |\n" +
	"| local_hyok_key_id         | string  | Filter by local HYOK key ID. |\n" +
	"| local_hyok_key_version_id | string  | Filter by local HYOK key version ID. |\n" +
	"| local_key_store_id        | string  | Filter by local key store ID. |\n" +
	"| linked_state              | boolean | Filter by whether the key is in a linked state (`true` or `false`). |\n" +
	"| key_material_origin       | string  | Filter by key material origin. Valid values are `native`, `cckm`, `HYOK-CCKM`, and `HYOK-External`. |\n" +
	"| blocked                   | boolean | Filter by whether the key is blocked (`true` or `false`). |\n" +
	"| state                     | string  | Filter by key state. Valid values are `ACTIVE` and `DISABLED`. |"

var (
	_ datasource.DataSource              = &dataSourceOCIKeys{}
	_ datasource.DataSourceWithConfigure = &dataSourceOCIKeys{}
)

func NewDataSourceOCIKeys() datasource.DataSource {
	return &dataSourceOCIKeys{}
}

func (d *dataSourceOCIKeys) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceOCIKeys struct {
	client *common.Client
}

type KeysDataSourceModel struct {
	Filters types.Map                   `tfsdk:"filters"`
	Keys    []models.DataSourceKeyTFSDK `tfsdk:"keys"`
	Matched types.Int64                 `tfsdk:"matched"`
}

func (d *dataSourceOCIKeys) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_key_list"
}

func (d *dataSourceOCIKeys) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI keys stored in CipherTrust Manager. " +
			"Supply a `filters` map of key/value pairs matching the CipherTrust Manager API query parameters " +
			"for listing OCI keys (such as `key_name`, `algorithm`, or `tenancy`). " +
			"Set `limit = \"-1\"` to return all matching keys.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters for listing OCI keys." + ociKeysFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The total number of records matching the given filters.",
			},
			"keys": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The list of OCI keys stored in CipherTrust Manager.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "The account that owns this resource.",
						},
						"auto_rotate": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the key is enabled for auto-rotation.",
						},
						"cckm_vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager vault ID.",
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager cloud name.",
						},
						"compartment_name": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's name.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the key was created in CipherTrust Manager.",
						},
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The key's CipherTrust Manager resource ID.",
						},
						"key_material_origin": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager origin of the key's material.",
						},
						"labels": schema.MapAttribute{
							ElementType: types.StringType,
							Computed:    true,
							Description: "A map of key/value pairs associated with the key.",
						},
						"oci_key_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "OCI key attributes.",
							Attributes: map[string]schema.Attribute{
								"algorithm": schema.StringAttribute{
									Computed:    true,
									Description: "The algorithm used by the key's versions to encrypt or decrypt.",
								},
								"compartment_id": schema.StringAttribute{
									Computed:    true,
									Description: "The compartment's OCID.",
								},
								"current_key_version": schema.StringAttribute{
									Computed:    true,
									Description: "The OCID of the key's current version.",
								},
								"curve_id": schema.StringAttribute{
									Computed:    true,
									Description: "The curve ID of the ECDSA key.",
								},
								"defined_tags": schema.SetNestedAttribute{
									Computed:    true,
									Description: "The defined tags of the key.",
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
								"display_name": schema.StringAttribute{
									Computed:    true,
									Description: "The key's name.",
								},
								"freeform_tags": schema.MapAttribute{
									Computed:    true,
									Description: "The key's freeform tags.",
									ElementType: types.StringType,
								},
								"is_primary": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the key belongs to a primary vault or a replica vault.",
								},
								"key_id": schema.StringAttribute{
									Computed:    true,
									Description: "The key's OCID.",
								},
								"length": schema.Int64Attribute{
									Computed:    true,
									Description: "The length of the key.",
								},
								"lifecycle_state": schema.StringAttribute{
									Computed:    true,
									Description: "The key's current lifecycle state.",
								},
								"protection_mode": schema.StringAttribute{
									Computed:    true,
									Description: "The key's protection mode.",
								},
								"replication_id": schema.StringAttribute{
									Computed:    true,
									Description: "The replication ID associated with a key operation.",
								},
								"restored_from_key_id": schema.StringAttribute{
									Computed:    true,
									Description: "The OCID of the key from which this key was restored.",
								},
								"time_created": schema.StringAttribute{
									Computed:    true,
									Description: "The time the key was created.",
								},
								"time_of_deletion": schema.StringAttribute{
									Computed:    true,
									Description: "The time when the key will be deleted.",
								},
								"vault_name": schema.StringAttribute{
									Computed:    true,
									Description: "The vault's name.",
								},
							},
						},
						"refreshed_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the key was refreshed.",
						},
						"region": schema.StringAttribute{
							Computed:    true,
							Description: "The key's region.",
						},
						"tenancy": schema.StringAttribute{
							Computed:    true,
							Description: "The key's tenancy.",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the key was last updated.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager's unique identifier for the resource.",
						},
						"vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's OCID.",
						},
						"external_key_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "Attributes for BYOK (Bring Your Own Key) keys.",
							Attributes: map[string]schema.Attribute{
								"blocked": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the key is blocked.",
								},
								"linked_state": schema.BoolAttribute{
									Computed:    true,
									Description: "Whether the key is in a linked state.",
								},
								"name": schema.StringAttribute{
									Computed:    true,
									Description: "The name of the key.",
								},
								"policy": schema.StringAttribute{
									Computed:    true,
									Description: "The key's policy.",
								},
								"state": schema.StringAttribute{
									Computed:    true,
									Description: "The key's current state.",
								},
							},
						},
						"version_summary": schema.ListNestedAttribute{
							Computed:    true,
							Description: "Key version summary.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"cckm_version_id": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager version ID.",
									},
									"created_at": schema.StringAttribute{
										Computed:    true,
										Description: "Date/time the version was created in CipherTrust Manager.",
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
									"version_id": schema.StringAttribute{
										Computed:    true,
										Description: "The key version's OCID.",
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

// Read lists OCI keys from CipherTrust Manager, optionally filtered by the
// key:value pairs in the filters attribute, and saves the results to state.
// Makes one additional API call per key to populate version_summary.
func (d *dataSourceOCIKeys) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Debug(common.MSG_METHOD_START + "[data_source_oci_keys.go -> Read][" + id + "]")
	defer d.client.Log.Debug(common.MSG_METHOD_END + "[data_source_oci_keys.go -> Read][" + id + "]")
	var state KeysDataSourceModel
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
	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_OCI+"/keys/", filters)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_keys.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read OCI keys from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var keys models.DataSourceKeysJSON
	err = json.Unmarshal([]byte(jsonStr), &keys)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_oci_keys.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read OCI keys from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for _, key := range keys.Resources {
		keyTFSDK := models.DataSourceKeyTFSDK{
			Account:           types.StringValue(key.Account),
			AutoRotate:        types.BoolValue(key.AutoRotate),
			CckmVaultID:       types.StringValue(key.CckmVaultID),
			CloudName:         types.StringValue(key.CloudName),
			CompartmentName:   types.StringValue(key.CompartmentName),
			CreatedAt:         types.StringValue(key.CreatedAt),
			ID:                types.StringValue(key.ID),
			KeyMaterialOrigin: types.StringValue(key.KeyMaterialOrigin),
			RefreshedAt:       types.StringValue(key.RefreshedAt),
			Region:            types.StringValue(key.Region),
			Tenancy:           types.StringValue(key.Tenancy),
			UpdatedAt:         types.StringValue(key.UpdatedAt),
			URI:               types.StringValue(key.URI),
			VaultID:           types.StringValue(key.VaultID),
			KeyParams: models.KeyParamsTFSDK{
				Algorithm:         types.StringValue(key.Algorithm),
				CompartmentID:     types.StringValue(key.CompartmentID),
				CurrentKeyVersion: types.StringValue(key.CurrentKeyVersion),
				CurveID:           types.StringValue(key.CurveID),
				DisplayName:       types.StringValue(key.DisplayName),
				IsPrimary:         types.BoolValue(key.IsPrimary),
				KeyID:             types.StringValue(key.KeyID),
				Length:            types.Int64Value(key.Length),
				LifecycleState:    types.StringValue(key.LifecycleState),
				ProtectionMode:    types.StringValue(key.ProtectionMode),
				ReplicationID:     types.StringValue(key.ReplicationID),
				RestoredFromKeyID: types.StringValue(key.RestoredFromKeyID),
				TimeCreated:       types.StringValue(key.TimeCreated),
				TimeOfDeletion:    types.StringValue(key.TimeOfDeletion),
				VaultName:         types.StringValue(key.VaultName),
			},
			BYOKKeyParams: models.DataSourceBYOKKeyParamsTFSDK{
				Blocked:     types.BoolValue(key.Blocked),
				LinkedState: types.BoolValue(key.LinkedState),
				Name:        types.StringValue(key.Name),
				Policy:      types.StringValue(key.Policy),
				State:       types.StringValue(key.State),
			},
		}
		setFreeformTagsState(ctx, key.FreeformTags, &keyTFSDK.KeyParams.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsState(ctx, key.DefinedTags, &keyTFSDK.KeyParams.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		var diags diag.Diagnostics
		keyTFSDK.Labels, diags = types.MapValueFrom(ctx, types.StringType, key.Labels)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		setKeyVersionSummaryState(ctx, id, d.client, key.ID, &keyTFSDK.KeyVersionSummary, &diags)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
		state.Keys = append(state.Keys, keyTFSDK)
	}
	state.Matched = types.Int64Value(gjson.Get(jsonStr, "total").Int())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
