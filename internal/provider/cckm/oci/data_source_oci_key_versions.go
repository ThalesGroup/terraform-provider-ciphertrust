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
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

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
		Description: "Use this data source to retrieve a list of CipherTrust Manager key versions.\n\n" +
			"Give a filter of 'limit=-1' to list more than 10 matches.",
		Attributes: map[string]schema.Attribute{
			"key_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager key ID of the key to list versions of.",
			},
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A list of key:value pairs where the 'key' is any of the filters available in CipherTrust Manager's API playground for listing OCI key versions.",
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "The number of key versions which matched the filters.",
			},
			"versions": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "The account which owns this resource.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the application was created",
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
							Description: "Date/time the key was refreshed.",
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
							Description: "Date/time the application was updated.",
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
									Description: "Version's public key.",
								},
								"replication_id": schema.StringAttribute{
									Computed:    true,
									Description: "The replication ID associated with a key version operation.",
								},
								"restored_from_key_version_id": schema.StringAttribute{
									Computed:    true,
									Description: "Key version OCID from which this key version was restored.",
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
									Description: "Version OCID.",
								},
							},
						},
						"hyok_key_version_params": schema.SingleNestedAttribute{
							Computed:    true,
							Description: "The attributes are related to external (hyok) keys.",
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

func (d *dataSourceOCIVersions) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_oci_key_versions.go -> Read]["+id+"]")
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
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_key_versions.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI keys from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var versions models.DataSourceKeyVersionsJSON
	err = json.Unmarshal([]byte(response), &versions)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_key_versions.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI keys from CipherTrust Manager",
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
			Origin:                   types.StringValue(version.LifecycleState),
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

		hyokKeyVersionParams := models.DataSourceHYOKKeyVersionParamsTFSDK{
			OCIKeyID:       types.StringValue(version.OCIKeyID),
			PartitionID:    types.StringValue(version.PartitionID),
			PartitionLabel: types.StringValue(version.PartitionLabel),
			State:          types.StringValue(version.State),
		}
		setHYOKKeyVersionParams(ctx, &hyokKeyVersionParams, &keyVersionTFSDK.HYOKKeyVersionParams, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.KeyVersions = append(state.KeyVersions, keyVersionTFSDK)
	}
	state.Matched = types.Int64Value(gjson.Get(response, "total").Int())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_key_versions.go -> Read]["+id+"]")
}
