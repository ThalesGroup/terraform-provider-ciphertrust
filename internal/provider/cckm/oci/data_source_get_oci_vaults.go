package cckm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/utils"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceGetOCIVaults{}
	_ datasource.DataSourceWithConfigure = &dataSourceGetOCIVaults{}
)

func NewDataSourceGetOCIVaults() datasource.DataSource {
	return &dataSourceGetOCIVaults{}
}

func (d *dataSourceGetOCIVaults) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type dataSourceGetOCIVaults struct {
	client *common.Client
}

func (d *dataSourceGetOCIVaults) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_get_oci_vaults"
}

func (d *dataSourceGetOCIVaults) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of OCI vaults available to the connection in the region and compartment.",
		Attributes: map[string]schema.Attribute{
			"connection_id": schema.StringAttribute{
				Required:    true,
				Description: "CipherTrust Manager OCI connection name or ID.",
			},
			"compartment_id": schema.StringAttribute{
				Required:    true,
				Description: "Compartment OICD to get vaults from.",
			},
			"region": schema.StringAttribute{
				Required:    true,
				Description: "OCI region OICD to get vaults from.",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of records to return in a paginated 'List' call. It might not return the exact number as the first page might return one more than provided limit because of the inclusion of the root vault (tenancy).",
				Validators:  []validator.Int64{int64validator.AtLeast(1)},
			},
			"vaults": schema.ListNestedAttribute{
				Description: "A list of vaults available to the connection.",
				Computed:    true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "The compartment's OCID.",
						},
						"defined_tags": schema.SetNestedAttribute{
							Computed:    true,
							Description: "The defined tags of the vault.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"tag": schema.StringAttribute{
										Computed:    true,
										Description: "The vault's defined tags.",
									},
									"values": schema.MapAttribute{
										Computed:    true,
										ElementType: types.StringType,
										Description: "The key:vault pair's associated with the tag.",
									},
								},
							},
						},
						"display_name": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's name.",
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "The freeform tags of the vault.",
						},
						"lifecycle_state": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's current lifecycle state.",
						},
						"management_endpoint": schema.StringAttribute{
							Computed:    true,
							Description: "The vault's management endpoint.",
						},
						"time_created": schema.StringAttribute{
							Computed:    true,
							Description: "The time the vault was created in OCI.",
						},
						"vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "The vaults OCID.",
						},
						"vault_type": schema.StringAttribute{
							Computed:    true,
							Description: "OCI Vault type.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceGetOCIVaults) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_get_oci_vaults.go -> Read]")
	defer tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_get_oci_vaults.go -> Read]")
	id := uuid.New().String()

	var state DataSourceGetOCIVaultsTFSDK
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)

	connection := state.Connection.ValueString()
	payload := GetOCIVaultsPayloadJSON{
		Connection:    connection,
		CompartmentID: state.CompartmentID.ValueString(),
		Region:        state.Region.ValueString(),
	}
	limit := state.Limit.ValueInt64()
	if limit != 0 {
		payload.Limit = &limit
	}

	var data []DataSourceGetOCIVaultJSON
	vaults := d.fetchVaults(ctx, id, payload, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	data = append(data, vaults.Data...)
	nextPage := vaults.NextPage
	for i := 0; nextPage != "" && (limit != 0 && int64(len(data)) < limit); i++ {
		payload.NextPage = &nextPage
		vaults = d.fetchVaults(ctx, id, payload, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		data = append(data, vaults.Data...)
		nextPage = vaults.NextPage
	}

	for _, vault := range data {
		ociVault := DataSourceGetOCIVaultTFSDK{
			CompartmentID:      types.StringValue(vault.CompartmentID),
			DisplayName:        types.StringValue(vault.DisplayName),
			VaultID:            types.StringValue(vault.VaultID),
			LifecycleState:     types.StringValue(vault.LifecycleState),
			ManagementEndpoint: types.StringValue(vault.ManagementEndpoint),
			TimeCreated:        types.StringValue(vault.TimeCreated),
			VaultType:          types.StringValue(vault.VaultType),
		}
		setFreeformTagsState(ctx, vault.FreeformTags, &ociVault.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsState(ctx, vault.DefinedTags, &ociVault.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Vaults = append(state.Vaults, ociVault)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_get_vaults.go -> Read]["+id+"]")
}

func (d *dataSourceGetOCIVaults) fetchVaults(ctx context.Context, id string, payload GetOCIVaultsPayloadJSON, diags *diag.Diagnostics) *GetOCIVaultsJSON {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		msg := "Error reading OCI vaults, invalid data input."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	response, err := d.client.PostDataV2(ctx, id, common.URL_OCI+"/get-vaults", payloadJSON)
	if err != nil {
		msg := "Error reading OCI vaults."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	var ociVaults GetOCIVaultsJSON
	err = json.Unmarshal([]byte(response), &ociVaults)
	if err != nil {
		msg := "Error reading OCI vaults, invalid data output."
		details := utils.ApiError(msg, map[string]interface{}{"error": err.Error(), "connection_id": payload.Connection})
		tflog.Error(ctx, details)
		diags.AddError(details, "")
		return nil
	}
	return &ociVaults
}
