package cckm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/cckm/acls"
	"github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
	"net/url"
)

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
	Filters types.Map    `tfsdk:"filters"`
	Vaults  []VaultTFSDK `tfsdk:"vaults"`
}

func (d *dataSourceOCIVault) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oci_vault_list"
}

func (d *dataSourceOCIVault) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
			"vaults": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Description: "The unique identifier of the resource.",
							Computed:    true,
						},
						"uri": schema.StringAttribute{
							Description: "A human-readable unique identifier of the resource.",
							Computed:    true,
						},
						"account": schema.StringAttribute{
							Description: "The account which owns this resource.",
							Computed:    true,
						},
						"created_at": schema.StringAttribute{
							Description: "Date/time the application was created",
							Computed:    true,
						},
						"refreshed_at": schema.StringAttribute{
							Description: "Date/time the application was refreshed.",
							Computed:    true,
						},
						"updated_at": schema.StringAttribute{
							Description: "Date/time the application was updated.",
							Computed:    true,
						},
						"cloud_name": schema.StringAttribute{
							Computed:    true,
							Description: "Cloud name.",
						},
						"connection_id": schema.StringAttribute{
							Computed:    true,
							Description: "CipherTrust Manager OCI connection ID or connection name.",
						},
						"region": schema.StringAttribute{
							Computed:    true,
							Description: "OCI region.",
						},
						"tenancy": schema.StringAttribute{
							Computed:    true,
							Description: "Tenancy name.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Vault name.",
						},
						"acls": schema.SetNestedAttribute{
							Computed:    true,
							Description: "List of ACLs that have been added to the vault.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"user_id": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager user ID.",
									},
									"group": schema.StringAttribute{
										Computed:    true,
										Description: "CipherTrust Manager group name.",
									},
									"actions": schema.SetAttribute{
										Computed:    true,
										Description: "Permitted actions.",
										ElementType: types.StringType,
									},
								},
							},
						},
						"compartment_id": schema.StringAttribute{
							Computed:    true,
							Description: "Compartment OCID.",
						},
						"compartment_name": schema.StringAttribute{
							Computed:    true,
							Description: "Compartment name.",
						},
						"lifecycle_state": schema.StringAttribute{
							Computed:    true,
							Description: "Current state of the vault.",
						},
						"vault_type": schema.StringAttribute{
							Computed:    true,
							Description: "OCI Vault type.",
						},
						"time_created": schema.StringAttribute{
							Computed:    true,
							Description: "OCI Vault type.",
						},
						"freeform_tags": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Freeform tags for the key. A freeform tag is a simple key-value pair with no predefined name, type, or namespace.",
						},
						"defined_tags": schema.ListNestedAttribute{
							Computed:    true,
							Description: "Defined tags for the key. A tag consists of namespace, key, and value.",
							NestedObject: schema.NestedAttributeObject{
								Attributes: map[string]schema.Attribute{
									"tag": schema.StringAttribute{
										Computed: true,
									},
									"values": schema.MapAttribute{
										Computed:    true,
										ElementType: types.StringType,
									},
								},
							},
						},
						"restored_from_vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "OCID of the vault this vault was restored from.",
						},
						"replication_id": schema.StringAttribute{
							Computed:    true,
							Description: "OCI replication ID.",
						},
						"is_primary": schema.BoolAttribute{
							Computed:    true,
							Description: "True if a primary vault.",
						},
						"vault_id": schema.StringAttribute{
							Computed:    true,
							Description: "Vault OCID.",
						},
						"bucket_name": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Name of the OCI bucket.",
						},
						"bucket_namespace": schema.StringAttribute{
							Optional:    true,
							Computed:    true,
							Description: "Namespace of the OCI bucket.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceOCIVault) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_oci_vaults.go -> Read]["+id+"]")
	var state OCIVaultDataSourceModel
	req.Config.Get(ctx, &state)
	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		val, ok := v.(types.String)
		if ok {
			filters.Add(k, val.ValueString())
		}
	}
	jsonStr, err := d.client.ListWithFilters(ctx, id, common.URL_OCI+"/vaults/", filters)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_vaults.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI vault from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	var ociVaults VaultDataSourceJSON
	err = json.Unmarshal([]byte(jsonStr), &ociVaults)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_oci_vaults.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read OCI vault from CipherTrust Manager",
			err.Error(),
		)
		return
	}

	for ndx, vault := range ociVaults.Resources {
		vaultTFSDK := VaultTFSDK{
			VaultCommonTFSDK: VaultCommonTFSDK{
				ID:                  types.StringValue(vault.ID),
				URI:                 types.StringValue(vault.URI),
				Account:             types.StringValue(vault.Account),
				CreatedAt:           types.StringValue(vault.CreatedAt),
				UpdatedAt:           types.StringValue(vault.UpdatedAt),
				CompartmentID:       types.StringValue(vault.CompartmentID),
				DisplayName:         types.StringValue(vault.DisplayName),
				VaultID:             types.StringValue(vault.VaultID),
				LifecycleState:      types.StringValue(vault.LifecycleState),
				TimeCreated:         types.StringValue(vault.TimeCreated),
				CloudName:           types.StringValue(vault.CloudName),
				Connection:          types.StringValue(vault.Connection),
				VaultType:           types.StringValue(vault.VaultType),
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
		vaultTFSDK.BucketParamsTFSDK = BucketParamsTFSDK{
			BucketName:      types.StringValue(bucketName),
			BucketNamespace: types.StringValue(bucketNamespace),
		}
		acls.SetAclsStateFromJSON(ctx, gjson.Get(resourceJSON, "acls"), &vaultTFSDK.Acls, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setFreeformTagsStateFromMap(ctx, vault.FreeformTags, &vaultTFSDK.FreeformTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		setDefinedTagsStateFromMap(ctx, vault.DefinedTags, &vaultTFSDK.DefinedTags, &resp.Diagnostics)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Vaults = append(state.Vaults, vaultTFSDK)
	}
	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_oci_vaults.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}
