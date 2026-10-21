package cckm

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func azureKeyListStringAttr(description string) schema.StringAttribute {
	return schema.StringAttribute{Computed: true, Description: description}
}

func (d *dataSourceAzureKeyList) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Use this data source to retrieve a list of Azure keys known to CipherTrust Manager. " +
			"Supply a `filters` map to narrow the results. Each key version is a separate entry, " +
			"so use the `version` filter with the value `-1` to return only the latest version of each key.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "A map of key/value pairs matching CipherTrust Manager API query parameters " +
					"for listing Azure keys." + azureKeyListFiltersTable,
			},
			"matched": schema.Int64Attribute{
				Computed:    true,
				Description: "Total number of keys matching the given filters.",
			},
			"keys": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of Azure keys.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":                     azureKeyListStringAttr("CipherTrust Manager resource ID of the key version."),
						"name":                   azureKeyListStringAttr("Azure name of the key."),
						"vault_name":             azureKeyListStringAttr("Name of the key vault the key belongs to."),
						"vault_id":               azureKeyListStringAttr("CipherTrust Manager resource ID of the key vault."),
						"cloud_name":             azureKeyListStringAttr("Cloud name as returned by CipherTrust Manager."),
						"region":                 azureKeyListStringAttr("Azure region of the key vault."),
						"status":                 azureKeyListStringAttr("Status of the key."),
						"version":                azureKeyListStringAttr("Azure version identifier of the key version."),
						"kid":                    azureKeyListStringAttr("Azure key identifier of the key version."),
						"kty":                    azureKeyListStringAttr("Key type."),
						"curve":                  azureKeyListStringAttr("Elliptic curve name. Only set for EC and EC-HSM keys."),
						"key_material_origin":    azureKeyListStringAttr("Origin of the key material."),
						"tenant":                 azureKeyListStringAttr("Azure tenant ID."),
						"created_at":             azureKeyListStringAttr("Time the key was created in CipherTrust Manager."),
						"updated_at":             azureKeyListStringAttr("Time the key was last updated in CipherTrust Manager."),
						"synced_at":              azureKeyListStringAttr("Time the key was last synchronized with Azure."),
						"rotated_at":             azureKeyListStringAttr("Time the key was last rotated. Not set until the key has been rotated."),
						"azure_created_at":       azureKeyListStringAttr("Time the key was created in Azure."),
						"azure_updated_at":       azureKeyListStringAttr("Time the key was last updated in Azure."),
						"azure_expire_at":        azureKeyListStringAttr("Time the key expires in Azure. Not set if the key has no expiry."),
						"created_by":             azureKeyListStringAttr("Client ID of the Azure registered application that created the key."),
						"modified_by":            azureKeyListStringAttr("Client ID of the Azure registered application that last modified the key."),
						"key_source":             azureKeyListStringAttr("The source of the key, for example ciphertrust or native."),
						"local_key_id":           azureKeyListStringAttr("CipherTrust Manager resource ID of the local key the Azure key was created from."),
						"operation":              azureKeyListStringAttr("The last operation performed on the key."),
						"operation_error":        azureKeyListStringAttr("The error of the last operation, if it failed."),
						"available_in_key_vault": azureKeyListStringAttr("Whether the key is available in the key vault."),
						"pk_id":                  azureKeyListStringAttr("CipherTrust Manager resource ID of the key's primary key record."),
						"version_deleted_in_azure": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether this version of the key was deleted in Azure.",
						},
						"key_size": schema.Int64Attribute{
							Computed:    true,
							Description: "Key size in bits. Only set for RSA and RSA-HSM keys.",
						},
						"enabled": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the key is enabled in Azure.",
						},
						"gone": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the key no longer exists in Azure.",
						},
						"deleted": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the key has been deleted.",
						},
					},
				},
			},
		},
	}
}
