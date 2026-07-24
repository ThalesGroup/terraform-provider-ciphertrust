// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/tidwall/gjson"
)

// keysListPageSize matches CipherTrust Manager's own default page size for
// GET /vault/keys2/, so a single page still round-trips exactly like the
// previous unpaginated GetAll() call, while additional pages are fetched
// instead of being silently dropped.
const keysListPageSize = 10

// fetchAllKeys pages through GET /vault/keys2/ via limit/skip until a short
// page (fewer than keysListPageSize items) is returned, accumulating every
// key across all pages. userFilters are merged with the pagination params on
// every request so caller-supplied filters (e.g. name=foo) are preserved.
func fetchAllKeys(ctx context.Context, client *common.Client, uuid string, userFilters url.Values) ([]map[string]any, error) {
	var allKeys []map[string]any
	skip := 0
	for {
		filters := url.Values{}
		for k, vals := range userFilters {
			for _, v := range vals {
				filters.Add(k, v)
			}
		}
		filters.Set("limit", strconv.Itoa(keysListPageSize))
		filters.Set("skip", strconv.Itoa(skip))

		body, err := client.ListWithFilters(ctx, uuid, common.URL_KEY_MANAGEMENT, filters)
		if err != nil {
			return nil, err
		}

		raw := gjson.Get(body, "resources").Raw
		if raw == "" {
			break
		}
		var page []map[string]any
		if err := json.Unmarshal([]byte(raw), &page); err != nil {
			return nil, err
		}
		allKeys = append(allKeys, page...)

		if len(page) < keysListPageSize {
			break
		}
		skip += keysListPageSize
	}
	return allKeys, nil
}

var (
	_ datasource.DataSource              = &dataSourceKeys{}
	_ datasource.DataSourceWithConfigure = &dataSourceKeys{}
)

func NewDataSourceKeys() datasource.DataSource {
	return &dataSourceKeys{}
}

type dataSourceKeys struct {
	client *common.Client
}

type keysDataSourceModel struct {
	Filters types.Map         `tfsdk:"filters"`
	Keys    []CMKeysListTFSDK `tfsdk:"keys"`
}

func (d *dataSourceKeys) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_keys_list"
}

func (d *dataSourceKeys) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists cryptographic keys from CipherTrust Manager's core vault key-management API (`/v1/vault/keys2`). Retrieves every key matching the given filters, paginating internally in pages of 10 (CM's default page size) until a short page is returned, so all matching keys are returned regardless of count.",
		Attributes: map[string]schema.Attribute{
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional filters passed as query parameters to the CM keys list API, e.g. \"name\", \"algorithm\", \"id\", \"uuid\", \"muid\", \"keyId\", \"size\", \"curveid\", \"version\", or \"state\". The '?' and '*' wildcard characters may be used in \"name\". Note: \"skip\" and \"limit\" cannot be set here — the data source always paginates internally starting at skip=0 in pages of 10 to retrieve the full result set.",
			},
			"keys": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of keys matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "The unique identifier of the key.",
						},
						"uri": schema.StringAttribute{
							Computed:    true,
							Description: "A human readable unique identifier of the key.",
						},
						"account": schema.StringAttribute{
							Computed:    true,
							Description: "The account which owns this key.",
						},
						"application": schema.StringAttribute{
							Computed:    true,
							Description: "The application this key belongs to.",
						},
						"dev_account": schema.StringAttribute{
							Computed:    true,
							Description: "The developer account which owns this key's application.",
						},
						"created_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the key was created.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Friendly name of the key. The key name should not contain special characters such as angular brackets (<,>) and backslash (\\).",
						},
						"updated_at": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the key was last updated.",
						},
						"usage_mask": schema.Int64Attribute{
							Computed:    true,
							Description: "Cryptographic usage mask. Sign (1), Verify (2), Encrypt (4), Decrypt (8), Wrap Key (16), Unwrap Key (32), Export (64), MAC Generate (128), MAC Verify (256), Derive Key (512), Content Commitment (1024), Key Agreement (2048), Certificate Sign (4096), CRL Sign (8192), Generate Cryptogram (16384), Validate Cryptogram (32768), Translate Encrypt (65536), Translate Decrypt (131072), Translate Wrap (262144), Translate Unwrap (524288), FPE Encrypt (1048576), FPE Decrypt (2097152). Individual bit values are summed to form the mask.",
						},
						"version": schema.Int64Attribute{
							Computed:    true,
							Description: "Version number of the key.",
						},
						"algorithm": schema.StringAttribute{
							Computed:    true,
							Description: "Cryptographic algorithm this key is used with. One of aes, tdes, rsa, ec, hmac-sha1, hmac-sha256, hmac-sha384, hmac-sha512, seed, aria, opaque, ml-dsa.",
						},
						"size": schema.Int64Attribute{
							Computed:    true,
							Description: "Bit length for the key.",
						},
						"format": schema.StringAttribute{
							Computed:    true,
							Description: "Format of the returned key material. One of pkcs1, pkcs8 (default), or pkcs12 for asymmetric keys; raw or opaque for symmetric keys.",
						},
						"unexportable": schema.BoolAttribute{
							Computed:    true,
							Description: "Key is not exportable if true.",
						},
						"undeletable": schema.BoolAttribute{
							Computed:    true,
							Description: "Key is not deletable if true.",
						},
						"object_type": schema.StringAttribute{
							Computed:    true,
							Description: "Type of the key object. Valid values are 'Symmetric Key', 'Public Key', 'Private Key', 'Secret Data', 'Opaque Object', or 'Certificate'.",
						},
						"activation_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the object becomes active.",
						},
						"deactivation_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the object becomes inactive.",
						},
						"archive_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the object becomes archived.",
						},
						"destroy_date": schema.StringAttribute{
							Computed:    true,
							Description: "Date/time the object was destroyed.",
						},
						"revocation_reason": schema.StringAttribute{
							Computed:    true,
							Description: "The reason the key was revoked.",
						},
						"state": schema.StringAttribute{
							Computed:    true,
							Description: "Current state of the key. One of Pre-Active, Active, Deactivated, Destroyed, Compromised, or Destroyed Compromised.",
						},
						"uuid": schema.StringAttribute{
							Computed:    true,
							Description: "Additional identifier of the key. The format of this value is 32 hexadecimal lowercase digits with 4 dashes.",
						},
						"description": schema.StringAttribute{
							Computed:    true,
							Description: "Information about the key.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceKeys) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_users.go -> Read]["+id+"]")
	var state keysDataSourceModel

	req.Config.Get(ctx, &state)

	userFilters := url.Values{}
	for k, v := range state.Filters.Elements() {
		userFilters.Set(k, v.(types.String).ValueString())
	}

	data, err := fetchAllKeys(ctx, d.client, id, userFilters)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_keys.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read keys from CM",
			err.Error(),
		)
		return
	}

	for _, key := range data {
		keyState := CMKeysListTFSDK{}
		if key["id"] != nil {
			keyState.ID = types.StringValue(key["id"].(string))
		}
		if key["uri"] != nil {
			keyState.URI = types.StringValue(key["uri"].(string))
		}
		if key["account"] != nil {
			keyState.Account = types.StringValue(key["account"].(string))
		}
		if key["application"] != nil {
			keyState.Application = types.StringValue(key["application"].(string))
		}
		if key["devAccount"] != nil {
			keyState.DevAccount = types.StringValue(key["devAccount"].(string))
		}
		if key["createdAt"] != nil {
			keyState.CreatedAt = types.StringValue(key["createdAt"].(string))
		}
		if key["name"] != nil {
			keyState.Name = types.StringValue(key["name"].(string))
		}
		if key["updatedAt"] != nil {
			keyState.UpdatedAt = types.StringValue(key["updatedAt"].(string))
		}
		if key["usageMask"] != nil {
			keyState.UsageMask = types.Int64Value(int64(key["usageMask"].(float64)))
		}
		if key["version"] != nil {
			keyState.Version = types.Int64Value(int64(key["version"].(float64)))
		}
		if key["algorithm"] != nil {
			keyState.Algorithm = types.StringValue(key["algorithm"].(string))
		}
		if key["size"] != nil {
			keyState.Size = types.Int64Value(int64(key["size"].(float64)))
		}
		if key["format"] != nil {
			keyState.Format = types.StringValue(key["format"].(string))
		}
		if key["unexportable"] != nil {
			keyState.Unexportable = types.BoolValue(bool(key["unexportable"].(bool)))
		}
		if key["undeletable"] != nil {
			keyState.Undeletable = types.BoolValue(bool(key["undeletable"].(bool)))
		}
		if key["objectType"] != nil {
			keyState.ObjectType = types.StringValue(key["objectType"].(string))
		}
		if key["activationDate"] != nil {
			keyState.ActivationDate = types.StringValue(key["activationDate"].(string))
		}
		if key["deactivationDate"] != nil {
			keyState.DeactivationDate = types.StringValue(key["deactivationDate"].(string))
		}
		if key["archiveDate"] != nil {
			keyState.ArchiveDate = types.StringValue(key["archiveDate"].(string))
		}
		if key["destroyDate"] != nil {
			keyState.DestroyDate = types.StringValue(key["destroyDate"].(string))
		}
		if key["revocationReason"] != nil {
			keyState.RevocationReason = types.StringValue(key["revocationReason"].(string))
		}
		if key["state"] != nil {
			keyState.State = types.StringValue(key["state"].(string))
		}
		if key["uuid"] != nil {
			keyState.UUID = types.StringValue(key["uuid"].(string))
		}
		if key["description"] != nil {
			keyState.Description = types.StringValue(key["description"].(string))
		}
		state.Keys = append(state.Keys, keyState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_keys.go -> Read]["+id+"]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceKeys) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
