package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ datasource.DataSource              = &dataSourceGroups{}
	_ datasource.DataSourceWithConfigure = &dataSourceGroups{}
)

func NewDataSourceGroups() datasource.DataSource {
	return &dataSourceGroups{}
}

type dataSourceGroups struct {
	client *common.Client
}

func (d *dataSourceGroups) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_groups_list"
}

func (d *dataSourceGroups) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists local CipherTrust Manager user groups via the /v1/usermgmt/groups API.",
		Attributes: map[string]schema.Attribute{
			"groups": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of groups matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Unique group name.",
						},
					},
				},
			},
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional filters passed as query parameters to the CM groups list API. Supported keys: \"name\" (filter by group name), \"users\" (filter by user membership; use \"nil\" for groups with no members, or prefix a user ID with \"-\" for groups the user is not part of), \"connection\" (filter by connection name or ID; applies only to user group membership), \"clients\" (filter by client membership; use \"nil\" for groups with no members, or prefix a client ID with \"-\" for groups the client is not part of), \"skip\", and \"limit\". If \"skip\" or \"limit\" is set, only a single page is fetched as specified; otherwise the data source automatically paginates internally and returns all groups.",
			},
		},
	}
}

func (d *dataSourceGroups) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_groups.go -> Read]["+id+"]")
	var state CMGroupsDataSourceModelTFSDK

	diags := req.Config.Get(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.Filters.IsNull() || state.Filters.IsUnknown() {
		state.Filters = types.MapNull(types.StringType)
	}

	filters := url.Values{}
	for k, v := range state.Filters.Elements() {
		filters.Set(k, v.(types.String).ValueString())
	}

	var groups []CMGroupJSON

	if filters.Get("skip") != "" || filters.Get("limit") != "" {
		rawBody, err := d.client.ListWithFilters(ctx, id, common.URL_GROUP, filters)
		if err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_groups.go -> Read]["+id+"]")
			resp.Diagnostics.AddError(
				"Unable to read groups from CM",
				err.Error(),
			)
			return
		}
		jsonStr := gjson.Get(rawBody, "resources").String()
		if err := json.Unmarshal([]byte(jsonStr), &groups); err != nil {
			tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_groups.go -> Read]["+id+"]")
			resp.Diagnostics.AddError("Unable to read groups from CM", err.Error())
			return
		}
	} else {
		skip := 0
		limit := 100
		for {
			filters.Set("skip", fmt.Sprintf("%d", skip))
			filters.Set("limit", fmt.Sprintf("%d", limit))

			rawBody, err := d.client.ListWithFilters(ctx, id, common.URL_GROUP, filters)
			if err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_groups.go -> Read paginated]["+id+"]")
				resp.Diagnostics.AddError(
					"Unable to read groups from CM",
					err.Error(),
				)
				return
			}

			resources := gjson.Get(rawBody, "resources").Array()
			if len(resources) == 0 {
				break
			}

			var pageGroups []CMGroupJSON
			jsonStr := gjson.Get(rawBody, "resources").String()
			if err := json.Unmarshal([]byte(jsonStr), &pageGroups); err != nil {
				tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_groups.go -> Read paginated unmarshal]["+id+"]")
				resp.Diagnostics.AddError("Unable to read groups from CM", err.Error())
				return
			}

			groups = append(groups, pageGroups...)

			if len(resources) < limit {
				break
			}
			skip += limit
		}
	}

	for _, group := range groups {
		state.Groups = append(state.Groups, CMGroupsListModelTFSDK{
			Name: types.StringValue(group.Name),
		})
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_groups.go -> Read]["+id+"]")
	diags = resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
}

func (d *dataSourceGroups) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
