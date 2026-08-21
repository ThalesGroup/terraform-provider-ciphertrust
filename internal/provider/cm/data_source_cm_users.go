package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &dataSourceUsers{}
	_ datasource.DataSourceWithConfigure = &dataSourceUsers{}
)

func NewDataSourceUsers() datasource.DataSource {
	return &dataSourceUsers{}
}

type dataSourceUsers struct {
	client *common.Client
}

type CMUserDSModel struct {
	ID                     types.String `tfsdk:"id"`
	UserID                 types.String `tfsdk:"user_id"`
	Name                   types.String `tfsdk:"name"`
	UserName               types.String `tfsdk:"username"`
	Nickname               types.String `tfsdk:"nickname"`
	Email                  types.String `tfsdk:"email"`
	Password               types.String `tfsdk:"password"`
	IsDomainUser           types.Bool   `tfsdk:"is_domain_user"`
	PreventUILogin         types.Bool   `tfsdk:"prevent_ui_login"`
	PasswordChangeRequired types.Bool   `tfsdk:"password_change_required"`
	Metadata               types.Map    `tfsdk:"user_metadata"`
}

type usersDataSourceModel struct {
	ID      types.String    `tfsdk:"id"`
	Filters types.Map       `tfsdk:"filters"`
	Limit   types.Int64     `tfsdk:"limit"`
	Skip    types.Int64     `tfsdk:"skip"`
	User    []CMUserDSModel `tfsdk:"users"`
}

func (d *dataSourceUsers) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_users_list"
}

func (d *dataSourceUsers) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Lists local CipherTrust Manager (or CDSPaaS) user accounts via the /v1/usermgmt/users API.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "The stable computed ID of this data source.",
			},
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Optional filters passed as query parameters to the CM users list API. Supported keys: \"name\", \"username\", \"email\", \"groups\" (comma-separated group names; use \"nil\" for users in no group), \"exclude_groups\" (comma-separated group names to exclude), \"auth_domain_name\", \"account_expired\" (boolean), \"allowed_auth_methods\" (comma-separated; use \"empty\" for users with no allowed auth method), \"allowed_client_types\" (comma-separated), \"password_policy\", \"return_groups\" (boolean), and \"is_admin\" (boolean; overrides \"groups\" when true).",
			},
			"limit": schema.Int64Attribute{
				Optional:    true,
				Description: "Limit the number of returned users (default: 1000).",
			},
			"skip": schema.Int64Attribute{
				Optional:    true,
				Description: "Number of users to skip (default: 0).",
			},
			"users": schema.ListNestedAttribute{
				Computed:    true,
				Description: "List of users matching the given filters.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the user, same value as `user_id`.",
						},
						"user_id": schema.StringAttribute{
							Computed:    true,
							Description: "Unique identifier of the user, as assigned by CipherTrust Manager.",
						},
						"username": schema.StringAttribute{
							Computed:    true,
							Description: "Username of the user.",
						},
						"nickname": schema.StringAttribute{
							Computed:    true,
							Description: "Display name / nickname of the user.",
						},
						"email": schema.StringAttribute{
							Computed:    true,
							Description: "Email address of the user.",
						},
						"name": schema.StringAttribute{
							Computed:    true,
							Description: "Users full name",
						},
						"password": schema.StringAttribute{
							Computed:    true,
							Sensitive:   true,
							Description: "Deprecated. This attribute is always unpopulated (null) to protect sensitive credentials from being stored in state.",
						},
						"is_domain_user": schema.BoolAttribute{
							Computed:    true,
							Description: "Set to true if user is a domain user.",
						},
						"prevent_ui_login": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the user is prevented from logging in through the CipherTrust Manager UI.",
						},
						"password_change_required": schema.BoolAttribute{
							Computed:    true,
							Description: "Whether the user must change their password on next login.",
						},
						"user_metadata": schema.MapAttribute{
							Computed:    true,
							ElementType: types.StringType,
							Description: "Information that can be stored with the user.",
						},
					},
				},
			},
		},
	}
}

func (d *dataSourceUsers) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	d.client.Log.Trace(common.MSG_METHOD_START + "[data_source_cm_users.go -> Read][" + id + "]")
	var state usersDataSourceModel
	req.Config.Get(ctx, &state)

	state.ID = types.StringValue("users-list")
	state.User = []CMUserDSModel{}

	var kvs []string
	if !state.Filters.IsNull() && !state.Filters.IsUnknown() {
		for k, v := range state.Filters.Elements() {
			strVal, ok := v.(types.String)
			if !ok || strVal.IsNull() || strVal.IsUnknown() {
				resp.Diagnostics.AddError(
					"Invalid filters input",
					fmt.Sprintf("Key %q in filters has an invalid or unconfigured string value", k),
				)
				return
			}
			kv := fmt.Sprintf("%s=%s&", k, strVal.ValueString())
			kvs = append(kvs, kv)
		}
	}

	limitVal := int64(1000)
	if !state.Limit.IsNull() && !state.Limit.IsUnknown() {
		limitVal = state.Limit.ValueInt64()
	}
	skipVal := int64(0)
	if !state.Skip.IsNull() && !state.Skip.IsUnknown() {
		skipVal = state.Skip.ValueInt64()
	}

	jsonStr, total, err := d.client.GetAllWithTotal(
		ctx,
		id,
		fmt.Sprintf("%s/?%sskip=%d&limit=%d", common.URL_USER_MANAGEMENT, strings.Join(kvs, ""), skipVal, limitVal))

	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cm_users.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read users from CM",
			err.Error(),
		)
		return
	}

	if total > limitVal {
		resp.Diagnostics.AddWarning(
			"Result Set Truncated",
			fmt.Sprintf("The server returned %d total users, but only %d were retrieved due to the configured limit parameter. To retrieve more items, please increase the 'limit' attribute in your data source configuration.", total, limitVal),
		)
	}

	// CM omits the "resources" field (gjson returns "") when zero entries match the filter.
	if jsonStr == "" {
		jsonStr = "[]"
	}

	users := []CMUserJSON{}

	err = json.Unmarshal([]byte(jsonStr), &users)
	if err != nil {
		d.client.Log.Debug(common.ERR_METHOD_END + err.Error() + " [data_source_cm_users.go -> Read][" + id + "]")
		resp.Diagnostics.AddError(
			"Unable to read users from CM",
			err.Error(),
		)
		return
	}

	for _, user := range users {
		userState := CMUserDSModel{
			ID:                     types.StringValue(user.UserID),
			UserID:                 types.StringValue(user.UserID),
			Name:                   types.StringValue(user.Name),
			Email:                  types.StringValue(user.Email),
			Nickname:               types.StringValue(user.Nickname),
			UserName:               types.StringValue(user.UserName),
			IsDomainUser:           types.BoolValue(user.IsDomainUser),
			PreventUILogin:         types.BoolValue(user.LoginFlags.PreventUILogin),
			PasswordChangeRequired: types.BoolValue(user.PasswordChangeRequired),
			Metadata:               convertMetadata(user.Metadata),
		}

		state.User = append(state.User, userState)
	}

	d.client.Log.Trace(common.MSG_METHOD_END + "[data_source_cm_users.go -> Read][" + id + "]")
	diags := resp.State.Set(ctx, &state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (d *dataSourceUsers) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func convertMetadata(m map[string]json.RawMessage) types.Map {
	if len(m) == 0 {
		return types.MapValueMust(types.StringType, map[string]attr.Value{})
	}
	result := make(map[string]attr.Value)
	for k, v := range m {
		// Attempt to unquote plain JSON strings so "value" round-trips as value.
		// Non-string values (objects, arrays) are stored as their raw JSON.
		var s string
		if json.Unmarshal(v, &s) == nil {
			result[k] = types.StringValue(s)
		} else {
			result[k] = types.StringValue(string(v))
		}
	}
	return types.MapValueMust(types.StringType, result)
}
