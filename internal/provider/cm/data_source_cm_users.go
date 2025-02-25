package cm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	common "github.com/ThalesGroup/terraform-provider-ciphertrust/internal/provider/common"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
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

type usersDataSourceModel struct {
	Filters types.Map     `tfsdk:"filters"`
	User    []CMUserTFSDK `tfsdk:"users"`
}

func (d *dataSourceUsers) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cm_users_list"
}

func (d *dataSourceUsers) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"users": schema.ListNestedAttribute{
				Computed: true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"user_id": schema.StringAttribute{
							Computed: true,
						},
						"username": schema.StringAttribute{
							Computed: true,
						},
						"nickname": schema.StringAttribute{
							Computed: true,
						},
						"email": schema.StringAttribute{
							Computed: true,
						},
						"full_name": schema.StringAttribute{
							Computed: true,
						},
						"password": schema.StringAttribute{
							Computed: true,
						},
						"is_domain_user": schema.BoolAttribute{
							Computed: true,
						},
						"prevent_ui_login": schema.BoolAttribute{
							Computed: true,
						},
						"password_change_required": schema.BoolAttribute{
							Computed: true,
						},
					},
				},
			},
			"filters": schema.MapAttribute{
				ElementType: types.StringType,
				Optional:    true,
			},
		},
	}
}

func (d *dataSourceUsers) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	id := uuid.New().String()
	tflog.Trace(ctx, common.MSG_METHOD_START+"[data_source_cm_users.go -> Read]["+id+"]")
	var state usersDataSourceModel
	req.Config.Get(ctx, &state)
	var kvs []string
	for k, v := range state.Filters.Elements() {
		kv := fmt.Sprintf("%s=%s&", k, v.(types.String).ValueString())
		kvs = append(kvs, kv)
	}

	jsonStr, err := d.client.GetAll(
		ctx,
		id,
		common.URL_USER_MANAGEMENT+"/?"+strings.Join(kvs, "")+"skip=0&limit=10")

	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_users.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read users from CM",
			err.Error(),
		)
		return
	}

	users := []CMUserJSON{}

	err = json.Unmarshal([]byte(jsonStr), &users)
	if err != nil {
		tflog.Debug(ctx, common.ERR_METHOD_END+err.Error()+" [data_source_cm_users.go -> Read]["+id+"]")
		resp.Diagnostics.AddError(
			"Unable to read users from CM",
			err.Error(),
		)
		return
	}

	for _, user := range users {
		userState := CMUserTFSDK{
			UserID:                 types.StringValue(user.UserID),
			Name:                   types.StringValue(user.Name),
			Email:                  types.StringValue(user.Email),
			Nickname:               types.StringValue(user.Nickname),
			UserName:               types.StringValue(user.UserName),
			Password:               types.StringValue(user.Password),
			IsDomainUser:           types.BoolValue(user.IsDomainUser),
			PasswordChangeRequired: types.BoolValue(user.PasswordChangeRequired),
		}

		state.User = append(state.User, userState)
	}

	tflog.Trace(ctx, common.MSG_METHOD_END+"[data_source_cm_users.go -> Read]["+id+"]")
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
