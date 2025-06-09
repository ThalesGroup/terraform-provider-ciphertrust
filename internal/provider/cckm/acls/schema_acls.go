package acls

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type ContainerAclJSON struct {
	UserID  string   `json:"user_id,omitempty"`
	Group   string   `json:"group,omitempty"`
	Permit  bool     `json:"permit"`
	Actions []string `json:"actions"`
}

type BaseAclsJSON struct {
	ContainerAcls []ContainerAclJSON `json:"acls"`
}

type AclTFSDK struct {
	UserID  types.String `tfsdk:"user_id"`
	Group   types.String `tfsdk:"group"`
	Actions types.Set    `tfsdk:"actions"`
}

var AclAttributes = map[string]attr.Type{
	"user_id": types.StringType,
	"group":   types.StringType,
	"actions": types.SetType{ElemType: types.StringType},
}

type AclJSON struct {
	UserID  string   `json:"user_id"`
	Group   string   `json:"group"`
	Actions []string `json:"actions"`
}
