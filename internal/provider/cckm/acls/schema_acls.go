package acls

import "github.com/hashicorp/terraform-plugin-framework/types"

type ContainerAclJSON struct {
	UserID  string   `json:"user_id,omitempty"`
	Group   string   `json:"group,omitempty"`
	Permit  bool     `json:"permit"`
	Actions []string `json:"actions"`
}

type BaseAclsJSON struct {
	ContainerAcls []ContainerAclJSON `json:"acls"`
}

type AclCommonTFSDK struct {
	UserID  types.String `tfsdk:"user_id"`
	Group   types.String `tfsdk:"group"`
	Actions types.Set    `tfsdk:"actions"`
}
