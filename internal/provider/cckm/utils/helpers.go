package utils

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/tidwall/gjson"
)

func StringSliceToListValue(inputStrings []string, diags *diag.Diagnostics) basetypes.ListValue {
	var values []attr.Value
	for _, item := range inputStrings {
		values = append(values, types.StringValue(item))
	}
	stringList, d := types.ListValue(types.StringType, values)
	if d.HasError() {
		diags.Append(d...)
	}
	return stringList
}

func StringSliceJSONToListValue(jsonString []gjson.Result, diags *diag.Diagnostics) basetypes.ListValue {
	var values []attr.Value
	for _, item := range jsonString {
		values = append(values, types.StringValue(item.String()))
	}
	stringList, d := types.ListValue(types.StringType, values)
	if d.HasError() {
		diags.Append(d...)
	}
	return stringList
}

func StringSliceJSONToSetValue(jsonString []gjson.Result, diags *diag.Diagnostics) basetypes.SetValue {
	var values []attr.Value
	for _, item := range jsonString {
		values = append(values, types.StringValue(item.String()))
	}
	stringSet, d := types.SetValue(types.StringType, values)
	if d.HasError() {
		diags.Append(d...)
	}
	return stringSet
}

func SlicesAreEqual(a *[]string, b *[]string) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil && b != nil) || (a != nil && b == nil) {
		return false
	}
	for _, str := range *a {
		if !StringInSlice(str, *b) {
			return false
		}
	}
	for _, str := range *b {
		if !StringInSlice(str, *a) {
			return false
		}
	}
	return true
}

func StringInSlice(a string, slist []string) bool {
	for _, b := range slist {
		if b == a {
			return true
		}
	}
	return false
}

func StringsEqual(a *string, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil && b != nil) || (a != nil && b == nil) || *a != *b {
		return false
	}
	return true
}

func BytesAreEqual(a *json.RawMessage, b *json.RawMessage) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil && b != nil) || (a != nil && b == nil) || string(*a) != string(*b) {
		return false
	}
	return true
}

func ApiError(msg string, details map[string]interface{}) string {
	str := msg + "\n"
	for k, v := range details {
		if k == "payload" {
			b, err := json.Marshal(v)
			if err == nil {
				v = string(b)
			}
		}
		if len(str) == 0 {
			str = fmt.Sprintf("%v=%v\n", k, v)
		} else {
			str = str + fmt.Sprintf("%v=%v\n", k, v)
		}
	}
	return str
}

func GetAclsStateList(ctx context.Context, acslJSON gjson.Result, aclsList *types.List, diags *diag.Diagnostics) {
	type AclsTFSDK struct {
		UserID  types.String `tfsdk:"user_id"`
		Group   types.String `tfsdk:"group"`
		Actions types.Set    `tfsdk:"actions"`
	}
	var aclsTfsdk []AclsTFSDK
	for _, aclJSON := range acslJSON.Array() {
		var actions []attr.Value
		for _, item := range gjson.Get(aclJSON.String(), "actions").Array() {
			actions = append(actions, types.StringValue(item.String()))
		}
		var dg diag.Diagnostics
		actionSet, dg := types.SetValue(types.StringType, actions)
		if dg.HasError() {
			diags.Append(dg...)
			return
		}
		aclTfsdk := AclsTFSDK{
			UserID:  types.StringValue(gjson.Get(aclJSON.String(), "user_id").String()),
			Group:   types.StringValue(gjson.Get(aclJSON.String(), "group").String()),
			Actions: actionSet,
		}
		aclsTfsdk = append(aclsTfsdk, aclTfsdk)
	}
	var dg diag.Diagnostics
	aclsListValue, dg := types.ListValueFrom(ctx,
		types.ObjectType{AttrTypes: map[string]attr.Type{
			"user_id": types.StringType,
			"group":   types.StringType,
			"actions": types.SetType{ElemType: types.StringType},
		}}, aclsTfsdk)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
	*aclsList, dg = aclsListValue.ToListValue(ctx)
	if dg.HasError() {
		diags.Append(dg...)
		return
	}
}
