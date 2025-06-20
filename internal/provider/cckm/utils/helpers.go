package utils

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

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
	valueMap := make(map[string]bool)
	for _, item := range jsonString {
		// No duplicates please!
		if _, ok := valueMap[item.String()]; !ok {
			valueMap[item.String()] = true
			values = append(values, types.StringValue(item.String()))
		}
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
	width := 0
	var keys []string
	for k, _ := range details {
		keys = append(keys, k)
		if len(k) > width {
			width = len(k)
		}
	}
	width++
	sort.Strings(keys)
	for _, k := range keys {
		str = str + fmt.Sprintf("%*s: %s\n", width, k, strings.TrimSpace(fmt.Sprintf("%v", details[k])))
	}
	_, file, line, ok := runtime.Caller(1)
	if ok {
		str = str + fmt.Sprintf("%*s: %s:%d", width, "file", filepath.Base(file), line)
	}
	return strings.TrimSpace(str)
}
