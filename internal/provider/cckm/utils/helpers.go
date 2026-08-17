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

// NotFoundRetainedFmt is the standard message for a non-delete 404 response.
// The %s placeholder receives the human-readable resource type (e.g. "AWS key").
// The resource ID should be included separately in the utils.ApiError details map.
const NotFoundRetainedFmt = "%s was not found and has been retained in the Terraform state. " +
	"If it has been permanently deleted, either remove it from your Terraform configuration " +
	"or run terraform state rm to remove it from the Terraform state. " +
	"If the resource remains in your configuration, Terraform will propose recreating it on the next apply."

// PendingDeletionReadFmt is the standard error message when a key or key version is found in a
// pending-deletion state during a read/refresh operation. The resource is retained in state.
// Placeholders: cloud name, resource type, state value, cloud name.
const PendingDeletionReadFmt = "%s %s was found in %s state during refresh. " +
	"The resource has been retained in Terraform state, but it cannot be managed " +
	"while scheduled for deletion. Cancel the scheduled deletion in CipherTrust " +
	"Manager or %s to resume management, or remove the resource from your Terraform " +
	"configuration if deletion is intended."

// PendingDeletionUpdateFmt is the standard error message when a key or key version is found in a
// pending-deletion state during an update operation. The resource is retained in state.
// Placeholders: cloud name, resource type, state value, cloud name.
const PendingDeletionUpdateFmt = "%s %s is in %s state. The resource has been " +
	"retained in Terraform state. Cancel the scheduled deletion in CipherTrust " +
	"Manager or %s to resume management, or remove the resource from your Terraform " +
	"configuration if deletion is intended."

// PendingDeletionDeleteFmt is the standard warning when a key/version is already in a
// pending-deletion state when a delete operation is attempted. The resource is removed from state.
// Placeholders (in order): cloud name, resource type.
const PendingDeletionDeleteFmt = "%s %s is already scheduled for deletion, " +
	"it will be removed from state."

// StringSliceToListValue converts a Go string slice into a Terraform ListValue of string elements.
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

// StringSliceJSONToListValue converts a slice of gjson.Result values into a Terraform ListValue of string elements.
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

// StringSliceJSONToSetValue converts a slice of gjson.Result values into a Terraform SetValue, deduplicating entries.
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

// SlicesAreEqual reports whether two string slice pointers contain the same elements regardless of order.
func SlicesAreEqual(a *[]string, b *[]string) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil && b != nil) || (a != nil && b == nil) || len(*a) != len(*b) {
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

// StringInSlice reports whether string a is present in slist.
func StringInSlice(a string, slist []string) bool {
	for _, b := range slist {
		if b == a {
			return true
		}
	}
	return false
}

// StringsEqual reports whether two string pointers point to equal strings, treating nil as an empty string.
func StringsEqual(a *string, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil && b != nil) || (a != nil && b == nil) || *a != *b {
		return false
	}
	return true
}

// BytesAreEqual reports whether two json.RawMessage pointers contain identical byte content.
func BytesAreEqual(a *json.RawMessage, b *json.RawMessage) bool {
	if a == nil && b == nil {
		return true
	}
	if (a == nil && b != nil) || (a != nil && b == nil) || string(*a) != string(*b) {
		return false
	}
	return true
}

// ApiError formats a structured error message combining msg with sorted key-value details and the caller's file/line location.
func ApiError(msg string, details map[string]interface{}) string {
	str := msg + "\n"
	if details != nil {
		width := 0
		var keys []string
		for k := range details {
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
	}
	return strings.TrimSpace(str)
}
