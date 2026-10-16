package cckm

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// azureCertOfflineConfigParams is azure_params as the configuration has it. Everything the test does not
// write is null, which is what Terraform sends for an optional and computed attribute left out of the config.
func azureCertOfflineConfigParams(kind string) types.Object {
	actionObjType := types.ObjectType{AttrTypes: azureCertLifetimeActionAttrTypes}
	ekus := types.ListNull(types.StringType)
	keyUsage := types.ListNull(types.StringType)
	sans := types.ObjectNull(azureCertSansAttrTypes)
	attributes := types.ObjectNull(azureCertAttributesAttrTypes)
	secretProps := types.ObjectNull(azureCertSecretPropsAttrTypes)
	actions := types.ListNull(actionObjType)
	if kind == azureCertOfflineKindRich {
		ekus = azureCertOfflineStrings("1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2")
		keyUsage = azureCertOfflineStrings("digitalSignature", "keyEncipherment")
		sans = types.ObjectValueMust(azureCertSansAttrTypes, map[string]attr.Value{
			"dns_names": azureCertOfflineStrings("a.example.com", "b.example.com"),
			"emails":    types.ListNull(types.StringType),
			"upns":      types.ListNull(types.StringType),
		})
		attributes = types.ObjectValueMust(azureCertAttributesAttrTypes, map[string]attr.Value{
			"enabled":         types.BoolValue(true),
			"activation_date": types.StringNull(),
			"expiration_date": types.StringNull(),
		})
		secretProps = types.ObjectValueMust(azureCertSecretPropsAttrTypes, map[string]attr.Value{
			"content_type": types.StringValue("application/x-pkcs12"),
		})
		action := types.ObjectValueMust(azureCertLifetimeActionAttrTypes, map[string]attr.Value{
			"trigger": types.ObjectValueMust(azureCertTriggerAttrTypes, map[string]attr.Value{
				"lifetime_percentage": types.Int64Value(80),
				"days_before_expiry":  types.Int64Null(),
			}),
			"action": types.ObjectValueMust(azureCertActionAttrTypes, map[string]attr.Value{
				"action_type": types.StringValue("AutoRenew"),
			}),
		})
		actions = types.ListValueMust(actionObjType, []attr.Value{action})
	}
	policy := types.ObjectValueMust(azureCertPolicyAttrTypes, map[string]attr.Value{
		"issuer": types.ObjectValueMust(azureCertIssuerAttrTypes, map[string]attr.Value{
			"name":              types.StringValue("Self"),
			"cty":               types.StringNull(),
			"cert_transparency": types.BoolNull(),
		}),
		"key_props": types.ObjectValueMust(azureCertKeyPropsAttrTypes, map[string]attr.Value{
			"kty":        types.StringValue("RSA"),
			"curve":      types.StringNull(),
			"exportable": types.BoolNull(),
			"key_size":   types.Int64Value(2048),
			"reuse_key":  types.BoolNull(),
		}),
		"x509_props": types.ObjectValueMust(azureCertX509PropsAttrTypes, map[string]attr.Value{
			"subject":         types.StringValue(azureCertOfflineSubject),
			"ekus":            ekus,
			"key_usage":       keyUsage,
			"validity_months": types.Int64Value(12),
			"sans":            sans,
		}),
		"attributes":       attributes,
		"lifetime_actions": actions,
		"secret_props":     secretProps,
	})
	return types.ObjectValueMust(azureCertParamsAttrTypes, map[string]attr.Value{
		"tags":   types.MapValueMust(types.StringType, map[string]attr.Value{"purpose": types.StringValue("native-test")}),
		"policy": policy,
	})
}
