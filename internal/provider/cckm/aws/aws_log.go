package cckm

import "encoding/json"

// redactAWSResponse returns a version of a CipherTrust Manager AWS API response
// JSON that is safe to write to debug logs. Sensitive fields are replaced with
// the string "redacted". The original response string is never modified; all
// changes are made on an in-memory copy produced by JSON round-tripping.
//
// Handles AWS key, AWS KMS, and AWS custom key store responses.
//
// Fields redacted at the top level (present in KMS, key, and/or policy template responses):
//
//	account_id, arn
//	key_admins, key_admins_roles, key_users, key_users_roles
//	policy (top-level policy object in policy template responses)
//
// Fields redacted inside aws_param (key and custom key store responses):
//
//	AWSAccountId, Arn, Policy, Tags
//	xks_proxy_uri_endpoint
//	MultiRegionConfiguration.PrimaryKey.Arn
//	MultiRegionConfiguration.ReplicaKeys[*].Arn
//
// Fields redacted inside local_hosted_params (custom key store responses):
//
//	health_check_ciphertext
func redactAWSResponse(response string) string {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(response), &data); err != nil {
		// If we cannot parse the response, return it as-is - a malformed response
		// is itself useful diagnostic information.
		return response
	}

	for _, field := range []string{
		"account_id",
		"arn",
		"key_admins", "key_admins_roles",
		"key_users", "key_users_roles",
		"policy",
	} {
		if _, ok := data[field]; ok {
			data[field] = "redacted"
		}
	}

	if awsParam, ok := data["aws_param"].(map[string]interface{}); ok {
		for _, field := range []string{"AWSAccountId", "Arn", "Policy", "Tags", "xks_proxy_uri_endpoint"} {
			if _, ok := awsParam[field]; ok {
				awsParam[field] = "redacted"
			}
		}
		if mrc, ok := awsParam["MultiRegionConfiguration"].(map[string]interface{}); ok {
			if pk, ok := mrc["PrimaryKey"].(map[string]interface{}); ok {
				if _, ok := pk["Arn"]; ok {
					pk["Arn"] = "redacted"
				}
			}
			if rks, ok := mrc["ReplicaKeys"].([]interface{}); ok {
				for _, rk := range rks {
					if rkMap, ok := rk.(map[string]interface{}); ok {
						if _, ok := rkMap["Arn"]; ok {
							rkMap["Arn"] = "redacted"
						}
					}
				}
			}
		}
	}

	if lhp, ok := data["local_hosted_params"].(map[string]interface{}); ok {
		if _, ok := lhp["health_check_ciphertext"]; ok {
			lhp["health_check_ciphertext"] = "redacted"
		}
	}

	b, err := json.Marshal(data)
	if err != nil {
		return response
	}
	return string(b)
}
