// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import (
	"encoding/json"
	"strings"
	"testing"
)

// Test_CM_LogForwardersJSON_OmitEmptyServerFields verifies that server-assigned fields
// (id, account, createdAt, updatedAt) are omitted from the JSON output when zero-valued,
// and that unused type-specific param blocks are omitted when nil.
func Test_CM_LogForwardersJSON_OmitEmptyServerFields(t *testing.T) {
	t.Run("zero-value struct omits server-assigned fields", func(t *testing.T) {
		data, err := json.Marshal(CMLogForwardersJSON{})
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		out := string(data)
		for _, key := range []string{`"id"`, `"account"`, `"createdAt"`, `"updatedAt"`} {
			if strings.Contains(out, key) {
				t.Errorf("expected key %s to be absent from JSON output, got: %s", key, out)
			}
		}
	})

	t.Run("loki-only payload omits elasticsearch_params and syslog_params", func(t *testing.T) {
		payload := CMLogForwardersJSON{
			Name: "x",
			Type: "loki",
			LokiParams: &CMLogForwardersLokiJSON{
				Labels: &CMLogForwardersESOrLokiParamsJSON{ActivityKMIP: "job=kmip"},
			},
		}
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		out := string(data)
		for _, key := range []string{`"elasticsearch_params"`, `"syslog_params"`} {
			if strings.Contains(out, key) {
				t.Errorf("expected key %s to be absent from loki payload, got: %s", key, out)
			}
		}
		if !strings.Contains(out, `"loki_params"`) {
			t.Errorf("expected loki_params to be present in output, got: %s", out)
		}
	})

	t.Run("elasticsearch-only payload omits loki_params and syslog_params", func(t *testing.T) {
		payload := CMLogForwardersJSON{
			Name: "x",
			Type: "elasticsearch",
			ElasticsearchParams: &CMLogForwardersESJSON{
				Indices: &CMLogForwardersESOrLokiParamsJSON{ActivityKMIP: "kmip-index"},
			},
		}
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json.Marshal failed: %v", err)
		}
		out := string(data)
		for _, key := range []string{`"loki_params"`, `"syslog_params"`} {
			if strings.Contains(out, key) {
				t.Errorf("expected key %s to be absent from elasticsearch payload, got: %s", key, out)
			}
		}
		if !strings.Contains(out, `"elasticsearch_params"`) {
			t.Errorf("expected elasticsearch_params to be present in output, got: %s", out)
		}
	})
}
