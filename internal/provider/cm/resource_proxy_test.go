// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package cm

import "testing"

func Test_CM_ProxyNonPasswordPart(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "unparseable URL",
			input: "://bad url",
			want:  "",
		},
		{
			name:  "schemeless URL (now rejected by validator but must not panic)",
			input: "user01:pass@10.0.0.1:8080",
			want:  "",
		},
		{
			name:  "cleartext credentialed URL",
			input: "http://user01:test12345@10.171.18.190:8080",
			want:  "http://user01@10.171.18.190:8080",
		},
		{
			name:  "CM-masked credentialed URL",
			input: "http://user01:xxxxxx@10.171.18.190:8080",
			want:  "http://user01@10.171.18.190:8080",
		},
		{
			name:  "cleartext and masked produce identical result (no spurious diff)",
			input: "http://user01:newpassword@10.171.18.190:8080",
			want:  "http://user01@10.171.18.190:8080",
		},
		{
			name:  "URL with no user info",
			input: "http://10.171.18.190:8080",
			want:  "http://10.171.18.190:8080",
		},
		{
			name:  "https scheme",
			input: "https://user01:pass@10.171.18.190:8443",
			want:  "https://user01@10.171.18.190:8443",
		},
		{
			name:  "host/port change is detectable (different host)",
			input: "http://user01:xxxxxx@10.171.18.200:9090",
			want:  "http://user01@10.171.18.200:9090",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := proxyNonPasswordPart(tc.input)
			if got != tc.want {
				t.Errorf("proxyNonPasswordPart(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}
