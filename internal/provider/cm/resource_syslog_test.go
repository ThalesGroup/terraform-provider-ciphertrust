package cm

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---------------------------------------------------------------------------
// hydrateSyslogOptionalFields – drift detection for message_format and port
// ---------------------------------------------------------------------------

// Test_CM_HydrateSyslogOptionalFields_OOBMessageFormatSurfaced is the primary
// regression test for the reported bug: if a user never sets message_format in
// their .tf (state has null) and an operator adds it via the CM API, Read must
// surface the value so Terraform can detect the drift.
func Test_CM_HydrateSyslogOptionalFields_OOBMessageFormatSurfaced(t *testing.T) {
	state := CMSyslogTFSDK{}
	state.MessageFormat = types.StringNull() // user never set it
	state.Port = types.Int64Null()

	response := `{"messageFormat": "cef", "port": 514}`
	hydrateSyslogOptionalFields(&state, response)

	if state.MessageFormat.IsNull() {
		t.Fatal("MessageFormat should not be null after OOB change")
	}
	if state.MessageFormat.ValueString() != "cef" {
		t.Errorf("MessageFormat: want cef, got %q", state.MessageFormat.ValueString())
	}
}

// Test_CM_HydrateSyslogOptionalFields_OOBPortSurfaced verifies that a port added
// via the CM API is surfaced in state even when the user never set port in .tf.
func Test_CM_HydrateSyslogOptionalFields_OOBPortSurfaced(t *testing.T) {
	state := CMSyslogTFSDK{}
	state.MessageFormat = types.StringNull()
	state.Port = types.Int64Null() // user never set it

	response := `{"port": 601}`
	hydrateSyslogOptionalFields(&state, response)

	if state.Port.IsNull() {
		t.Fatal("Port should not be null after OOB change")
	}
	if state.Port.ValueInt64() != 601 {
		t.Errorf("Port: want 601, got %d", state.Port.ValueInt64())
	}
}

// Test_CM_HydrateSyslogOptionalFields_MessageFormatAbsentBecomesNull ensures that
// when the API response contains no messageFormat, the state field is set to
// null (not left with a stale value from a previous state).
func Test_CM_HydrateSyslogOptionalFields_MessageFormatAbsentBecomesNull(t *testing.T) {
	state := CMSyslogTFSDK{}
	state.MessageFormat = types.StringValue("rfc5424") // stale prior value
	state.Port = types.Int64Value(514)

	response := `{"port": 514}` // no messageFormat key
	hydrateSyslogOptionalFields(&state, response)

	if !state.MessageFormat.IsNull() {
		t.Errorf("MessageFormat should be null when absent from API response, got %q",
			state.MessageFormat.ValueString())
	}
}

// Test_CM_HydrateSyslogOptionalFields_PortAbsentBecomesNull ensures that when the
// API response contains no port (or port = 0), state.Port is set to null.
func Test_CM_HydrateSyslogOptionalFields_PortAbsentBecomesNull(t *testing.T) {
	state := CMSyslogTFSDK{}
	state.MessageFormat = types.StringValue("plain_message")
	state.Port = types.Int64Value(6514) // stale prior value

	response := `{"messageFormat": "plain_message"}` // no port key
	hydrateSyslogOptionalFields(&state, response)

	if !state.Port.IsNull() {
		t.Errorf("Port should be null when absent from API response, got %d",
			state.Port.ValueInt64())
	}
}

// Test_CM_HydrateSyslogOptionalFields_BothPresentAndPreserved verifies the happy
// path: both fields are present in the response and get written to state.
func Test_CM_HydrateSyslogOptionalFields_BothPresentAndPreserved(t *testing.T) {
	state := CMSyslogTFSDK{}
	state.MessageFormat = types.StringNull()
	state.Port = types.Int64Null()

	response := `{"messageFormat": "leef", "port": 6514}`
	hydrateSyslogOptionalFields(&state, response)

	if state.MessageFormat.ValueString() != "leef" {
		t.Errorf("MessageFormat: want leef, got %q", state.MessageFormat.ValueString())
	}
	if state.Port.ValueInt64() != 6514 {
		t.Errorf("Port: want 6514, got %d", state.Port.ValueInt64())
	}
}

// Test_CM_HydrateSyslogOptionalFields_EmptyMessageFormatBecomesNull confirms that
// an explicitly empty messageFormat string in the response is treated as absent
// (set to null) rather than stored as an empty string.
func Test_CM_HydrateSyslogOptionalFields_EmptyMessageFormatBecomesNull(t *testing.T) {
	state := CMSyslogTFSDK{}
	state.MessageFormat = types.StringValue("rfc5424")
	state.Port = types.Int64Null()

	response := `{"messageFormat": "", "port": 514}`
	hydrateSyslogOptionalFields(&state, response)

	if !state.MessageFormat.IsNull() {
		t.Errorf("MessageFormat should be null for empty string response, got %q",
			state.MessageFormat.ValueString())
	}
}

// Test_CM_HydrateSyslogOptionalFields_ZeroPortBecomesNull confirms that a port
// value of 0 in the API response is treated as absent (null in state).
func Test_CM_HydrateSyslogOptionalFields_ZeroPortBecomesNull(t *testing.T) {
	state := CMSyslogTFSDK{}
	state.MessageFormat = types.StringNull()
	state.Port = types.Int64Value(514)

	response := `{"port": 0}`
	hydrateSyslogOptionalFields(&state, response)

	if !state.Port.IsNull() {
		t.Errorf("Port should be null for zero value response, got %d",
			state.Port.ValueInt64())
	}
}
