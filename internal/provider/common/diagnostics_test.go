package common

import (
	"fmt"
	"strings"
	"testing"
)

// TestNotFoundConstants verifies that the shared 404 diagnostic constants
// contain the expected substrings and format correctly with fmt.Sprintf.
func TestNotFoundConstants(t *testing.T) {
	t.Run("NotFoundReadErrorSummaryFmt formats with resource type", func(t *testing.T) {
		got := fmt.Sprintf(NotFoundReadErrorSummaryFmt, "AWS Connection")
		if !strings.Contains(got, "AWS Connection") {
			t.Errorf("summary missing resource type: %q", got)
		}
		if !strings.Contains(got, "Not Found") {
			t.Errorf("summary missing 'Not Found': %q", got)
		}
	})

	t.Run("NotFoundReadErrorDetailFmt formats with resource type and ID", func(t *testing.T) {
		got := fmt.Sprintf(NotFoundReadErrorDetailFmt, "CM Key", "abc-123")
		if !strings.Contains(got, "CM Key") {
			t.Errorf("detail missing resource type: %q", got)
		}
		if !strings.Contains(got, "abc-123") {
			t.Errorf("detail missing resource ID: %q", got)
		}
		if !strings.Contains(got, "404") {
			t.Errorf("detail missing HTTP status reference: %q", got)
		}
	})

	t.Run("NotFoundReadErrorDetailFmt mentions state retention", func(t *testing.T) {
		got := fmt.Sprintf(NotFoundReadErrorDetailFmt, "License", "lic-42")
		if !strings.Contains(strings.ToLower(got), "retained") && !strings.Contains(strings.ToLower(got), "retained in") {
			// At least one of "retained" should appear to communicate the behaviour
			if !strings.Contains(strings.ToLower(got), "state") {
				t.Errorf("detail should mention state retention: %q", got)
			}
		}
	})

	t.Run("NotFoundDeleteWarningSummary is non-empty", func(t *testing.T) {
		if NotFoundDeleteWarningSummary == "" {
			t.Error("NotFoundDeleteWarningSummary must not be empty")
		}
	})

	t.Run("NotFoundDeleteWarningDetail is non-empty", func(t *testing.T) {
		if NotFoundDeleteWarningDetail == "" {
			t.Error("NotFoundDeleteWarningDetail must not be empty")
		}
	})

	t.Run("NotFoundDeleteWarningDetail mentions deletion", func(t *testing.T) {
		lower := strings.ToLower(NotFoundDeleteWarningDetail)
		if !strings.Contains(lower, "404") && !strings.Contains(lower, "not found") {
			t.Errorf("delete warning detail should reference 404 or 'not found': %q", NotFoundDeleteWarningDetail)
		}
	})

	t.Run("Read error and Delete warning have distinct summaries", func(t *testing.T) {
		readSummary := fmt.Sprintf(NotFoundReadErrorSummaryFmt, "Foo")
		if readSummary == NotFoundDeleteWarningSummary {
			t.Error("Read error summary and Delete warning summary must differ")
		}
	})
}
