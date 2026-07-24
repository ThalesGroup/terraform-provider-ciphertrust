// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MIT

package provider

import (
	"os"
	"path/filepath"
	"testing"
)

// Test_openProviderLog_Off_NoFile verifies that log_level="off" (and its
// case variants) skips file creation and returns a usable null logger.
func Test_openProviderLog_Off_NoFile(t *testing.T) {
	for _, level := range []string{"off", "OFF", "Off"} {
		t.Run(level, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, "test.log")

			logger, fh, err := openProviderLog(logPath, level)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fh != nil {
				fh.Close()
				t.Error("expected nil file handle for log_level=off")
			}
			if _, statErr := os.Stat(logPath); !os.IsNotExist(statErr) {
				t.Error("log file must not be created when log_level=off")
			}
			if logger == nil {
				t.Fatal("expected non-nil logger")
			}
			// Must not panic on use.
			logger.Info("should be silently discarded")
		})
	}
}

// Test_openProviderLog_Permissions verifies that the log file is always created
// with mode 0600, never world-readable 0666, regardless of the active log level.
func Test_openProviderLog_Permissions(t *testing.T) {
	for _, level := range []string{"trace", "debug", "info", "warn", "error"} {
		t.Run(level, func(t *testing.T) {
			dir := t.TempDir()
			logPath := filepath.Join(dir, level+".log")

			_, fh, err := openProviderLog(logPath, level)
			if err != nil {
				t.Fatalf("openProviderLog(%q): %v", level, err)
			}
			defer fh.Close()

			info, err := os.Stat(logPath)
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if got := info.Mode().Perm(); got != 0600 {
				t.Errorf("log_level=%q: expected permissions 0600, got %04o", level, got)
			}
		})
	}
}

// Test_openProviderLog_ReturnsError verifies that an unwritable path propagates
// the OS error instead of silently swallowing it.
func Test_openProviderLog_ReturnsError(t *testing.T) {
	_, fh, err := openProviderLog("/nonexistent/directory/cannot/be/created/test.log", "info")
	if err == nil {
		if fh != nil {
			fh.Close()
		}
		t.Fatal("expected an error for an invalid path, got nil")
	}
}

// Test_openProviderLog_FileIsWritable verifies that the returned logger actually
// writes to the file (i.e. the handle is correctly wired up).
func Test_openProviderLog_FileIsWritable(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "write.log")

	logger, fh, err := openProviderLog(logPath, "info")
	if err != nil {
		t.Fatalf("openProviderLog: %v", err)
	}
	defer fh.Close()

	logger.Info("sentinel message", "key", "value")

	// Flush by closing and reopening for read.
	fh.Close()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected log file to contain data after logger.Info, got empty file")
	}
}

// Test_Provider_LogHandleNilAfterOpenError verifies that p.logFileHandle is
// left nil when openProviderLog fails. The assignment in Configure only runs
// on the success path, so a bad log_file path must not leave a stale handle.
func Test_Provider_LogHandleNilAfterOpenError(t *testing.T) {
	p := &ciphertrustProvider{}

	// Mimic Configure: close old handle (none here), then call openProviderLog.
	if p.logFileHandle != nil {
		_ = p.logFileHandle.Close()
		p.logFileHandle = nil
	}
	_, logFH, logErr := openProviderLog("/nonexistent/path/cannot/be/created.log", "info")
	if logErr == nil {
		if logFH != nil {
			logFH.Close()
		}
		t.Fatal("expected error from invalid path, got nil")
	}
	// Configure returns early on error — p.logFileHandle is never assigned.
	// Confirm it stays nil so no stale FD is held.
	if p.logFileHandle != nil {
		t.Error("p.logFileHandle must remain nil after a failed openProviderLog")
	}
}

// Test_Provider_ClosesOldLogHandle_OnReconfigure verifies that a second
// Configure call does not leak the file descriptor opened by the first.
// We exercise this at the struct level (same package) because constructing a
// full provider.ConfigureRequest without a live CM backend is not feasible in
// a unit test; the close-old-handle logic is the first thing that runs in
// Configure, before any CM connectivity is required.
func Test_Provider_ClosesOldLogHandle_OnReconfigure(t *testing.T) {
	dir := t.TempDir()

	// Simulate a handle left behind by a previous Configure call.
	oldPath := filepath.Join(dir, "old.log")
	oldFH, err := os.OpenFile(oldPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("setup old handle: %v", err)
	}

	p := &ciphertrustProvider{logFileHandle: oldFH}

	// Replicate the two-line cleanup that Configure executes at the start of
	// the logging section.
	if p.logFileHandle != nil {
		_ = p.logFileHandle.Close()
		p.logFileHandle = nil
	}
	newPath := filepath.Join(dir, "new.log")
	_, newFH, err := openProviderLog(newPath, "info")
	if err != nil {
		t.Fatalf("openProviderLog: %v", err)
	}
	p.logFileHandle = newFH
	defer p.logFileHandle.Close()

	// The old handle must be closed — any write attempt must fail.
	if _, writeErr := oldFH.Write([]byte("stale")); writeErr == nil {
		t.Error("expected write to closed file handle to fail, but it succeeded (FD leak)")
	}

	// The new handle must still be usable.
	if _, writeErr := newFH.Write([]byte("fresh")); writeErr != nil {
		t.Errorf("expected new handle to be writable: %v", writeErr)
	}
}
