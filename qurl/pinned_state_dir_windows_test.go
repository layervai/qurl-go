//go:build windows

package qurl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func secureAgentStateTestDirPlatform(t *testing.T, dir string) {
	t.Helper()
	setWindowsTestACL(t, dir, false)
}

func setWindowsTestACL(t *testing.T, path string, includeWorld bool) {
	t.Helper()
	currentSID, _, err := currentWindowsStateSecurity()
	if err != nil {
		t.Fatal(err)
	}
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	systemSID, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	entries := []windows.EXPLICIT_ACCESS{
		windowsTestAccess(currentSID, windows.GENERIC_ALL),
		windowsTestAccess(adminSID, windows.GENERIC_ALL),
		windowsTestAccess(systemSID, windows.GENERIC_ALL),
	}
	if includeWorld {
		worldSID, err := windows.CreateWellKnownSid(windows.WinWorldSid)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, windowsTestAccess(worldSID, windows.GENERIC_READ))
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

func windowsTestAccess(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

func TestPinnedAgentState_WindowsRoundTripAndAtomicReplacement(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "qurl", "connector")
	path := filepath.Join(stateDir, "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	first := testAgentState(t)
	if err := store.SaveAgentState(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second := first.clone()
	second.DeviceAPIKey = "lv_device_windows_replacement"
	if err := store.SaveAgentState(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceAPIKey != second.DeviceAPIKey {
		t.Fatalf("device credential = %q, want replacement", loaded.DeviceAPIKey)
	}
	if matches, err := filepath.Glob(filepath.Join(stateDir, ".qurl-agent-state-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary state entries = %v, error = %v", matches, err)
	}
	if err := store.ValidateContinuity(); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedAgentState_WindowsLockSerializesAndCancels(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector", "agent.json")
	first, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })

	hold, err := first.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := second.acquireSetupLock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("contended acquire = %v, want deadline exceeded", err)
	}
	if err := hold.Close(); err != nil {
		t.Fatal(err)
	}
	acquired, err := second.acquireSetupLock(context.Background())
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := acquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestPinnedAgentState_WindowsRejectsHardlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector", "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, path+".hardlink"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("hard-linked state load = %v, want continuity failure", err)
	}
}

func TestPinnedAgentState_WindowsRejectsInsecureDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "qurl", "connector", "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	setWindowsTestACL(t, path, true)
	if _, err := store.LoadAgentState(context.Background()); !errors.Is(err, ErrAgentStateContinuity) ||
		!errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("insecure state load = %v, want insecure continuity failure", err)
	}
}

func TestPinnedAgentState_WindowsRejectsReparseEntry(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "qurl", "connector")
	path := filepath.Join(stateDir, "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(stateDir, "target.json")
	if err := os.Rename(path, target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
			t.Skip("Windows runner does not permit symlink creation")
		}
		t.Fatal(err)
	}
	if _, err := OpenFileAgentState(path); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("reparse state open = %v, want continuity failure", err)
	}
}
