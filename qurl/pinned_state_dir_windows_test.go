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

func securePrivateStateFilePlatform(t *testing.T, path string) {
	t.Helper()
	setWindowsTestACL(t, path, false)
}

func assertPrivateStatePermissionsPlatform(t *testing.T, file, dir string) {
	t.Helper()
	for _, entry := range []struct {
		path      string
		directory bool
	}{
		{path: file},
		{path: dir, directory: true},
	} {
		handle, err := openWindowsPrivateStatePath(entry.path, entry.directory)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateWindowsPrivateStateACL(handle, entry.path, ErrInsecureAgentStatePermissions, false); err != nil {
			_ = windows.CloseHandle(handle)
			t.Fatal(err)
		}
		if err := windows.CloseHandle(handle); err != nil {
			t.Fatal(err)
		}
	}
}

func makePrivateStateFileInsecurePlatform(t *testing.T, path string) {
	t.Helper()
	setWindowsTestACL(t, path, true)
}

func makePrivateStateDirInsecurePlatform(t *testing.T, path string) {
	t.Helper()
	setWindowsTestACL(t, path, true)
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

func TestPinnedAgentState_WindowsReplacementWithOpenReader(t *testing.T) {
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
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := windows.CreateFile(path16, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = windows.CloseHandle(reader) }()
	second := first.clone()
	second.DeviceAPIKey = "lv_device_windows_open_reader"
	if err := store.SaveAgentState(context.Background(), second); err != nil {
		t.Fatalf("atomic replacement with an open reader: %v", err)
	}
	loaded, err := store.LoadAgentState(context.Background())
	if err != nil || loaded.DeviceAPIKey != second.DeviceAPIKey {
		t.Fatalf("replacement state = %+v, %v", loaded, err)
	}
}

func TestPinnedAgentState_WindowsDoesNotPinAncestors(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Join(base, "qurl")
	path := filepath.Join(ancestor, "connector", "agent.json")
	store, err := OpenFileAgentState(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SaveAgentState(context.Background(), testAgentState(t)); err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(base, "qurl-renamed")
	if err := os.Rename(ancestor, renamed); err != nil {
		t.Fatalf("retained state store pinned an ancestor against rename: %v", err)
	}
	if err := store.ValidateContinuity(); !errors.Is(err, ErrAgentStateContinuity) {
		t.Fatalf("continuity after ancestor rename = %v, want failure", err)
	}
}

func TestPinnedAgentState_WindowsRejectsUntrustedAncestorControl(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Join(base, "qurl")
	stateDir := filepath.Join(ancestor, "connector")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestACL(t, ancestor, true)
	setWindowsTestACL(t, stateDir, false)
	if _, err := OpenFileAgentState(filepath.Join(stateDir, "agent.json")); !errors.Is(err, ErrAgentStateContinuity) || !errors.Is(err, ErrInsecureAgentStatePermissions) {
		t.Fatalf("untrusted ancestor open = %v, want insecure continuity failure", err)
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
