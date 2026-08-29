//go:build windows

package qurl

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsFileDeleteChild = windows.ACCESS_MASK(0x00000040)

func validatePrivateStateFilePermissions(path, label string, _ os.FileInfo, insecurePermissions error) error {
	handle, err := openWindowsPrivateStatePath(path, false)
	if err != nil {
		return fmt.Errorf("qurl: open %s for Windows permission validation: %w", label, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	_, info, err := windowsHandleIdentity(handle)
	if err != nil {
		return fmt.Errorf("qurl: stat %s Windows handle: %w", label, err)
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 || info.NumberOfLinks != 1 {
		return fmt.Errorf("%w: %s must be a non-reparse, single-link file", insecurePermissions, label)
	}
	return validateWindowsPrivateStateACL(handle, label, insecurePermissions, false)
}

func statPrivateStateDir(dir, label string, invalidConfig, insecurePermissions error) (os.FileInfo, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("qurl: stat %s dir: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: %s dir must be a non-reparse directory", invalidConfig, label)
	}
	handle, err := openWindowsPrivateStatePath(dir, true)
	if err != nil {
		return nil, fmt.Errorf("qurl: open %s Windows directory: %w", label, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	_, handleInfo, err := windowsHandleIdentity(handle)
	if err != nil {
		return nil, fmt.Errorf("qurl: stat %s Windows directory handle: %w", label, err)
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("%w: %s dir must be a non-reparse directory", invalidConfig, label)
	}
	if err := validateWindowsPrivateStateACL(handle, label+" directory", insecurePermissions, true); err != nil {
		return nil, err
	}
	return info, nil
}

func validatePrivateStateDir(dir, label string, invalidConfig, insecurePermissions error) error {
	_, err := statPrivateStateDir(dir, label, invalidConfig, insecurePermissions)
	return err
}

func openWindowsPrivateStatePath(path string, directory bool) (windows.Handle, error) {
	utf16Path, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	return windows.CreateFile(utf16Path, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, flags, 0)
}

func validateWindowsPrivateStateACL(handle windows.Handle, label string, insecurePermissions error, allowOtherRead bool) error {
	currentSID, _, err := currentWindowsStateSecurity()
	if err != nil {
		return fmt.Errorf("qurl: read current Windows identity for %s: %w", label, err)
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("qurl: read %s Windows ACL: %w", label, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(currentSID) {
		return fmt.Errorf("%w: %s is not owned by the current Windows user", insecurePermissions, label)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: %s has no restrictive Windows DACL", insecurePermissions, label)
	}
	adminSID, adminErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	systemSID, systemErr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if adminErr != nil || systemErr != nil {
		return errors.New("qurl: build trusted Windows security identities")
	}
	header := (*windowsACLHeader)(unsafe.Pointer(dacl))
	var userMask windows.ACCESS_MASK
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return fmt.Errorf("qurl: inspect %s Windows DACL entry %d: %w", label, index, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("%w: %s has an unsupported Windows DACL entry", insecurePermissions, label)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return fmt.Errorf("%w: %s has an invalid Windows DACL identity", insecurePermissions, label)
		}
		switch {
		case sid.Equals(currentSID):
			if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
				userMask |= ace.Mask
			}
		case sid.Equals(adminSID), sid.Equals(systemSID):
		default:
			writeMask := windows.ACCESS_MASK(windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|
				windows.FILE_WRITE_EA|windows.FILE_WRITE_ATTRIBUTES) | windowsFileDeleteChild |
				windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.GENERIC_WRITE | windows.GENERIC_ALL
			if !allowOtherRead || ace.Mask&writeMask != 0 {
				return fmt.Errorf("%w: %s grants unsafe access to another Windows principal", insecurePermissions, label)
			}
		}
	}
	if userMask&windowsFileAllAccess != windowsFileAllAccess && userMask&windows.GENERIC_ALL == 0 {
		return fmt.Errorf("%w: %s does not grant the current Windows user full control", insecurePermissions, label)
	}
	return nil
}
