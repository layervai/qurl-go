//go:build windows

package qurl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsPinnedOpenAttempts = 32
	windowsLockRetryInterval  = 25 * time.Millisecond
	windowsFileCreated        = uintptr(2)
	windowsFileAllAccess      = windows.ACCESS_MASK(0x001f01ff)
)

type pinnedStateDirHooks struct {
	syncFD func(int) error
}

var defaultPinnedStateDirHooks = pinnedStateDirHooks{
	syncFD: func(fd int) error {
		return windows.FlushFileBuffers(windows.Handle(uintptr(fd)))
	},
}

type windowsACLHeader struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	ACECount uint16
	Sbz2     uint16
}

type windowsFileRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

type windowsFileDispositionInformation struct {
	DeleteFile byte
}

type pinnedStateDirImpl struct {
	mu sync.Mutex

	path       string
	handles    []windows.Handle
	handle     windows.Handle
	identity   pinnedFileIdentity
	currentSID *windows.SID
	secureSD   *windows.SECURITY_DESCRIPTOR
	hooks      pinnedStateDirHooks

	activeLockHandle windows.Handle
	activeLockName   string
	activeLockToken  *pinnedSetupLockToken
	activeEntries    map[string]pinnedFileIdentity
}

type pinnedFileIdentity struct {
	volume uint32
	index  uint64
	exists bool
}

func canonicalPinnedStatePath(path string) string {
	return filepath.Clean(path)
}

func currentWindowsStateSecurity() (*windows.SID, *windows.SECURITY_DESCRIPTOR, error) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, nil, fmt.Errorf("read current Windows user SID: %w", err)
	}
	sid, err := windows.StringToSid(user.User.Sid.String())
	if err != nil {
		return nil, nil, fmt.Errorf("copy current Windows user SID: %w", err)
	}
	sidText := sid.String()
	sd, err := windows.SecurityDescriptorFromString(fmt.Sprintf(
		"O:%sG:%sD:P(A;;FA;;;%s)(A;;FA;;;SY)(A;;FA;;;BA)", sidText, sidText, sidText))
	if err != nil {
		return nil, nil, fmt.Errorf("build protected Windows state ACL: %w", err)
	}
	return sid, sd, nil
}

func windowsNTPath(path string) (string, error) {
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, `\\?\`) || strings.HasPrefix(clean, `\\.\`) {
		return "", errors.New("Windows device namespace paths are not supported")
	}
	volume := filepath.VolumeName(clean)
	if volume == "" || !filepath.IsAbs(clean) {
		return "", errors.New("Windows state path must be absolute")
	}
	if strings.HasPrefix(volume, `\\`) {
		return `\??\UNC\` + strings.TrimPrefix(clean, `\\`), nil
	}
	return `\??\` + clean, nil
}

func windowsRelativeName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return errors.New("invalid Windows state entry name")
	}
	return nil
}

func ntOpenWindowsObject(root windows.Handle, name string, access uint32, disposition uint32,
	options uint32, sd *windows.SECURITY_DESCRIPTOR,
) (windows.Handle, bool, error) {
	if root != 0 {
		if err := windowsRelativeName(name); err != nil {
			return windows.InvalidHandle, false, err
		}
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, false, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		RootDirectory: root, ObjectName: objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: sd,
	}
	oa.Length = uint32(unsafe.Sizeof(*oa))
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	allocation := int64(0)
	err = windows.NtCreateFile(&handle, access, oa, &iosb, &allocation,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		disposition, options|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT,
		0, 0)
	if err != nil {
		return windows.InvalidHandle, false, err
	}
	return handle, iosb.Information == windowsFileCreated, nil
}

func windowsNotFound(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND)
}

func windowsNameCollision(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) || errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

func windowsHandleIdentity(handle windows.Handle) (pinnedFileIdentity, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return pinnedFileIdentity{}, info, err
	}
	identity := pinnedFileIdentity{
		volume: info.VolumeSerialNumber,
		index:  uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow),
		exists: true,
	}
	return identity, info, nil
}

func (d *pinnedStateDirImpl) validateSecureACL(handle windows.Handle, label string) error {
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return fmt.Errorf("%w: read %s ACL: %w", ErrAgentStateContinuity, label, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !owner.Equals(d.currentSID) {
		return fmt.Errorf("%w: %s is not owned by the current Windows user", ErrAgentStateContinuity, label)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: %w: %s ACL must be protected from inheritance",
			ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: %w: %s has no restrictive DACL",
			ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label)
	}
	adminSID, adminErr := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	systemSID, systemErr := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if adminErr != nil || systemErr != nil {
		return fmt.Errorf("%w: build trusted Windows SIDs", ErrAgentStateContinuity)
	}
	header := (*windowsACLHeader)(unsafe.Pointer(dacl))
	var userMask windows.ACCESS_MASK
	for index := uint32(0); index < uint32(header.ACECount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return fmt.Errorf("%w: inspect %s DACL entry %d: %w", ErrAgentStateContinuity, label, index, err)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			return fmt.Errorf("%w: %w: %s has an unsupported deny ACE",
				ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			return fmt.Errorf("%w: %w: %s has an unsupported access-allow ACE",
				ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label)
		}
		if ace.Header.AceFlags != 0 {
			return fmt.Errorf("%w: %w: %s has an inherited or inherit-only ACE",
				ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return fmt.Errorf("%w: %s has an invalid DACL SID", ErrAgentStateContinuity, label)
		}
		switch {
		case sid.Equals(d.currentSID):
			userMask |= ace.Mask
		case sid.Equals(adminSID), sid.Equals(systemSID):
		default:
			return fmt.Errorf("%w: %w: %s grants access to another Windows principal",
				ErrAgentStateContinuity, ErrInsecureAgentStatePermissions, label)
		}
	}
	if userMask&windowsFileAllAccess != windowsFileAllAccess && userMask&windows.GENERIC_ALL == 0 {
		return fmt.Errorf("%w: %s does not grant the current Windows user full control",
			ErrAgentStateContinuity, label)
	}
	return nil
}

func validateWindowsDirectoryHandle(handle windows.Handle, label string) (pinnedFileIdentity, error) {
	identity, info, err := windowsHandleIdentity(handle)
	if err != nil {
		return pinnedFileIdentity{}, fmt.Errorf("%w: stat %s: %w", ErrAgentStateContinuity, label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return pinnedFileIdentity{}, fmt.Errorf("%w: %s must be a non-reparse directory", ErrAgentStateContinuity, label)
	}
	return identity, nil
}

func (d *pinnedStateDirImpl) validateWindowsFileHandle(handle windows.Handle, label string) (pinnedFileIdentity, error) {
	identity, info, err := windowsHandleIdentity(handle)
	if err != nil {
		return pinnedFileIdentity{}, fmt.Errorf("%w: stat %s: %w", ErrAgentStateContinuity, label, err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return pinnedFileIdentity{}, fmt.Errorf("%w: %s must be a non-reparse regular file", ErrAgentStateContinuity, label)
	}
	if info.NumberOfLinks != 1 {
		return pinnedFileIdentity{}, fmt.Errorf("%w: %s link count is %d, want 1",
			ErrAgentStateContinuity, label, info.NumberOfLinks)
	}
	if err := d.validateSecureACL(handle, label); err != nil {
		return pinnedFileIdentity{}, err
	}
	return identity, nil
}

func windowsPathComponents(path string) (string, []string, error) {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	if volume == "" || !filepath.IsAbs(clean) {
		return "", nil, errors.New("Windows state directory must be absolute")
	}
	root := volume + string(filepath.Separator)
	rel, err := filepath.Rel(root, clean)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", nil, errors.New("Windows state directory must be below a volume root")
	}
	components := strings.Split(rel, string(filepath.Separator))
	for _, component := range components {
		if err := windowsRelativeName(component); err != nil {
			return "", nil, err
		}
	}
	return root, components, nil
}

func openWindowsDirectoryAbsolute(path string, access uint32) (windows.Handle, error) {
	ntPath, err := windowsNTPath(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	handle, _, err := ntOpenWindowsObject(0, ntPath, access, windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE, nil)
	return handle, err
}

func closeWindowsHandles(handles []windows.Handle) error {
	var result error
	for index := len(handles) - 1; index >= 0; index-- {
		if handles[index] == windows.InvalidHandle || handles[index] == 0 {
			continue
		}
		if err := windows.CloseHandle(handles[index]); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func reopenWindowsWalkParent(handles []windows.Handle, root string, components []string, index int,
	access uint32,
) (windows.Handle, error) {
	var handle windows.Handle
	var err error
	if index == 0 {
		handle, err = openWindowsDirectoryAbsolute(root, access)
	} else {
		handle, _, err = ntOpenWindowsObject(handles[index-1], components[index-1], access,
			windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
	}
	if err != nil {
		return windows.InvalidHandle, err
	}
	want, _, wantErr := windowsHandleIdentity(handles[index])
	got, _, gotErr := windowsHandleIdentity(handle)
	if wantErr != nil || gotErr != nil || want != got {
		_ = windows.CloseHandle(handle)
		return windows.InvalidHandle, fmt.Errorf("%w: Windows state ancestor changed before directory creation",
			ErrAgentStateContinuity)
	}
	return handle, nil
}

func openWindowsPinnedWalk(path string, mode pinnedStateDirOpenMode, currentSID *windows.SID,
	secureSD *windows.SECURITY_DESCRIPTOR,
) ([]windows.Handle, error) {
	root, components, err := windowsPathComponents(path)
	if err != nil {
		return nil, err
	}
	rootAccess := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES |
		windows.READ_CONTROL | windows.SYNCHRONIZE)
	rootHandle, err := openWindowsDirectoryAbsolute(root, rootAccess)
	if err != nil {
		return nil, fmt.Errorf("%w: open Windows state volume root: %w", ErrAgentStateContinuity, err)
	}
	handles := []windows.Handle{rootHandle}
	cleanup := func(cause error) ([]windows.Handle, error) {
		return nil, errors.Join(cause, closeWindowsHandles(handles))
	}
	if _, err := validateWindowsDirectoryHandle(rootHandle, "Windows state volume root"); err != nil {
		return cleanup(err)
	}
	for index, component := range components {
		last := index == len(components)-1
		access := rootAccess
		if last && mode == pinnedStateDirWritable {
			access = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.READ_CONTROL | windows.SYNCHRONIZE
		}
		parent := handles[len(handles)-1]
		handle, created, openErr := ntOpenWindowsObject(parent, component, access,
			windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
		if openErr != nil && windowsNotFound(openErr) && mode == pinnedStateDirWritable {
			parentIndex := len(handles) - 1
			writableParent, reopenErr := reopenWindowsWalkParent(handles, root, components, parentIndex,
				windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE)
			if reopenErr != nil {
				return cleanup(fmt.Errorf("%w: open Windows state parent for creation: %w",
					ErrAgentStateContinuity, reopenErr))
			}
			_ = windows.CloseHandle(handles[parentIndex])
			handles[parentIndex] = writableParent
			parent = writableParent
			for attempt := 0; attempt < windowsPinnedOpenAttempts; attempt++ {
				handle, created, openErr = ntOpenWindowsObject(parent, component, access,
					windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, secureSD)
				if openErr == nil {
					break
				}
				if !windowsNameCollision(openErr) {
					break
				}
				handle, created, openErr = ntOpenWindowsObject(parent, component, access,
					windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
				if openErr == nil || !windowsNotFound(openErr) {
					break
				}
			}
		}
		if openErr != nil {
			return cleanup(fmt.Errorf("%w: open Windows state directory component: %w",
				ErrAgentStateContinuity, openErr))
		}
		if _, err := validateWindowsDirectoryHandle(handle, "Windows state directory component"); err != nil {
			_ = windows.CloseHandle(handle)
			return cleanup(err)
		}
		if created {
			if err := windows.FlushFileBuffers(parent); err != nil {
				_ = windows.CloseHandle(handle)
				return cleanup(fmt.Errorf("%w: sync new Windows state directory parent: %w",
					ErrAgentStateContinuity, err))
			}
		}
		handles = append(handles, handle)
	}
	if len(handles) < 2 {
		return cleanup(fmt.Errorf("%w: Windows state directory cannot be a volume root", ErrAgentStateContinuity))
	}
	probe := &pinnedStateDirImpl{currentSID: currentSID}
	if err := probe.validateSecureACL(handles[len(handles)-1], "Windows state directory"); err != nil {
		return cleanup(err)
	}
	return handles, nil
}

func openPinnedStateDir(path, label string, mode pinnedStateDirOpenMode) (*pinnedStateDirImpl, error) {
	if mode != pinnedStateDirWritable && mode != pinnedStateDirReadOnly {
		return nil, fmt.Errorf("%w: invalid %s directory open mode", ErrInvalidBootstrapConfig, label)
	}
	currentSID, secureSD, err := currentWindowsStateSecurity()
	if err != nil {
		return nil, fmt.Errorf("%w: prepare %s Windows ACL: %w", ErrAgentStateContinuity, label, err)
	}
	handles, err := openWindowsPinnedWalk(path, mode, currentSID, secureSD)
	if err != nil {
		return nil, err
	}
	final := handles[len(handles)-1]
	identity, err := validateWindowsDirectoryHandle(final, label+" directory")
	if err != nil {
		_ = closeWindowsHandles(handles)
		return nil, err
	}
	impl := &pinnedStateDirImpl{
		path: path, handles: handles, handle: final, identity: identity,
		currentSID: currentSID, secureSD: secureSD, hooks: defaultPinnedStateDirHooks,
		activeLockHandle: windows.InvalidHandle,
	}
	if err := impl.validateSecureACL(final, label+" directory"); err != nil {
		_ = closeWindowsHandles(handles)
		return nil, err
	}
	return impl, nil
}

func (d *pinnedStateDirImpl) close() error {
	return closeWindowsHandles(d.handles)
}

func (d *pinnedStateDirImpl) validateInitialEntry(name, label string) error {
	_, err := d.captureEntry(name, label)
	return err
}

func (d *pinnedStateDirImpl) validateContinuity() error {
	current, err := validateWindowsDirectoryHandle(d.handle, "retained Windows state directory")
	if err != nil {
		return err
	}
	if current != d.identity {
		return fmt.Errorf("%w: retained Windows state directory identity changed", ErrAgentStateContinuity)
	}
	if err := d.validateSecureACL(d.handle, "Windows state directory"); err != nil {
		return err
	}
	handles, err := openWindowsPinnedWalk(d.path, pinnedStateDirReadOnly, d.currentSID, d.secureSD)
	if err != nil {
		return fmt.Errorf("%w: reopen Windows state directory: %w", ErrAgentStateContinuity, err)
	}
	reopened, _, identityErr := windowsHandleIdentity(handles[len(handles)-1])
	closeErr := closeWindowsHandles(handles)
	if identityErr != nil || reopened != d.identity {
		return errors.Join(fmt.Errorf("%w: Windows state directory namespace was replaced", ErrAgentStateContinuity), closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("%w: close reopened Windows state directory: %w", ErrAgentStateContinuity, closeErr)
	}
	d.mu.Lock()
	lockHandle, lockName := d.activeLockHandle, d.activeLockName
	activeEntries := make(map[string]pinnedFileIdentity, len(d.activeEntries))
	for name, identity := range d.activeEntries {
		activeEntries[name] = identity
	}
	d.mu.Unlock()
	if lockHandle != windows.InvalidHandle {
		if err := d.validateOpenEntry(lockHandle, lockName, "agent setup lock"); err != nil {
			return err
		}
		for name, expected := range activeEntries {
			current, err := d.captureEntry(name, "active agent state")
			if err != nil {
				return err
			}
			if current != expected {
				return fmt.Errorf("%w: state entry changed while the setup lock was held", ErrAgentStateContinuity)
			}
		}
	}
	return nil
}

func (d *pinnedStateDirImpl) openFile(name string, access, disposition uint32,
	sd *windows.SECURITY_DESCRIPTOR,
) (windows.Handle, bool, error) {
	return ntOpenWindowsObject(d.handle, name, access, disposition, windows.FILE_NON_DIRECTORY_FILE, sd)
}

func (d *pinnedStateDirImpl) validateOpenEntry(handle windows.Handle, name, label string) error {
	opened, err := d.validateWindowsFileHandle(handle, label)
	if err != nil {
		return err
	}
	reopened, _, err := d.openFile(name, windows.FILE_GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_OPEN, nil)
	if err != nil {
		return fmt.Errorf("%w: reopen %s directory entry: %w", ErrAgentStateContinuity, label, err)
	}
	defer func() { _ = windows.CloseHandle(reopened) }()
	current, err := d.validateWindowsFileHandle(reopened, label)
	if err != nil {
		return err
	}
	if opened != current {
		return fmt.Errorf("%w: opened %s no longer matches its directory entry", ErrAgentStateContinuity, label)
	}
	return nil
}

func (d *pinnedStateDirImpl) readFile(name, label string, maxBytes int, notFound error) ([]byte, error) {
	if err := d.validateContinuity(); err != nil {
		return nil, err
	}
	handle, _, err := d.openFile(name, windows.FILE_GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_OPEN, nil)
	if err != nil {
		if windowsNotFound(err) {
			if err := d.trackActiveEntry(name, pinnedFileIdentity{}); err != nil {
				return nil, err
			}
			return nil, notFound
		}
		return nil, fmt.Errorf("qurl: open %s: %w", label, err)
	}
	file := os.NewFile(uintptr(handle), label)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("qurl: create %s file handle", label)
	}
	defer func() { _ = file.Close() }()
	if err := d.validateOpenEntry(handle, name, label); err != nil {
		return nil, err
	}
	identity, _, err := windowsHandleIdentity(handle)
	if err != nil {
		return nil, fmt.Errorf("%w: capture opened %s identity: %w", ErrAgentStateContinuity, label, err)
	}
	if err := d.trackActiveEntry(name, identity); err != nil {
		return nil, err
	}
	raw, err := readCappedBody(file, maxBytes, label)
	if err != nil {
		var tooLarge *inputExceedsCapError
		if errors.As(err, &tooLarge) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidAgentState, err)
		}
		return nil, fmt.Errorf("qurl: %w", err)
	}
	if err := d.validateOpenEntry(handle, name, label); err != nil {
		return nil, err
	}
	if err := d.validateContinuity(); err != nil {
		return nil, err
	}
	return raw, nil
}

func (d *pinnedStateDirImpl) captureEntry(name, label string) (pinnedFileIdentity, error) {
	handle, _, err := d.openFile(name, windows.FILE_GENERIC_READ|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_OPEN, nil)
	if err != nil {
		if windowsNotFound(err) {
			return pinnedFileIdentity{}, nil
		}
		return pinnedFileIdentity{}, fmt.Errorf("%w: open existing %s: %w", ErrAgentStateContinuity, label, err)
	}
	defer func() { _ = windows.CloseHandle(handle) }()
	if err := d.validateOpenEntry(handle, name, label); err != nil {
		return pinnedFileIdentity{}, err
	}
	identity, _, err := windowsHandleIdentity(handle)
	return identity, err
}

func renameWindowsHandle(handle, root windows.Handle, name string) error {
	nameUTF16, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	nameLength := (len(nameUTF16) - 1) * 2
	var shape windowsFileRenameInformation
	bufferSize := int(unsafe.Offsetof(shape.FileName)) + nameLength
	buffer := make([]byte, bufferSize)
	info := (*windowsFileRenameInformation)(unsafe.Pointer(&buffer[0]))
	info.ReplaceIfExists = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	info.RootDirectory = root
	info.FileNameLength = uint32(nameLength)
	destination := unsafe.Slice(&info.FileName[0], nameLength/2)
	copy(destination, nameUTF16[:len(nameUTF16)-1])
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(handle, &iosb, &buffer[0], uint32(bufferSize), windows.FileRenameInformation)
}

func deleteWindowsHandleOnClose(handle windows.Handle) error {
	info := windowsFileDispositionInformation{DeleteFile: 1}
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(handle, &iosb, (*byte)(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)), windows.FileDispositionInformation)
}

func (d *pinnedStateDirImpl) createExclusiveTemp(prefix, label string) (string, windows.Handle, error) {
	for range windowsPinnedOpenAttempts {
		var suffix [16]byte
		if _, err := io.ReadFull(rand.Reader, suffix[:]); err != nil {
			return "", windows.InvalidHandle, fmt.Errorf("qurl: generate temp %s name: %w", label, err)
		}
		name := prefix + hex.EncodeToString(suffix[:])
		handle, _, err := d.openFile(name,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE|windows.READ_CONTROL|windows.SYNCHRONIZE,
			windows.FILE_CREATE, d.secureSD)
		if err == nil {
			return name, handle, nil
		}
		if !windowsNameCollision(err) {
			return "", windows.InvalidHandle, fmt.Errorf("qurl: create temp %s: %w", label, err)
		}
	}
	return "", windows.InvalidHandle, fmt.Errorf("qurl: create temp %s after %d attempts", label, windowsPinnedOpenAttempts)
}

func (d *pinnedStateDirImpl) writeFileAtomic(ctx context.Context, token *pinnedSetupLockToken,
	name, label, tempPrefix string, raw []byte,
) (resultErr error) {
	if !d.ownsSetupLock(token) {
		return fmt.Errorf("%w: %s write requires the active setup lock", ErrAgentSetupLock, label)
	}
	if err := d.validateContinuity(); err != nil {
		return err
	}
	baseline, err := d.captureEntry(name, label)
	if err != nil {
		return err
	}
	if err := d.trackActiveEntry(name, baseline); err != nil {
		return err
	}
	tempName, handle, err := d.createExclusiveTemp(tempPrefix, label)
	if err != nil {
		return err
	}
	tempExists := true
	file := os.NewFile(uintptr(handle), tempName)
	if file == nil {
		_ = deleteWindowsHandleOnClose(handle)
		_ = windows.CloseHandle(handle)
		return fmt.Errorf("qurl: create temp %s handle", label)
	}
	defer func() {
		var deleteErr error
		if tempExists {
			deleteErr = deleteWindowsHandleOnClose(handle)
			if deleteErr != nil && !windowsNotFound(deleteErr) {
				resultErr = errors.Join(resultErr, fmt.Errorf("qurl: remove temp %s: %w", label, deleteErr))
			}
		}
		if err := file.Close(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("qurl: close temp %s: %w", label, err))
		}
		// Deletion becomes durable only after the delete-on-close handle is
		// closed. An ambiguous disposition receives the same directory flush
		// as the Unix backend because it may already have removed the name.
		if tempExists && !windowsNotFound(deleteErr) {
			if syncErr := d.hooks.syncFD(int(d.handle)); syncErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("qurl: sync temp %s cleanup: %w", label, syncErr))
			}
		}
	}()
	if err := d.validateOpenEntry(handle, tempName, "temp "+label); err != nil {
		return err
	}
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("qurl: write temp %s: %w", label, err)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return fmt.Errorf("qurl: sync temp %s: %w", label, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := d.validateContinuity(); err != nil {
		return err
	}
	if err := d.validateOpenEntry(handle, tempName, "temp "+label); err != nil {
		return err
	}
	current, err := d.captureEntry(name, label)
	if err != nil {
		return err
	}
	if current != baseline {
		return fmt.Errorf("%w: %s entry changed before commit", ErrAgentStateContinuity, label)
	}
	if err := d.trackActiveEntry(name, current); err != nil {
		return err
	}
	if err := renameWindowsHandle(handle, d.handle, name); err != nil {
		return fmt.Errorf("qurl: replace %s: %w", label, err)
	}
	tempExists = false
	if err := d.hooks.syncFD(int(d.handle)); err != nil {
		return fmt.Errorf("qurl: sync %s directory: %w", label, err)
	}
	if err := d.validateOpenEntry(handle, name, label); err != nil {
		return err
	}
	committed, _, err := windowsHandleIdentity(handle)
	if err != nil {
		return fmt.Errorf("%w: capture committed %s identity: %w", ErrAgentStateContinuity, label, err)
	}
	d.updateActiveEntry(name, committed)
	if err := d.validateContinuity(); err != nil {
		return err
	}
	return nil
}

func (d *pinnedStateDirImpl) trackActiveEntry(name string, identity pinnedFileIdentity) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activeLockHandle == windows.InvalidHandle {
		return nil
	}
	if previous, ok := d.activeEntries[name]; ok && previous != identity {
		return fmt.Errorf("%w: state entry changed while the setup lock was held", ErrAgentStateContinuity)
	}
	if d.activeEntries == nil {
		d.activeEntries = make(map[string]pinnedFileIdentity)
	}
	d.activeEntries[name] = identity
	return nil
}

func (d *pinnedStateDirImpl) updateActiveEntry(name string, identity pinnedFileIdentity) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.activeLockHandle == windows.InvalidHandle {
		return
	}
	d.activeEntries[name] = identity
}

type pinnedSetupLock struct {
	file       *os.File
	dir        *pinnedStateDirImpl
	name       string
	lease      *pinnedStateDirLease
	token      *pinnedSetupLockToken
	overlapped windows.Overlapped
}

func (l *pinnedSetupLock) bindStore(store AgentStateStore) AgentStateStore {
	if decorator, ok := store.(agentStateStoreDecorator); ok {
		bound := l.bindStore(decorator.decoratedAgentStateStore())
		return decorator.withDecoratedAgentStateStore(bound)
	}
	retained, ok := store.(*retainedLocalAgentStateStore)
	if !ok || l == nil || l.token == nil {
		return store
	}
	return retained.withSetup(l.token)
}

func (d *pinnedStateDirImpl) ownsSetupLock(token *pinnedSetupLockToken) bool {
	if token == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.activeLockHandle != windows.InvalidHandle && d.activeLockToken == token
}

func (d *pinnedStateDir) lock(ctx context.Context, name string) (setupLock, error) {
	lease, err := d.retain()
	if err != nil {
		return nil, err
	}
	impl := lease.dir.impl
	lock, err := impl.acquireLock(ctx, name, lease)
	if err != nil {
		_ = lease.release()
		return nil, err
	}
	return lock, nil
}

func (d *pinnedStateDir) lockWithImpl(ctx context.Context, name string, impl *pinnedStateDirImpl) (setupLock, error) {
	if d == nil || impl == nil {
		return nil, fmt.Errorf("%w: retained state directory is nil", ErrAgentStateContinuity)
	}
	d.mu.Lock()
	same := d.impl == impl && !d.closed
	d.mu.Unlock()
	if !same {
		return nil, fmt.Errorf("%w: retained state directory changed", ErrAgentStateContinuity)
	}
	return impl.acquireLock(ctx, name, nil)
}

func (d *pinnedStateDirImpl) openLock(name string) (windows.Handle, error) {
	for range windowsPinnedOpenAttempts {
		handle, _, err := d.openFile(name,
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
			windows.FILE_OPEN_IF, d.secureSD)
		if err == nil {
			return handle, nil
		}
		if !windowsNameCollision(err) {
			return windows.InvalidHandle, err
		}
	}
	return windows.InvalidHandle, fmt.Errorf("setup lock file changed during %d open attempts", windowsPinnedOpenAttempts)
}

func (d *pinnedStateDirImpl) acquireLock(ctx context.Context, name string,
	lease *pinnedStateDirLease,
) (setupLock, error) {
	if err := d.validateContinuity(); err != nil {
		return nil, err
	}
	handle, err := d.openLock(name)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), name)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("create agent setup lock file handle")
	}
	fail := func(cause error) error {
		if closeErr := file.Close(); closeErr != nil {
			cause = errors.Join(cause, fmt.Errorf("close rejected agent setup lock: %w", closeErr))
		}
		return cause
	}
	if err := d.validateOpenEntry(handle, name, "agent setup lock"); err != nil {
		return nil, fail(err)
	}
	if err := windows.FlushFileBuffers(handle); err != nil {
		return nil, fail(fmt.Errorf("sync agent setup lock: %w", err))
	}
	if err := d.hooks.syncFD(int(d.handle)); err != nil {
		return nil, fail(fmt.Errorf("sync agent setup lock directory: %w", err))
	}
	var retry *time.Timer
	defer func() {
		if retry != nil {
			retry.Stop()
		}
	}()
	var overlapped windows.Overlapped
	for {
		if err := ctx.Err(); err != nil {
			return nil, fail(err)
		}
		err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0, 1, 0, &overlapped)
		if err == nil {
			if err := d.validateOpenEntry(handle, name, "agent setup lock"); err != nil {
				_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
				return nil, fail(err)
			}
			if err := d.validateContinuity(); err != nil {
				_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
				return nil, fail(err)
			}
			d.mu.Lock()
			if d.activeLockHandle != windows.InvalidHandle {
				d.mu.Unlock()
				_ = windows.UnlockFileEx(handle, 0, 1, 0, &overlapped)
				return nil, fail(fmt.Errorf("%w: state store already owns an active setup lock", ErrAgentSetupLock))
			}
			token := &pinnedSetupLockToken{impl: d}
			d.activeLockHandle = handle
			d.activeLockName = name
			d.activeLockToken = token
			d.activeEntries = make(map[string]pinnedFileIdentity)
			d.mu.Unlock()
			return &pinnedSetupLock{file: file, dir: d, name: name, lease: lease,
				token: token, overlapped: overlapped}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return nil, fail(err)
		}
		if retry == nil {
			retry = time.NewTimer(windowsLockRetryInterval)
		} else {
			retry.Reset(windowsLockRetryInterval)
		}
		select {
		case <-ctx.Done():
			return nil, fail(ctx.Err())
		case <-retry.C:
		}
	}
}

func (l *pinnedSetupLock) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	handle := windows.Handle(l.file.Fd())
	var result error
	if err := l.dir.validateOpenEntry(handle, l.name, "agent setup lock"); err != nil {
		result = err
	}
	if err := l.dir.validateContinuity(); err != nil {
		result = errors.Join(result, err)
	}
	l.dir.mu.Lock()
	if l.dir.activeLockHandle == handle && l.dir.activeLockName == l.name && l.dir.activeLockToken == l.token {
		l.dir.activeLockHandle = windows.InvalidHandle
		l.dir.activeLockName = ""
		l.dir.activeLockToken = nil
		l.dir.activeEntries = nil
	} else {
		result = errors.Join(result, fmt.Errorf("%w: active setup lock ownership changed", ErrAgentStateContinuity))
	}
	l.dir.mu.Unlock()
	if err := windows.UnlockFileEx(handle, 0, 1, 0, &l.overlapped); err != nil {
		result = errors.Join(result, err)
	}
	if err := l.file.Close(); err != nil {
		result = errors.Join(result, err)
	}
	l.file = nil
	if l.lease != nil {
		if err := l.lease.release(); err != nil {
			result = errors.Join(result, err)
		}
	}
	l.lease = nil
	return result
}
