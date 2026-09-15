//go:build windows

package sessiondir

import (
	"errors"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// replaceFile moves from onto to, replacing whatever is there.
//
// os.Rename is MoveFileEx(MOVEFILE_REPLACE_EXISTING), which cannot replace a
// destination another process holds open, and FILE_SHARE_DELETE does not buy
// its way past that: sharing delete lets the destination be marked for
// deletion, but the name stays in the directory until the last handle closes,
// and the rename needs the name now. Publishing a session record is exactly
// that situation — a reader reopens the record continuously — so the retries
// were not waiting out a race, they were losing every attempt of it.
//
// A rename with POSIX semantics does what the name promises and what every
// other platform does: the destination's name goes away now, its existing
// handles stay valid until they are closed, and no reader is ever shown a
// half-written record. It needs Windows 10 1607 / Server 2016 and NTFS, so the
// older call is kept for what it can still do.
func replaceFile(from, to string) error {
	err := renamePOSIX(from, to)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, windows.ERROR_INVALID_PARAMETER),
		errors.Is(err, windows.ERROR_NOT_SUPPORTED),
		errors.Is(err, windows.ERROR_INVALID_NAME),
		errors.Is(err, windows.ERROR_BAD_PATHNAME):
		// The first two are a pre-1607 Windows answering an information class
		// it does not know, and a volume without POSIX rename support (FAT,
		// exFAT) answering the flag. The last two are the name being refused
		// by the path normalizer, whatever the reason.
		//
		// None of them says the rename cannot be done, only that it cannot be
		// done this way — and Update is the only path by which a record is
		// published, so a refusal here has to degrade to the older call rather
		// than take every publication on this platform down with it.
		return renameWithRetry(from, to)
	default:
		return err
	}
}

const (
	renameAttempts = 5
	renameBackoff  = 2 * time.Millisecond
)

// renameWithRetry is the fallback for a system that cannot rename with POSIX
// semantics. A reader's window is microseconds, so a few attempts turn a lost
// final outcome into a slightly delayed one — which is as much as MoveFileEx
// can offer against a reader that is there when it looks.
func renameWithRetry(from, to string) error {
	var err error
	for attempt := 0; attempt < renameAttempts; attempt++ {
		if err = os.Rename(from, to); err == nil {
			return nil
		}
		time.Sleep(renameBackoff)
	}
	return err
}

// fileRenameInfo is FILE_RENAME_INFO from winbase.h, laid out by hand because
// x/sys/windows has no binding for it and two of its properties have no Go
// spelling:
//
//   - the first field is a union of a BOOLEAN (ReplaceIfExists, read by the
//     FileRenameInfo class) and a DWORD (Flags, read by FileRenameInfoEx). The
//     DWORD is the whole union, so declaring Flags alone is the union.
//   - FileName is declared WCHAR[1] and is in fact as long as FileNameLength
//     says, so the buffer handed to the call is longer than this struct. The
//     field is here to name the offset the name is copied to, not to hold it.
//
// The padding between Flags and RootDirectory is left to Go rather than
// written out, because it is not the same everywhere: a HANDLE is 8 bytes and
// 8-aligned on a 64-bit build, which puts 4 bytes of padding after Flags, and
// 4 bytes and 4-aligned on a 32-bit one, which puts none. Go's alignment rules
// are the C compiler's here, so this matches the header on both — an explicit
// 4-byte pad would be right on amd64 and wrong on 386.
type fileRenameInfo struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// renamePOSIX renames from onto to with POSIX semantics.
func renamePOSIX(from, to string) error {
	// A full Win32 path, which is the form FILE_RENAME_INFO documents and the
	// form kernel32 expects: SetFileInformationByHandle runs the name through
	// the DOS path normalizer on its way to the NT call below it. Spelling the
	// name the way the object manager reads it (\??\C:\...) does not skip that
	// step -- the normalizer classifies a single-backslash prefix as a rooted
	// path and prepends the current drive, which produces a name nothing can
	// resolve.
	target, err := filepath.Abs(to)
	if err != nil {
		return err
	}
	name, err := windows.UTF16FromString(target)
	if err != nil {
		return err
	}
	// FileNameLength is a byte count and excludes the terminating NUL, which
	// UTF16FromString appends and the call does not want.
	chars := len(name) - 1
	nameBytes := chars * 2

	fromp, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}

	// DELETE is the access a rename needs: what it removes is the directory
	// entry. The share modes match the reader's in read_windows.go so that
	// publishing and reading never exclude one another.
	h, err := windows.CreateFile(
		fromp,
		windows.DELETE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return &os.PathError{Op: "open", Path: from, Err: err}
	}
	defer func() { _ = windows.CloseHandle(h) }()

	buf := make([]byte, int(unsafe.Offsetof(fileRenameInfo{}.FileName))+nameBytes)
	info := (*fileRenameInfo)(unsafe.Pointer(&buf[0]))
	// FILE_RENAME_FLAG_REPLACE_IF_EXISTS (0x1) | FILE_RENAME_FLAG_POSIX_SEMANTICS
	// (0x2); x/sys spells them with the ntifs names for the same bits.
	info.Flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	// Zero because the name above is a full path; a handle here would make it
	// relative to that directory.
	info.RootDirectory = 0
	info.FileNameLength = uint32(nameBytes)
	copy(unsafe.Slice(&info.FileName[0], chars), name[:chars])

	// FileRenameInfoEx is 22, the class that reads Flags rather than
	// ReplaceIfExists; the length is the whole buffer, name included.
	if err := windows.SetFileInformationByHandle(h, windows.FileRenameInfoEx, &buf[0], uint32(len(buf))); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}
