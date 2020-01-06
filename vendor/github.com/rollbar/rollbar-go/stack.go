package rollbar

import (
	"fmt"
	"hash/crc32"
	"os"
	"runtime"
	"strings"
)

var (
	knownFilePathPatterns = []string{
		"github.com/",
		"code.google.com/",
		"bitbucket.org/",
		"launchpad.net/",
	}
)

// frame represents one frame in a stack trace
type frame struct {
	// Filename is the name of the file for this frame
	Filename string `json:"filename"`
	// Method is the name of the method for this frame
	Method string `json:"method"`
	// Line is the line number in the file for this frame
	Line int `json:"lineno"`
}

// A stack is a slice of frames
type stack []frame

// buildStack converts []runtime.Frame into a JSON serializable slice of frames
func buildStack(frames []runtime.Frame) stack {
	stack := make(stack, len(frames))

	for i, fr := range frames {
		file := shortenFilePath(fr.File)
		stack[i] = frame{file, functionName(fr.Function), fr.Line}
	}

	return stack
}

// Fingerprint creates a fingerprint that uniqely identify a given message. We use the full
// callstack, including file names. That ensure that there are no false duplicates
// but also means that after changing the code (adding/removing lines), the
// fingerprints will change. It's a trade-off.
func (s stack) Fingerprint() string {
	hash := crc32.NewIEEE()
	for _, frame := range s {
		fmt.Fprintf(hash, "%s%s%d", frame.Filename, frame.Method, frame.Line)
	}
	return fmt.Sprintf("%x", hash.Sum32())
}

// Remove un-needed information from the source file path. This makes them
// shorter in Rollbar UI as well as making them the same, regardless of the
// machine the code was compiled on.
//
// Examples:
//   /usr/local/go/src/pkg/runtime/proc.c -> pkg/runtime/proc.c
//   /home/foo/go/src/github.com/rollbar/rollbar.go -> github.com/rollbar/rollbar.go
func shortenFilePath(s string) string {
	idx := strings.Index(s, "/src/pkg/")
	if idx != -1 {
		return s[idx+5:]
	}
	for _, pattern := range knownFilePathPatterns {
		idx = strings.Index(s, pattern)
		if idx != -1 {
			return s[idx:]
		}
	}
	return s
}

func functionName(pcFuncName string) string {
	if pcFuncName == "" {
		return "???"
	}
	end := strings.LastIndex(pcFuncName, string(os.PathSeparator))
	return pcFuncName[end+1:]
}
