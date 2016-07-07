package rollbar

import (
	"fmt"
	"hash/crc32"
	"os"
	"runtime"
	"strings"
)

var (
	knownSrcPrefixes []string = []string{
		"/src/",
		"/vendor/",
	}
)

// Frame is a single line of executed code in a Stack.
type Frame struct {
	Filename string `json:"filename"`
	Method   string `json:"method"`
	Line     int    `json:"lineno"`
}

// Stack represents a stacktrace as a slice of Frames.
type Stack []Frame

// BuildStack builds a full stacktrace for the current execution location.
func BuildStack(skip int) Stack {
	stack := make(Stack, 0)

	for i := skip; ; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		file = ShortenFilePath(file)
		stack = append(stack, Frame{file, functionName(pc), line})
	}

	return stack
}

// Fingerprint builds a string that uniquely identifies a Rollbar item using
// the full stacktrace. The fingerprint is used to ensure (to a reasonable
// degree) that items are coalesced by Rollbar in a smart way.
func (s Stack) Fingerprint() string {
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
func ShortenFilePath(s string) string {
	lastIndex := -1
	for _, prefix := range knownSrcPrefixes {
		index := strings.LastIndex(s, prefix) + len(prefix)
		if index > lastIndex {
			lastIndex = index
		}
	}
	if lastIndex != -1 {
		return s[lastIndex:]
	}
	return s
}

func functionName(pc uintptr) string {
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return "???"
	}
	name := fn.Name()
	end := strings.LastIndex(name, string(os.PathSeparator))
	return name[end+1 : len(name)]
}
