package version

import (
	"fmt"
	"io"
	"os"

	"go.uber.org/zap"
)

// Info is the running binary build metadata.
type Info struct {
	Version string
	Commit  string
	BuildID string
}

// Get returns the linked build metadata.
func Get() Info {
	return Info{
		Version: Version,
		Commit:  Commit,
		BuildID: BuildID,
	}
}

// String returns a human-readable build description.
func String() string {
	info := Get()
	return fmt.Sprintf("%s (commit=%s build=%s)", info.Version, info.Commit, info.BuildID)
}

// ZapFields returns structured fields for startup logging.
func ZapFields() []zap.Field {
	info := Get()
	return []zap.Field{
		zap.String("version", info.Version),
		zap.String("commit", info.Commit),
		zap.String("build_id", info.BuildID),
	}
}

// Print writes the build description to w (for -version output).
func Print(w io.Writer) {
	_, _ = fmt.Fprintln(w, String())
}

// PrintStdout writes the build description to stdout.
func PrintStdout() {
	Print(os.Stdout)
}
