package version

import "fmt"

// These values are overridden by release builds through -ldflags. Development
// builds intentionally report the stable placeholder so the CLI is deterministic.
var (
	Value  = "dev"
	Commit = "unknown"
	Date   = "unknown"
)

func String() string {
	if Commit == "unknown" && Date == "unknown" {
		return Value
	}
	return fmt.Sprintf("%s (%s %s)", Value, Commit, Date)
}
