package version

// Value is overridden by release builds through -ldflags. Development builds
// intentionally report the stable placeholder so the CLI is deterministic.
var Value = "dev"
