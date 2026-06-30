package version

// HandleArgs reports whether args request version output (-version / --version).
func HandleArgs(args []string) bool {
	for _, arg := range args {
		if arg == "-version" || arg == "--version" {
			PrintStdout()
			return true
		}
	}
	return false
}
