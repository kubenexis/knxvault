package version

import (
	"log"

	"go.uber.org/zap"
)

// AnnounceZap logs build metadata when a zap logger is initialized.
func AnnounceZap(logger *zap.Logger, tool string) {
	if logger == nil {
		return
	}
	fields := append([]zap.Field{zap.String("tool", tool)}, ZapFields()...)
	logger.Info("build metadata", fields...)
}

// AnnounceStandard logs build metadata when the standard library logger is used.
func AnnounceStandard(tool string) {
	info := Get()
	log.Printf("%s build version=%s commit=%s build_id=%s", tool, info.Version, info.Commit, info.BuildID)
}
