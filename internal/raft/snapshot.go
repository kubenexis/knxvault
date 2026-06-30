package raft

import (
	"context"

	"github.com/kubenexis/knxvault/internal/backup"
)

// SnapshotImporter applies portable snapshots through Raft.
type SnapshotImporter struct {
	client *Client
}

// NewSnapshotImporter constructs a Raft snapshot importer.
func NewSnapshotImporter(client *Client) *SnapshotImporter {
	return &SnapshotImporter{client: client}
}

// ImportSnapshot replaces replicated state from a backup snapshot.
func (s *SnapshotImporter) ImportSnapshot(ctx context.Context, snapshot *backup.Snapshot) error {
	if err := backup.ValidateSnapshot(snapshot); err != nil {
		return err
	}
	data, err := s.client.Propose(ctx, OpImportSnapshot, snapshot)
	if err != nil {
		return err
	}
	return DecodeResult(data, nil)
}
