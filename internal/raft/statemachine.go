package raft

import (
	"encoding/json"
	"io"

	sm "github.com/lni/dragonboat/v3/statemachine"

	"github.com/kubenexis/knxvault/internal/backup"
)

// VaultStateMachine implements dragonboat IStateMachine.
type VaultStateMachine struct {
	store *Store
}

// NewVaultStateMachine constructs a vault state machine.
func NewVaultStateMachine() *VaultStateMachine {
	return &VaultStateMachine{store: NewStore()}
}

// CreateStateMachine is the dragonboat factory.
func CreateStateMachine(uint64, uint64) sm.IStateMachine {
	return NewVaultStateMachine()
}

// Update applies a committed Raft entry.
func (v *VaultStateMachine) Update(data []byte) (sm.Result, error) {
	cmd, err := decodeCommand(data)
	if err != nil {
		return sm.Result{}, err
	}
	out, err := v.store.Handle(cmd)
	if err != nil {
		return sm.Result{}, err
	}
	return sm.Result{Data: out}, nil
}

// Lookup performs a linearizable read.
func (v *VaultStateMachine) Lookup(query interface{}) (interface{}, error) {
	var cmd Command
	switch q := query.(type) {
	case Command:
		cmd = q
	case []byte:
		if err := json.Unmarshal(q, &cmd); err != nil {
			return nil, err
		}
	default:
		b, err := json.Marshal(q)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, &cmd); err != nil {
			return nil, err
		}
	}
	return v.store.Lookup(cmd)
}

// SaveSnapshot persists state to the writer.
func (v *VaultStateMachine) SaveSnapshot(w io.Writer, _ sm.ISnapshotFileCollection, _ <-chan struct{}) error {
	snapshot, err := v.store.ExportSnapshot(true)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(snapshot)
}

// RecoverFromSnapshot restores state from a snapshot.
func (v *VaultStateMachine) RecoverFromSnapshot(r io.Reader, _ []sm.SnapshotFile, _ <-chan struct{}) error {
	var snapshot backup.Snapshot
	if err := json.NewDecoder(r).Decode(&snapshot); err != nil {
		return err
	}
	return v.store.ImportSnapshot(&snapshot)
}

// Close releases resources.
func (v *VaultStateMachine) Close() error { return nil }

// Store returns the underlying store (tests only).
func (v *VaultStateMachine) Store() *Store { return v.store }
