package dto

// CapabilitiesResponse is GET /sys/capabilities.
type CapabilitiesResponse struct {
	Capabilities []string `json:"capabilities"`
}

// InitRequest is POST /sys/init.
type InitRequest struct {
	CreateRootCA   bool   `json:"create_root_ca"`
	RootCAName     string `json:"root_ca_name,omitempty"`
	RootCommonName string `json:"root_common_name,omitempty"`
}

// RotateMasterKeyRequest is POST /sys/rotate-master-key.
type RotateMasterKeyRequest struct {
	NewKey string `json:"new_key"`
}

// RotateMasterKeyResponse is returned after master key rotation.
type RotateMasterKeyResponse struct {
	KeyVersion int `json:"key_version"`
}

// UnsealRequest is POST /sys/unseal.
type UnsealRequest struct {
	Key string `json:"key"`
}

// RaftAddNodeRequest is POST /sys/raft/add-node.
type RaftAddNodeRequest struct {
	NodeID  uint64 `json:"node_id"`
	Address string `json:"address"`
}

// RaftRemoveNodeRequest is POST /sys/raft/remove-node.
type RaftRemoveNodeRequest struct {
	NodeID uint64 `json:"node_id"`
}
