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
