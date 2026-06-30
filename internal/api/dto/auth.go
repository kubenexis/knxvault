package dto

// K8sLoginRequest is POST /auth/kubernetes.
type K8sLoginRequest struct {
	Role string `json:"role" binding:"required"`
	JWT  string `json:"jwt" binding:"required"`
}

// TokenLoginRequest is POST /auth/token.
type TokenLoginRequest struct {
	Token string `json:"token" binding:"required"`
}

// LoginResponse is returned by auth endpoints.
type LoginResponse struct {
	ClientToken string   `json:"client_token"`
	TTL         int      `json:"ttl"`
	Policies    []string `json:"policies"`
	Renewable   bool     `json:"renewable"`
}
