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

// TokenCreateRequest is POST /auth/token/create.
type TokenCreateRequest struct {
	Policies  []string `json:"policies" binding:"required"`
	TTL       string   `json:"ttl,omitempty"`
	Subject   string   `json:"subject,omitempty"`
	Renewable *bool    `json:"renewable,omitempty"`
}

// TokenRenewRequest is POST /auth/token/renew.
type TokenRenewRequest struct {
	Increment string `json:"increment,omitempty"`
}
