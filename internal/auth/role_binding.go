package auth

import (
	"strings"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// ServiceAccountIdentity is a parsed Kubernetes ServiceAccount principal.
type ServiceAccountIdentity struct {
	Namespace string
	Name      string
	Username  string
}

// MatchServiceAccountBinding checks role SA bindings against the authenticated identity.
func MatchServiceAccountBinding(role *domainauth.Role, id ServiceAccountIdentity) error {
	if role == nil {
		return nil
	}
	if len(role.BoundServiceAccountNames) == 0 && len(role.BoundServiceAccountNamespaces) == 0 {
		return common.New(common.ErrCodeForbidden, "kubernetes role requires service account bindings")
	}
	if id.Namespace == "" || id.Name == "" {
		return common.New(common.ErrCodeForbidden, "service account identity required")
	}
	if len(role.BoundServiceAccountNamespaces) > 0 && !containsString(role.BoundServiceAccountNamespaces, id.Namespace) && !containsString(role.BoundServiceAccountNamespaces, "*") {
		return common.New(common.ErrCodeForbidden, "service account namespace not bound to role")
	}
	if len(role.BoundServiceAccountNames) > 0 && !containsString(role.BoundServiceAccountNames, id.Name) && !containsString(role.BoundServiceAccountNames, "*") {
		return common.New(common.ErrCodeForbidden, "service account name not bound to role")
	}
	return nil
}

// ParseServiceAccountUsername extracts namespace and name from system:serviceaccount:ns:name.
func ParseServiceAccountUsername(username string) (ServiceAccountIdentity, bool) {
	const prefix = "system:serviceaccount:"
	if !strings.HasPrefix(username, prefix) {
		return ServiceAccountIdentity{}, false
	}
	rest := strings.TrimPrefix(username, prefix)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ServiceAccountIdentity{}, false
	}
	return ServiceAccountIdentity{
		Namespace: parts[0],
		Name:      parts[1],
		Username:  username,
	}, true
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
