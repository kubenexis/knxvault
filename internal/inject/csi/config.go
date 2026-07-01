package csi

import (
	"encoding/json"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	attrPodName      = "csi.storage.k8s.io/pod.name"
	attrPodNamespace = "csi.storage.k8s.io/pod.namespace"
	attrPodSA        = "csi.storage.k8s.io/serviceAccount.name"
	attrSAToken      = "csi.storage.k8s.io/serviceAccount.tokens" // #nosec G101 -- CSI attribute name
)

// ObjectSpec describes one secret object to mount.
type ObjectSpec struct {
	Path       string `yaml:"path"`
	FileName   string `yaml:"fileName"`
	ObjectType string `yaml:"objectType"`
}

// MountConfig is parsed SecretProviderClass parameters for a mount request.
type MountConfig struct {
	VaultAddr      string
	Role           string
	Objects        []ObjectSpec
	PodName        string
	Namespace      string
	ServiceAccount string
	SAToken        string
}

// ParseMountConfig parses CSI driver attributes and optional secrets payload.
func ParseMountConfig(attributesJSON, secretsJSON string) (MountConfig, error) {
	var attrs map[string]string
	if err := unmarshalJSONMap(attributesJSON, &attrs); err != nil {
		return MountConfig{}, fmt.Errorf("parse attributes: %w", err)
	}
	cfg := MountConfig{
		VaultAddr:      strings.TrimSpace(attrs["vaultAddr"]),
		Role:           strings.TrimSpace(attrs["role"]),
		PodName:        strings.TrimSpace(attrs[attrPodName]),
		Namespace:      strings.TrimSpace(attrs[attrPodNamespace]),
		ServiceAccount: strings.TrimSpace(attrs[attrPodSA]),
	}
	if cfg.Role == "" {
		return MountConfig{}, fmt.Errorf("role parameter is required")
	}
	if cfg.VaultAddr == "" {
		cfg.VaultAddr = "http://knxvault.knxvault.svc.cluster.local:8200"
	}
	objectsRaw := strings.TrimSpace(attrs["objects"])
	if objectsRaw == "" {
		return MountConfig{}, fmt.Errorf("objects parameter is required")
	}
	var objects []ObjectSpec
	if err := yaml.Unmarshal([]byte(objectsRaw), &objects); err != nil {
		return MountConfig{}, fmt.Errorf("parse objects yaml: %w", err)
	}
	if len(objects) == 0 {
		return MountConfig{}, fmt.Errorf("at least one object is required")
	}
	for i := range objects {
		objects[i].Path = strings.TrimPrefix(strings.TrimSpace(objects[i].Path), "/")
		if objects[i].Path == "" {
			return MountConfig{}, fmt.Errorf("object path is required")
		}
		if objects[i].FileName == "" {
			objects[i].FileName = sanitizeFileName(objects[i].Path)
		}
		if objects[i].ObjectType == "" {
			objects[i].ObjectType = "secret"
		}
	}
	cfg.Objects = objects

	if secretsJSON != "" {
		var secrets map[string]string
		if err := unmarshalJSONMap(secretsJSON, &secrets); err == nil {
			if token := strings.TrimSpace(secrets["serviceAccountToken"]); token != "" {
				cfg.SAToken = token
			}
			if token := strings.TrimSpace(secrets[attrSAToken]); token != "" {
				cfg.SAToken = token
			}
		}
	}
	if cfg.SAToken == "" {
		if token := strings.TrimSpace(attrs[attrSAToken]); token != "" {
			cfg.SAToken = token
		}
	}
	return cfg, nil
}

func unmarshalJSONMap(raw string, out *map[string]string) error {
	if strings.TrimSpace(raw) == "" {
		*out = map[string]string{}
		return nil
	}
	return json.Unmarshal([]byte(raw), out)
}

func sanitizeFileName(p string) string {
	p = strings.TrimPrefix(p, "/")
	p = strings.ReplaceAll(p, "/", "_")
	if p == "" {
		return "secret"
	}
	return p
}
