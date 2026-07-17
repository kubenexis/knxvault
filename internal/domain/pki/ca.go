// Copyright The KNXVault Authors.
// SPDX-License-Identifier: Apache-2.0

package pki

import (
	"fmt"
	"time"

	"github.com/google/uuid"
)

// CAType identifies root vs intermediate certificate authorities.
type CAType string

const (
	CATypeRoot         CAType = "root"
	CATypeIntermediate CAType = "intermediate"
)

// CAStatus is the lifecycle state of a CA.
type CAStatus string

const (
	CAStatusActive  CAStatus = "active"
	CAStatusRevoked CAStatus = "revoked"
)

// DistinguishedName holds X.509 subject fields.
type DistinguishedName struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
}

// CA is a certificate authority aggregate root (LLD §4.A.2).
type CA struct {
	ID            uuid.UUID
	ParentID      *uuid.UUID
	Name          string
	Type          CAType
	Subject       DistinguishedName
	Serial        string
	CertPEM       string
	PrivateKeyEnc []byte
	DEKEnc        []byte
	Status        CAStatus
	CreatedAt     time.Time
	ExpiresAt     time.Time
	CRLNextUpdate *time.Time
}

// Validate checks required CA fields.
func (c *CA) Validate() error {
	if c.ID == uuid.Nil {
		return fmt.Errorf("ca id is required")
	}
	if c.Name == "" {
		return fmt.Errorf("ca name is required")
	}
	switch c.Type {
	case CATypeRoot, CATypeIntermediate:
	default:
		return fmt.Errorf("invalid ca type %q", c.Type)
	}
	if c.Type == CATypeRoot && c.ParentID != nil {
		return fmt.Errorf("root ca must not have parent_id")
	}
	if c.Type == CATypeIntermediate && (c.ParentID == nil || *c.ParentID == uuid.Nil) {
		return fmt.Errorf("intermediate ca requires parent_id")
	}
	if c.CertPEM == "" {
		return fmt.Errorf("cert_pem is required")
	}
	if len(c.PrivateKeyEnc) == 0 || len(c.DEKEnc) == 0 {
		return fmt.Errorf("encrypted key material is required")
	}
	return nil
}
