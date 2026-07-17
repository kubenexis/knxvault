// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"github.com/kubenexis/knxvault/internal/domain/audit"
	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/pki"
	"github.com/kubenexis/knxvault/internal/domain/secrets"
)

func caFromDomain(ca *pki.CA) CARecord {
	return CARecord{
		ID:            ca.ID,
		ParentID:      ca.ParentID,
		Name:          ca.Name,
		Type:          ca.Type,
		CommonName:    ca.Subject.CommonName,
		Serial:        ca.Serial,
		CertPEM:       ca.CertPEM,
		PrivateKeyEnc: ca.PrivateKeyEnc,
		DEKEnc:        ca.DEKEnc,
		Status:        ca.Status,
		CreatedAt:     ca.CreatedAt,
		ExpiresAt:     ca.ExpiresAt,
		CRLNextUpdate: ca.CRLNextUpdate,
	}
}

func caToDomain(rec CARecord) *pki.CA {
	return &pki.CA{
		ID:            rec.ID,
		ParentID:      rec.ParentID,
		Name:          rec.Name,
		Type:          rec.Type,
		Subject:       pki.DistinguishedName{CommonName: rec.CommonName},
		Serial:        rec.Serial,
		CertPEM:       rec.CertPEM,
		PrivateKeyEnc: rec.PrivateKeyEnc,
		DEKEnc:        rec.DEKEnc,
		Status:        rec.Status,
		CreatedAt:     rec.CreatedAt,
		ExpiresAt:     rec.ExpiresAt,
		CRLNextUpdate: rec.CRLNextUpdate,
	}
}

func secretFromDomain(sv *secrets.SecretVersion) SecretRecord {
	return SecretRecord{
		ID:         sv.ID,
		Path:       sv.Path,
		Version:    sv.Version,
		DataEnc:    sv.DataEnc,
		DEKEnc:     sv.DEKEnc,
		LeaseID:    sv.LeaseID,
		TTLSeconds: sv.TTLSeconds,
		CreatedAt:  sv.CreatedAt,
		ExpiresAt:  sv.ExpiresAt,
		Destroyed:  sv.Destroyed,
	}
}

func secretToDomain(rec SecretRecord) *secrets.SecretVersion {
	return &secrets.SecretVersion{
		ID:         rec.ID,
		Path:       rec.Path,
		Version:    rec.Version,
		DataEnc:    rec.DataEnc,
		DEKEnc:     rec.DEKEnc,
		LeaseID:    rec.LeaseID,
		TTLSeconds: rec.TTLSeconds,
		CreatedAt:  rec.CreatedAt,
		ExpiresAt:  rec.ExpiresAt,
		Destroyed:  rec.Destroyed,
	}
}

func pkiRoleFromDomain(role *pki.Role) PKIRoleRecord {
	return PKIRoleRecord{
		Name:            role.Name,
		CAName:          role.CAName,
		AllowedDomains:  append([]string(nil), role.AllowedDomains...),
		MaxTTLSeconds:   role.MaxTTLSeconds,
		KeyUsage:        role.KeyUsage,
		AllowSubdomains: role.AllowSubdomains,
	}
}

func pkiRoleToDomain(rec PKIRoleRecord) *pki.Role {
	return &pki.Role{
		Name:            rec.Name,
		CAName:          rec.CAName,
		AllowedDomains:  rec.AllowedDomains,
		MaxTTLSeconds:   rec.MaxTTLSeconds,
		KeyUsage:        rec.KeyUsage,
		AllowSubdomains: rec.AllowSubdomains,
	}
}

func auditFromDomain(entry *audit.Entry) AuditRecord {
	return AuditRecord{
		Timestamp: entry.Timestamp,
		Actor:     entry.Actor,
		Action:    entry.Action,
		Resource:  entry.Resource,
		Status:    entry.Status,
		Details:   entry.Details,
		Hash:      entry.Hash,
	}
}

func auditToDomain(rec AuditRecord) *audit.Entry {
	return &audit.Entry{
		Timestamp: rec.Timestamp,
		Actor:     rec.Actor,
		Action:    rec.Action,
		Resource:  rec.Resource,
		Status:    rec.Status,
		Details:   rec.Details,
		Hash:      rec.Hash,
	}
}

func sshRoleFromDomain(role *secrets.SSHRole) SSHRoleRecord {
	secrets.NormalizeSSHRole(role)
	return SSHRoleRecord{
		Name:         role.Name,
		TTLSeconds:   role.TTLSeconds,
		CAKeyPath:    role.CAKeyPath,
		AllowedUsers: append([]string(nil), role.AllowedUsers...),
		DefaultUser:  role.DefaultUser,
		KeyType:      role.KeyType,
		Extensions:   role.Extensions,
	}
}

func sshRoleToDomain(rec SSHRoleRecord) *secrets.SSHRole {
	role := &secrets.SSHRole{
		Name:         rec.Name,
		TTLSeconds:   rec.TTLSeconds,
		CAKeyPath:    rec.CAKeyPath,
		AllowedUsers: rec.AllowedUsers,
		DefaultUser:  rec.DefaultUser,
		KeyType:      rec.KeyType,
		Extensions:   rec.Extensions,
	}
	secrets.NormalizeSSHRole(role)
	return role
}

func databaseRoleFromDomain(role *secrets.DatabaseRole) DatabaseRoleRecord {
	secrets.NormalizeDatabaseRole(role)
	return DatabaseRoleRecord{
		Name:                 role.Name,
		TTLSeconds:           role.TTLSeconds,
		UsernamePrefix:       role.UsernamePrefix,
		DefaultUsername:      role.DefaultUsername,
		CreationStatements:   append([]string(nil), role.CreationStatements...),
		RevocationStatements: append([]string(nil), role.RevocationStatements...),
		ExecutionMode:        role.ExecutionMode,
		AdminCredentialsPath: role.AdminCredentialsPath,
		Config:               role.Config,
	}
}

func databaseRoleToDomain(rec DatabaseRoleRecord) *secrets.DatabaseRole {
	role := &secrets.DatabaseRole{
		Name:                 rec.Name,
		TTLSeconds:           rec.TTLSeconds,
		UsernamePrefix:       rec.UsernamePrefix,
		DefaultUsername:      rec.DefaultUsername,
		CreationStatements:   rec.CreationStatements,
		RevocationStatements: rec.RevocationStatements,
		ExecutionMode:        rec.ExecutionMode,
		AdminCredentialsPath: rec.AdminCredentialsPath,
		Config:               rec.Config,
	}
	secrets.NormalizeDatabaseRole(role)
	return role
}

func leaseFromDomain(lease *secrets.Lease) LeaseRecord {
	return LeaseRecord{
		ID:         lease.ID,
		Path:       lease.Path,
		RoleName:   lease.RoleName,
		Engine:     lease.Engine,
		TTLSeconds: lease.TTLSeconds,
		CreatedAt:  lease.CreatedAt,
		ExpiresAt:  lease.ExpiresAt,
		RevokedAt:  lease.RevokedAt,
		Renewable:  lease.Renewable,
	}
}

func leaseToDomain(rec LeaseRecord) *secrets.Lease {
	return &secrets.Lease{
		ID:         rec.ID,
		Path:       rec.Path,
		RoleName:   rec.RoleName,
		Engine:     rec.Engine,
		TTLSeconds: rec.TTLSeconds,
		CreatedAt:  rec.CreatedAt,
		ExpiresAt:  rec.ExpiresAt,
		RevokedAt:  rec.RevokedAt,
		Renewable:  rec.Renewable,
	}
}

func issuedFromDomain(cert *pki.IssuedCertificate) IssuedCertRecord {
	return IssuedCertRecord{
		ID:                cert.ID,
		CAID:              cert.CAID,
		Role:              cert.Role,
		Serial:            cert.Serial,
		CommonName:        cert.CommonName,
		DNSNames:          append([]string(nil), cert.DNSNames...),
		TTLSeconds:        cert.TTLSeconds,
		IssuedAt:          cert.IssuedAt,
		ExpiresAt:         cert.ExpiresAt,
		AutoRenew:         cert.AutoRenew,
		RenewedFromSerial: cert.RenewedFromSerial,
	}
}

func issuedToDomain(rec IssuedCertRecord) *pki.IssuedCertificate {
	return &pki.IssuedCertificate{
		ID:                rec.ID,
		CAID:              rec.CAID,
		Role:              rec.Role,
		Serial:            rec.Serial,
		CommonName:        rec.CommonName,
		DNSNames:          rec.DNSNames,
		TTLSeconds:        rec.TTLSeconds,
		IssuedAt:          rec.IssuedAt,
		ExpiresAt:         rec.ExpiresAt,
		AutoRenew:         rec.AutoRenew,
		RenewedFromSerial: rec.RenewedFromSerial,
	}
}

func policyFromDomain(policy *domainauth.Policy) PolicyRecord {
	return PolicyRecord{
		Name:       policy.Name,
		Effect:     policy.Effect,
		Resources:  append([]string(nil), policy.Resources...),
		Actions:    append([]string(nil), policy.Actions...),
		Conditions: policy.Conditions,
	}
}

func policyToDomain(rec PolicyRecord) *domainauth.Policy {
	return &domainauth.Policy{
		Name:       rec.Name,
		Effect:     rec.Effect,
		Resources:  rec.Resources,
		Actions:    rec.Actions,
		Conditions: rec.Conditions,
	}
}

func roleFromDomain(role *domainauth.Role) RoleRecord {
	return RoleRecord{
		Name:                          role.Name,
		Policies:                      append([]string(nil), role.Policies...),
		BoundServiceAccountNames:      append([]string(nil), role.BoundServiceAccountNames...),
		BoundServiceAccountNamespaces: append([]string(nil), role.BoundServiceAccountNamespaces...),
	}
}

func roleToDomain(rec RoleRecord) *domainauth.Role {
	return &domainauth.Role{
		Name:                          rec.Name,
		Policies:                      rec.Policies,
		BoundServiceAccountNames:      rec.BoundServiceAccountNames,
		BoundServiceAccountNamespaces: rec.BoundServiceAccountNamespaces,
	}
}

func tokenFromDomain(token *domainauth.ClientToken) TokenRecord {
	return TokenRecord{
		ID:        token.ID,
		Subject:   token.Subject,
		Policies:  append([]string(nil), token.Policies...),
		ExpiresAt: token.ExpiresAt,
		Renewable: token.Renewable,
		Revoked:   token.Revoked,
	}
}

func tokenToDomain(rec TokenRecord) *domainauth.ClientToken {
	return &domainauth.ClientToken{
		ID:        rec.ID,
		Subject:   rec.Subject,
		Policies:  rec.Policies,
		ExpiresAt: rec.ExpiresAt,
		Renewable: rec.Renewable,
		Revoked:   rec.Revoked,
	}
}
