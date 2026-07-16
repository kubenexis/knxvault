// Package operator is the KNXVault Kubernetes operator runtime.
//
// Entry point: Run() in manager.go (cmd/operator). Controllers reconcile
// KNXVaultCA, Issuer/ClusterIssuer, Certificate, CertificateRequest, and
// optional Ingress annotations so clusters can use vault PKI without cert-manager.
package operator
