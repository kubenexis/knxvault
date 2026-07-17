// Copyright Kubenexis Systems Private Limited.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"time"

	"github.com/kubenexis/knxvault/internal/version"
)

func defaults() Config {
	return Config{
		HTTPAddr:                      defaultHTTPAddr,
		LogLevel:                      defaultLogLevel,
		ShutdownGrace:                 defaultShutdownGrace,
		Version:                       version.Version,
		TokenTTL:                      defaultTokenTTL,
		HANamespace:                   defaultHANamespace,
		HALeaseName:                   defaultHALeaseName,
		JobLeaseCleanupInterval:       defaultJobLeaseCleanupInterval,
		JobCRLRefreshInterval:         defaultJobCRLRefreshInterval,
		JobCertRenewInterval:          defaultJobCertRenewInterval,
		JobKVRotationInterval:         defaultJobKVRotationInterval,
		JobMasterKeyReencryptInterval: defaultJobMasterKeyReencryptInterval,
		RenewGrace:                    defaultRenewGrace,
		OIDCDefaultTTL:                defaultOIDCTokenTTL,
		RateLimitEnabled:              true, // W52-05: on by default
		RateLimitRPM:                  defaultRateLimitRPM,
		AuthLoginRateLimitRPM:         defaultAuthLoginRateLimitRPM,
		TokenCreateRateLimitRPM:       defaultTokenCreateRateLimitRPM,
		AuthLockoutThreshold:          defaultAuthLockoutThreshold,
		AuthLockoutTTL:                defaultAuthLockoutTTL,
		RBACSyncFailClosed:            true,
		ManagedSQLStrict:              true,
		// W81: coarse "pki" write off by default; opt-in only for legacy lab policies.
		AllowCoarsePKIWrite: false,
		RootTokenTTL:        72 * time.Hour,
		RequireHTTPSClients: true, // W52-06: CSI/ESO/operator prefer HTTPS
		SecurityProfile:     SecurityProfileLab,
		// M-DTP-2: lab keeps OIDC/LDAP routes available; production/airgap ConfigMaps disable.
		AuthOIDCEnabled:     true,
		AuthLDAPEnabled:     true,
		AuditForwardEnabled: false, // explicit enable required (W90-21)
		ACMERelatedEnabled:  true,  // server-side; airgap overlays set false
		Raft:                defaultRaft(),
	}
}

func defaultRaft() RaftConfig {
	return RaftConfig{
		LeaderWait:     defaultRaftLeaderWait,
		RaftAddress:    defaultRaftAddress,
		DataDir:        defaultRaftDataDir,
		ElectionRTT:    defaultRaftElectionRTT,
		HeartbeatRTT:   defaultRaftHeartbeatRTT,
		RTTMillisecond: defaultRaftRTTMillisecond,
	}
}
