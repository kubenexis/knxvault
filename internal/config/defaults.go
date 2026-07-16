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
		OpenSSLTimeout:                defaultOpenSSLTimeout,
		OpenSSLBinary:                 defaultOpenSSLBinary,
		PKIBackend:                    defaultPKIBackend,
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
		RootTokenTTL:                  72 * time.Hour,
		RequireHTTPSClients:           true, // W52-06: CSI/ESO/operator prefer HTTPS
		Raft:                          defaultRaft(),
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
