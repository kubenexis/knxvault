package config

import "github.com/kubenexis/knxvault/internal/version"

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
		RateLimitRPM:                  defaultRateLimitRPM,
		AuthLoginRateLimitRPM:         defaultAuthLoginRateLimitRPM,
		TokenCreateRateLimitRPM:       defaultTokenCreateRateLimitRPM,
		AuthLockoutThreshold:          defaultAuthLockoutThreshold,
		AuthLockoutTTL:                defaultAuthLockoutTTL,
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
