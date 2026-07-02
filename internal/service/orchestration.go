package service

import (
	"context"
	"time"

	"github.com/kubenexis/knxvault/internal/notify"
)

// OrchestrationService coordinates rotation across KV, database, SSH, and PKI engines.
type OrchestrationService struct {
	rotation *RotationService
	database *DatabaseService
	ssh      *SSHService
	pki      *PKIService
	webhook  *notify.Webhook
}

// NewOrchestrationService constructs an orchestration service.
func NewOrchestrationService(
	rotation *RotationService,
	database *DatabaseService,
	ssh *SSHService,
	pki *PKIService,
	webhookURL string,
) *OrchestrationService {
	return &OrchestrationService{
		rotation: rotation,
		database: database,
		ssh:      ssh,
		pki:      pki,
		webhook:  notify.NewWebhook(webhookURL),
	}
}

// RunResult summarizes a rotation orchestration run.
type RunResult struct {
	KVRotated    int `json:"kv_rotated"`
	DBRenewed    int `json:"db_leases_renewed"`
	SSHRenewed   int `json:"ssh_leases_renewed"`
	PKIRenewed   int `json:"pki_certs_renewed"`
	TotalActions int `json:"total_actions"`
}

// Run triggers due KV rotations, expiring DB/SSH lease renewals, and PKI renewals.
func (s *OrchestrationService) Run(ctx context.Context, dbGrace, sshGrace, pkiGrace time.Duration) (*RunResult, error) {
	if s == nil {
		return &RunResult{}, nil
	}
	result := &RunResult{}
	now := time.Now().UTC()

	if s.rotation != nil {
		kv, err := s.rotation.RunDue(ctx, now)
		if err != nil {
			return nil, err
		}
		result.KVRotated = kv
	}

	if s.database != nil {
		db, err := s.database.RenewExpiring(ctx, dbGrace, 50)
		if err != nil {
			return nil, err
		}
		result.DBRenewed = db
	}

	if s.ssh != nil {
		if sshGrace <= 0 {
			sshGrace = dbGrace
		}
		sshCount, err := s.ssh.RenewExpiring(ctx, sshGrace, 50)
		if err != nil {
			return nil, err
		}
		result.SSHRenewed = sshCount
	}

	if s.pki != nil && pkiGrace > 0 {
		pkiCount, err := s.pki.RenewExpiring(ctx, pkiGrace, 50)
		if err != nil {
			return nil, err
		}
		result.PKIRenewed = pkiCount
	}

	result.TotalActions = result.KVRotated + result.DBRenewed + result.SSHRenewed + result.PKIRenewed
	if s.webhook != nil && result.TotalActions > 0 {
		_ = s.webhook.Send(ctx, notify.Event{
			Event: "rotation.run",
			Details: map[string]any{
				"kv_rotated":         result.KVRotated,
				"db_leases_renewed":  result.DBRenewed,
				"ssh_leases_renewed": result.SSHRenewed,
				"pki_certs_renewed":  result.PKIRenewed,
			},
		})
	}
	return result, nil
}
