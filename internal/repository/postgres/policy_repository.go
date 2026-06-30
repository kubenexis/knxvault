package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	domainauth "github.com/kubenexis/knxvault/internal/domain/auth"
	"github.com/kubenexis/knxvault/internal/domain/common"
)

// PolicyRepository persists policies in PostgreSQL.
type PolicyRepository struct {
	pool *pgxpool.Pool
}

// NewPolicyRepository constructs a PolicyRepository.
func NewPolicyRepository(pool *pgxpool.Pool) *PolicyRepository {
	return &PolicyRepository{pool: pool}
}

// Save inserts or updates a policy.
func (r *PolicyRepository) Save(ctx context.Context, policy *domainauth.Policy) error {
	if err := policy.Validate(); err != nil {
		return common.Wrap(common.ErrCodeValidation, "invalid policy", err)
	}
	if policy.ID == uuid.Nil {
		policy.ID = uuid.New()
	}

	resources, err := json.Marshal(policy.Resources)
	if err != nil {
		return fmt.Errorf("marshal resources: %w", err)
	}
	actions, err := json.Marshal(policy.Actions)
	if err != nil {
		return fmt.Errorf("marshal actions: %w", err)
	}
	conditions := policy.Conditions
	if conditions == nil {
		conditions = map[string]any{}
	}
	conditionsJSON, err := json.Marshal(conditions)
	if err != nil {
		return fmt.Errorf("marshal conditions: %w", err)
	}

	now := time.Now().UTC()
	const q = `
INSERT INTO policies (id, name, effect, resources, actions, conditions, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
ON CONFLICT (name) DO UPDATE SET
    effect = EXCLUDED.effect,
    resources = EXCLUDED.resources,
    actions = EXCLUDED.actions,
    conditions = EXCLUDED.conditions,
    updated_at = EXCLUDED.updated_at
RETURNING id
`
	err = r.pool.QueryRow(ctx, q,
		policy.ID,
		policy.Name,
		string(policy.Effect),
		resources,
		actions,
		conditionsJSON,
		now,
	).Scan(&policy.ID)
	if err != nil {
		return fmt.Errorf("save policy: %w", err)
	}
	return nil
}

// GetByName returns a policy by name.
func (r *PolicyRepository) GetByName(ctx context.Context, name string) (*domainauth.Policy, error) {
	const q = `
SELECT id, name, effect, resources, actions, conditions
FROM policies WHERE name = $1
`
	row := r.pool.QueryRow(ctx, q, name)
	policy, err := scanPolicy(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, common.New(common.ErrCodeNotFound, "policy not found")
		}
		return nil, err
	}
	return policy, nil
}

// List returns all policies ordered by name.
func (r *PolicyRepository) List(ctx context.Context) ([]*domainauth.Policy, error) {
	const q = `
SELECT id, name, effect, resources, actions, conditions
FROM policies ORDER BY name ASC
`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var out []*domainauth.Policy
	for rows.Next() {
		policy, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list policies rows: %w", err)
	}
	return out, nil
}

// Delete removes a policy by name.
func (r *PolicyRepository) Delete(ctx context.Context, name string) error {
	const q = `DELETE FROM policies WHERE name = $1`
	tag, err := r.pool.Exec(ctx, q, name)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return common.New(common.ErrCodeNotFound, "policy not found")
	}
	return nil
}

type policyScanner interface {
	Scan(dest ...any) error
}

func scanPolicy(row policyScanner) (*domainauth.Policy, error) {
	var (
		policy         domainauth.Policy
		resourcesJSON  []byte
		actionsJSON    []byte
		conditionsJSON []byte
		effect         string
	)
	if err := row.Scan(
		&policy.ID,
		&policy.Name,
		&effect,
		&resourcesJSON,
		&actionsJSON,
		&conditionsJSON,
	); err != nil {
		return nil, fmt.Errorf("scan policy: %w", err)
	}
	policy.Effect = domainauth.Effect(effect)
	if len(resourcesJSON) > 0 {
		if err := json.Unmarshal(resourcesJSON, &policy.Resources); err != nil {
			return nil, fmt.Errorf("unmarshal resources: %w", err)
		}
	}
	if len(actionsJSON) > 0 {
		if err := json.Unmarshal(actionsJSON, &policy.Actions); err != nil {
			return nil, fmt.Errorf("unmarshal actions: %w", err)
		}
	}
	if len(conditionsJSON) > 0 {
		if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
			return nil, fmt.Errorf("unmarshal conditions: %w", err)
		}
	}
	if policy.Conditions == nil {
		policy.Conditions = map[string]any{}
	}
	return &policy, nil
}
