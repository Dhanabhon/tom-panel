package operations

import (
	"context"
	"database/sql"
	"time"

	"github.com/Dhanabhon/tom-panel/internal/store"
)

// RetentionRules bounds how long operational records survive.
type RetentionRules struct {
	JobsDays  int
	AuditDays int
}

// DefaultRetention matches the approved product policy.
func DefaultRetention() RetentionRules {
	return RetentionRules{JobsDays: 30, AuditDays: 180}
}

const retentionBatch = 500

// Retention prunes finished jobs and old audit events in bounded batches so
// a huge backlog can never flood a single transaction.
type Retention struct {
	store *store.Store
	rules RetentionRules
	now   func() time.Time
}

// NewRetention builds the pruner.
func NewRetention(database *store.Store, rules RetentionRules) *Retention {
	if rules.JobsDays <= 0 || rules.AuditDays <= 0 {
		rules = DefaultRetention()
	}
	return &Retention{store: database, rules: rules, now: time.Now}
}

// Apply prunes in bounded batches and returns how many rows were removed.
func (r *Retention) Apply(ctx context.Context) (jobsRemoved, auditRemoved int, err error) {
	jobsCutoff := r.now().UTC().Add(-time.Duration(r.rules.JobsDays) * 24 * time.Hour).Unix()
	auditCutoff := r.now().UTC().Add(-time.Duration(r.rules.AuditDays) * 24 * time.Hour).Unix()
	for {
		batch, err := r.prune(ctx, `DELETE FROM jobs WHERE id IN (
			SELECT id FROM jobs WHERE status IN ('succeeded', 'failed', 'cancelled') AND finished_at IS NOT NULL AND finished_at < ? LIMIT ?)`, jobsCutoff)
		if err != nil {
			return jobsRemoved, auditRemoved, err
		}
		jobsRemoved += batch
		if batch < retentionBatch {
			break
		}
	}
	for {
		batch, err := r.prune(ctx, `DELETE FROM audit_events WHERE id IN (
			SELECT id FROM audit_events WHERE created_at < ? LIMIT ?)`, auditCutoff)
		if err != nil {
			return jobsRemoved, auditRemoved, err
		}
		auditRemoved += batch
		if batch < retentionBatch {
			break
		}
	}
	return jobsRemoved, auditRemoved, nil
}

func (r *Retention) prune(ctx context.Context, statement string, cutoff int64) (int, error) {
	removed := 0
	err := r.store.Tx(ctx, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, statement, cutoff, retentionBatch)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		removed = int(changed)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return removed, nil
}
