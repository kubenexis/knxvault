package postgres

import "testing"

func TestSplitSQL(t *testing.T) {
	t.Parallel()

	sql := `
-- comment
CREATE TABLE foo (id INT);

CREATE INDEX idx_foo ON foo(id);
`
	stmts := splitSQL(sql)
	if len(stmts) != 2 {
		t.Fatalf("len(stmts) = %d, want 2", len(stmts))
	}
}
