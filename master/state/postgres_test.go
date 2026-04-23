package state

import "testing"

func TestPostgresMigrationsStrictlyIncrease(t *testing.T) {
	seen := make(map[int]struct{}, len(postgresMigrations))
	last := 0
	for _, migration := range postgresMigrations {
		if migration.Version <= last {
			t.Fatalf("migration version %d is not greater than previous version %d", migration.Version, last)
		}
		if _, ok := seen[migration.Version]; ok {
			t.Fatalf("duplicate migration version %d", migration.Version)
		}
		seen[migration.Version] = struct{}{}
		last = migration.Version
	}
}
