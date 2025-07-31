package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
	var databaseURL, migrationsPath, migrationsTable string

	flag.StringVar(&databaseURL, "database-url", "", "PostgreSQL database connection URL")
	flag.StringVar(&migrationsPath, "migrations-path", "", "path to migrations")
	flag.StringVar(&migrationsTable, "migrations-table", "schema_migrations", "name of migrations table")
	flag.Parse()

	if databaseURL == "" {
		panic("database-url is required")
	}
	if migrationsPath == "" {
		panic("migrations-path is required")
	}

	m, err := migrate.New(
		"file://"+migrationsPath,
		databaseURL,
	)
	if err != nil {
		panic(err)
	}
	defer m.Close()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("no migrations to apply")
			return
		}
		panic(err)
	}

	fmt.Println("migrations applied successfully")
}
