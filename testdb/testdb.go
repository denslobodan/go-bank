package testdb

// https://bunyk.github.io/posts/testcontainers_go
import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

type TestDB struct {
	Container testcontainers.Container
	DB        *sql.DB
}

func NewTestDB() (*TestDB, error) {
	ctx := context.Background()

	// Создание контейнера PostgreSQL
	req := testcontainers.ContainerRequest{
		Image:        "postgres:latest",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "test",
			"POSTGRES_PASSWORD": "test",
			"POSTGRES_DB":       "testdb",
		},
		WaitingFor: wait.ForLog(`listening on IPv4 address "0.0.0.0", port 5432`),
	}

	postgresC, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start PostgreSQL container: %w", err)
	}

	// Получение информации о подключении к контейнеру PostgreSQL
	host, err := postgresC.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get PostgreSQL container host: %w", err)
	}

	port, err := postgresC.MappedPort(ctx, "5432")
	if err != nil {
		return nil, fmt.Errorf("failed to get PostgreSQL container port: %w", err)
	}

	dbURL := fmt.Sprintf("postgres://test:test@%s:%s/testdb", host, port.Port())

	// Подключение к тестовой базе данных PostgreSQL
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL test database: %w", err)
	}

	// Проверка подключения к базе данных
	err = db.Ping()
	if err != nil {
		return nil, fmt.Errorf("failed to ping PostgreSQL test database: %w", err)
	}

	log.Println("Connected to test database")

	testDB := &TestDB{
		Container: postgresC,
		DB:        db,
	}

	return testDB, nil
}

func (tdb *TestDB) Close() error {
	err := tdb.DB.Close()
	if err != nil {
		return fmt.Errorf("failed to close PostgreSQL test database connection: %w", err)
	}

	err = tdb.Container.Terminate(context.Background())
	if err != nil {
		return fmt.Errorf("failed to terminate PostgreSQL container: %w", err)
	}

	log.Println("Closed test database")

	return nil
}
