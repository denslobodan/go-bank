package store_test

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	store "github.com/denslobodan/go-bank/internal/storage"
	"github.com/denslobodan/go-bank/pkg/types"
	_ "github.com/lib/pq"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var db *sql.DB

func TestMain(m *testing.M) {
	// uses a sensible default on windows (tcp/http) and linux/osx (socket)
	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("Could not construct pool: %s", err)
	}

	err = pool.Client.Ping()
	if err != nil {
		log.Fatalf("Could not connect to Docker: %s", err)
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Tag:        "15",
		Env: []string{
			"POSTGRES_PASSWORD=secret",
			"POSTGRES_USER=user_name",
			"POSTGRES_DB=dbname",
			"listen_addresses = '*'",
		},
	}, func(config *docker.HostConfig) {
		// set AutoRemove to true so that stopped container goes away by itself
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}

	hostAndPort := resource.GetHostPort("5432/tcp")
	databaseUrl := fmt.Sprintf("postgres://user_name:secret@%s/dbname?sslmode=disable", hostAndPort)

	log.Println("Connecting to database on url: ", databaseUrl)

	err = resource.Expire(120) // Tell docker to hard kill the container in 120 seconds
	if err != nil {
		log.Fatalf("Docker timeout: %s", err)
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	pool.MaxWait = 120 * time.Second
	if err = pool.Retry(func() error {
		db, err = sql.Open("postgres", databaseUrl)
		if err != nil {
			return err
		}
		return db.Ping()
	}); err != nil {
		log.Fatalf("Could not connect to docker: %s", err)
	}
	//Run tests
	code := m.Run()

	// You can't defer this because os.Exit doesn't care for defer
	if err := pool.Purge(resource); err != nil {
		log.Fatalf("Could not purge resource: %s", err)
	}

	os.Exit(code)
}

func TestStorageMethods(t *testing.T) {
	// all tests
	postgres, err := store.NewPostgresStore(db)
	if err != nil {
		log.Fatal("Postgres structure not created")
	}

	// Инициализируем БД
	err = postgres.Init()
	assert.NoError(t, err)

	// 	Created account
	account := &types.Account{
		FirstName:         "Bob",
		LastName:          "Ross",
		EncryptedPassword: "password",
		Number:            1235987890,
		Balance:           1000,
		CreatedAt:         time.Now().UTC(),
	}
	// Создаём аккаунт в БД
	err = postgres.CreateAccount(account)
	assert.NoError(t, err)

	account.ID = 1
	// Получаем аккаунт из БД по ID
	account, err = postgres.GetAccountByID(account.ID)
	assert.NoError(t, err, "ожидался успешный запрос")
	assert.NotNil(t, account, "ожидался непустой аккаунт")

	// Передаём неверынй ID аккаунта
	_, err = postgres.GetAccountByID(0_0)
	assert.Error(t, err, "ожидалась ошибка")

	// Получаем аккаунт из БД по номеру
	account, err = postgres.GetAccountByNumber(account.Number)
	assert.NoError(t, err, "ожидался успешный запрос")
	assert.NotNil(t, account, "ожидался непустой аккаунт")

	// Передаём неверынй номер аккаунта
	_, err = postgres.GetAccountByNumber(0_1)
	assert.Error(t, err, "ожидалась ошибка")

	// Получаем все аккаунты
	accounts, err := postgres.GetAccounts()
	assert.NoError(t, err, "ожидался успешный запрос")
	assert.NotEmpty(t, accounts, "ожидался не пустой аккаунт")

	// Обновляем имя аккаунта
	account.FirstName = "Robert"
	err = postgres.UpdateAccount(account)
	assert.NoError(t, err, "ожидался успешный запрос")

	// Проверяем обновление аккаунта
	account, err = postgres.GetAccountByID(account.ID)
	assert.NoError(t, err, "ожидался успешный запрос")
	assert.Equal(t, account.FirstName, account.FirstName, "ожидалось равное FirstName")

	// Удаляем аккаунт
	err = postgres.DeleteAccount(account.ID)
	assert.NoError(t, err, "ожидался успешный запрос")

	// Пытаемся получить несуществующий аккаунт
	account, err = postgres.GetAccountByID(account.ID)
	assert.Empty(t, account, "ожидался пустой аккаунт")
	assert.Error(t, err, "ожидалась ошибка")
}
