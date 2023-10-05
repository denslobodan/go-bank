package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestStorageFunctions(t *testing.T) {
	ctx := context.Background()

	// Start PostgreSQL container
	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:latest",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     "postgres",
				"POSTGRES_PASSWORD": "gobank",
				"POSTGRES_DB":       "postgres",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections"),
		},
		Started: true,
	}

	pgContainer, err := testcontainers.GenericContainer(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	defer pgContainer.Terminate(ctx)

	// Create PostgresStore with the connection string
	store, err := NewPostgresStore()
	if err != nil {
		t.Fatal(err)
	}

	// Create account table
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}

	// Run tests with the store
	// ...
	// Create a test accJoe
	accJoe := &Account{
		ID:                2,
		FirstName:         "Joe",
		LastName:          "Doe",
		Number:            1234567890,
		EncryptedPassword: "hashedpassword",
		Balance:           1000,
		CreatedAt:         time.Now(),
	}

	// Create the account using the store
	err = store.CreateAccount(accJoe)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that the account was created
	getAccount, err := store.GetAccountByID(accJoe.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Create second account
	accJane, _ := NewAccount("Jane", "Eyre", "herPass")

	// Check GetAccoutns
	gotAccounts, err := store.GetAccounts()
	if err != nil {
		t.Fatal(err)
	}

	var wantAccounts []*Account
	wantAccounts = append(wantAccounts, accJane, accJoe)

	if reflect.DeepEqual(gotAccounts, wantAccounts) {
		t.Error(err)
	}

	// Compare the created account with the original account
	assert.Equal(t, getAccount.FirstName, accJoe.FirstName)
	assert.Equal(t, getAccount.LastName, accJoe.LastName)
	assert.Equal(t, getAccount.EncryptedPassword, accJoe.EncryptedPassword)
	assert.Equal(t, getAccount.Number, accJoe.Number)
	assert.Equal(t, getAccount.Balance, accJoe.Balance)
	// assert.Equal(t, getAccount, accJoe)

	updateAccJoe := &Account{
		ID:                2,
		FirstName:         "Joe",
		LastName:          "Doe",
		Number:            9876543210,
		EncryptedPassword: "hashedpassword",
		Balance:           1000,
		CreatedAt:         time.Now(),
	}
	if err = store.UpdateAccount(updateAccJoe); err != nil {
		t.Fatal(err)
	}

	assert.NotEqual(t, accJoe.Number, updateAccJoe.Number)

	if err = store.DeleteAccount(updateAccJoe.ID); err != nil {
		t.Fatal(err)
	}

	_, err = store.GetAccountByID(updateAccJoe.ID)
	assert.NotNil(t, err)

	// Cleanup
	err = store.db.Close()
	if err != nil {
		t.Fatal(err)
	}
}
