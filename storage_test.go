package main

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestCreateAccount(t *testing.T) {
	// Подключение к базе данных
	db, err := sql.Open("postgres", "user=postgres dbname=postgres password=gobank sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Создание экземпляра хранилища
	store := &PostgresStore{db: db}

	// Создание объекта Account для тестирования
	acc := &Account{
		FirstName: "John",
		LastName:  "Doe",
		Number:    123456,
		Balance:   1000,
		CreatedAt: time.Now(),
	}

	// Вызов функции CreateAccount
	err = store.CreateAccount(acc)

	// Проверка наличия ошибок
	if err != nil {
		t.Errorf("CreateAccount returned an error: %v", err)
	}

	// Проверка, что аккаунт был успешно создан
	// Можно добавить дополнительные проверки на значения полей аккаунта
	if acc.ID == 0 {
		t.Error("CreateAccount did not assign an ID to the account")
	}
}
