package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/denslobodan/go-bank/api"
	store "github.com/denslobodan/go-bank/pkg/storage"

	_ "github.com/lib/pq"
)

func NewDB() (db *sql.DB, err error) {
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	var connStr = fmt.Sprintf("host=%s port=%s user=postgres dbname=postgres password=gobank sslmode=disable",
		dbHost,
		dbPort,
	)
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть базу данных: %v", err)
	}
	return db, nil
}

func main() {

	db, err := NewDB()
	if err != nil {
		log.Fatal(err)
	}

	store, err := store.NewPostgresStore(db)
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := api.NewAPIServer(":3030", store)
	server.Run()

}
