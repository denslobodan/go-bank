package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/denslobodan/go-bank/api"
	store "github.com/denslobodan/go-bank/pkg/storage"
	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

func NewDB() (*sql.DB, error) {
	err := godotenv.Load(".env")
	if err != nil {
		return nil, fmt.Errorf("не удалось загрузить файл .env: %v", err)
	}

	dbhost := os.Getenv("DB_HOST")
	dbport := os.Getenv("DB_PORT")
	dbname := os.Getenv("DB_NAME")
	dbuser := os.Getenv("DB_USER")
	dbpass := os.Getenv("DB_PASS")

	var connStr = fmt.Sprintf("host=%s port=%s user=%s dbname=%s password=%s sslmode=disable",
		dbhost,
		dbport,
		dbuser,
		dbname,
		dbpass,
	)
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, fmt.Errorf("не удалось открыть базу данных: %v", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("соединение отсутствует: %v", err)
	}

	return db, nil
}

func main() {

	db, err := NewDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

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
