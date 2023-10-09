package main

import (
	"log"

	"github.com/denslobodan/go-bank/api"
	store "github.com/denslobodan/go-bank/pkg/storage"
)

var connStr = "user=postgres dbname=postgres password=gobank sslmode=disable"

func main() {

	store, err := store.NewPostgresStore(connStr)
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	server := api.NewAPIServer(":3030", store)
	server.Run()

}
