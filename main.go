package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/arup3201/oauth2.0/db"
	"github.com/arup3201/oauth2.0/handlers"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mongodb"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const (
	HOST = "127.0.0.1"
	PORT = 8081
)

func main() {
	// migrations

	client, err := db.GetMongoClient()
	defer db.DisconnectMongoClient(client)
	if err != nil {
		log.Fatalf("mongodb client connection error: %s", err)
	}
	dbName, err := db.GetDBName()
	if err != nil {
		log.Fatalf("mongodb database name error: %s", err)
	}
	driver, err := mongodb.WithInstance(client, &mongodb.Config{
		DatabaseName: dbName,
	})
	if err != nil {
		log.Fatalf("mongodb driver instance create error: %s", err)
	}
	m, err := migrate.NewWithDatabaseInstance(
		"file://migrations",
		dbName, driver)
	if err != nil {
		log.Fatalf("mongodb migration error: %s", err)
	}
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatalf("migration failed: %v", err)
	}

	// HTTP handlers

	mux := http.NewServeMux()
	mux.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images"))))
	mux.HandleFunc("GET /register", handlers.RegisterPage)
	mux.HandleFunc("GET /login", handlers.LoginPage)

	mux.HandleFunc("POST /register", handlers.Register)
	mux.HandleFunc("POST /login", handlers.Login)
	mux.HandleFunc("GET /auth", handlers.Authorize)

	mux.HandleFunc("POST /clients", handlers.ClientRegister)
	mux.HandleFunc("POST /clients/scopes", handlers.AddClientScopes)

	// server

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", HOST, PORT),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler:      mux,
	}

	log.Printf("server started at %s:%d", HOST, PORT)

	err = server.ListenAndServe()
	if err != nil {
		log.Fatalf("error starting server")
	}
}
