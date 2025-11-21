package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/arup3201/oauth2.0/handlers"
)

const (
	HOST = "127.0.0.1"
	PORT = 8081
)

func main() {
	mux := http.NewServeMux()
	mux.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images"))))
	mux.HandleFunc("GET /register-page", handlers.RegisterPage)
	mux.HandleFunc("GET /login-page", handlers.LoginPage)
	mux.HandleFunc("GET /consent-page", handlers.ConsentPage)

	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", HOST, PORT),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 20 * time.Second,
		Handler:      mux,
	}

	log.Printf("server started at %s:%d", HOST, PORT)

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("error starting server")
	}
}
