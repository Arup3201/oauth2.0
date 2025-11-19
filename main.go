package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	HOST = "127.0.0.1"
	PORT = 8081
)

func authorize(w http.ResponseWriter, r *http.Request) {
	content, err := os.ReadFile("templates/permissions.txt")
	if err != nil {
		http.Error(w, fmt.Sprintf("error in opening template permissions: %s", err), 500)
	}

	tmpl, err := template.New("permissions_template").Parse(string(content))
	if err != nil {
		http.Error(w, fmt.Sprintf("error parsing template: %s", err), 500)
	}

	data := struct {
		Client      string
		Permissions []string
	}{
		Client: "OAuth 2.0 Client",
		Permissions: []string{
			"View files located at Go Server",
			"Edit files located at Go Server",
			"Delete files located at Go Server",
		},
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, fmt.Sprintf("error executing template: %s", err), 500)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", authorize)
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
