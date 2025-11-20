package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	HOST = "127.0.0.1"
	PORT = 8081
)

func parseExecuteTemplate(templateFile string, w io.Writer, data any) error {
	file, err := os.ReadFile(templateFile)
	if err != nil {
		log.Printf("[ERROR] error opening template file")
		return err
	}

	templateFilename := strings.Split(templateFile, ".")
	tmpl, err := template.New(templateFilename[0] + ".html").Parse(string(file))
	if err != nil {
		log.Printf("[ERROR] error parsing template file")
		return err
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		log.Printf("[ERROR] error parsing template file")
		return err
	}

	return nil
}

func registerPage(w http.ResponseWriter, r *http.Request) {
	parseExecuteTemplate("templates/register.tmpl", w, nil)
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	parseExecuteTemplate("templates/login.tmpl", w, nil)
}

func consentPage(w http.ResponseWriter, r *http.Request) {
	// extract client data and scopes
	parseExecuteTemplate("templates/permissions.tmpl", w, nil)
}

func main() {

	mux := http.NewServeMux()
	mux.Handle("/images/", http.StripPrefix("/images/", http.FileServer(http.Dir("images"))))
	mux.HandleFunc("GET /register-page", registerPage)
	mux.HandleFunc("GET /login-page", loginPage)
	mux.HandleFunc("GET /consent-page", consentPage)

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
