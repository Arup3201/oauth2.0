package handlers

import (
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
)

func parseExecuteTemplate(templateFile string, w io.Writer, data any) error {
	file, err := os.ReadFile(templateFile)
	if err != nil {
		return err
	}

	templateFilename := strings.Split(templateFile, ".")
	tmpl, err := template.New(templateFilename[0] + ".html").Parse(string(file))
	if err != nil {
		return err
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		return err
	}

	return nil
}

func RegisterPage(w http.ResponseWriter, r *http.Request) {
	parseExecuteTemplate("templates/register.tmpl", w, nil)
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	parseExecuteTemplate("templates/login.tmpl", w, nil)
}
