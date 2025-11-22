package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arup3201/oauth2.0/models"
	"github.com/stretchr/testify/assert"
)

func TestRegisterHandler(t *testing.T) {
	t.Run("register success with 201 status code and response", func(t *testing.T) {
		// prepare
		email, password := "test@example.com", "123"
		password = base64.StdEncoding.EncodeToString([]byte(password))
		data := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{
			Email:    email,
			Password: password,
		}
		body := getRequestBody(t, data)
		request, err := http.NewRequest("GET", "/register", body)
		if err != nil {
			t.Fail()
			t.Logf("failed to create a request: %s", err)
			return
		}
		rec := httptest.NewRecorder()

		// act
		handler.ServeHTTP(rec, request)

		// assert
		assert.Equal(t, http.StatusCreated, rec.Result().StatusCode)
		var response models.HTTPResponse
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fail()
			t.Logf("failed to decode response: %s", err)
		}
		cleanupMongoDB(t)
	})
}
