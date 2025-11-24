package handlers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arup3201/oauth2.0/constants"
	"github.com/arup3201/oauth2.0/models"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
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
		diagnoseMongoDB(t)
		cleanupMongoDB(t)
	})
	t.Run("register success response with user id", func(t *testing.T) {
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
		var response models.HTTPResponse
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fail()
			t.Logf("failed to decode response: %s", err)
		}
		assert.Equal(t, "Success", response.Status)
		assert.NotEqual(t, nil, response.Data)
		cleanupMongoDB(t)
	})
	t.Run("register failure with no email", func(t *testing.T) {
		// prepare
		_, password := "test@example.com", "123"
		password = base64.StdEncoding.EncodeToString([]byte(password))
		data := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{
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
		assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)
		var response models.HTTPResponse
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fail()
			t.Logf("failed to decode response: %s", err)
		}
		assert.Equal(t, "Error", response.Status)
		assert.Equal(t, constants.ERROR_INVALID_PAYLOAD, response.Error.Code)
		cleanupMongoDB(t)
	})
	t.Run("register failure with invalid email", func(t *testing.T) {
		// prepare
		email, password := "test.example.com", "123"
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
		assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)
		var response models.HTTPResponse
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fail()
			t.Logf("failed to decode response: %s", err)
		}
		assert.Equal(t, "Error", response.Status)
		assert.Equal(t, constants.ERROR_INVALID_PAYLOAD, response.Error.Code)
		cleanupMongoDB(t)
	})
	t.Run("register failure with no password", func(t *testing.T) {
		// prepare
		email, _ := "test@example.com", "123"
		data := struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}{
			Email: email,
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
		assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)
		var response models.HTTPResponse
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fail()
			t.Logf("failed to decode response: %s", err)
		}
		assert.Equal(t, "Error", response.Status)
		assert.Equal(t, constants.ERROR_INVALID_PAYLOAD, response.Error.Code)
		cleanupMongoDB(t)
	})
	t.Run("register failure for password encoding error", func(t *testing.T) {
		// prepare
		email, password := "test@example.com", "123"
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
		assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)
		var response models.HTTPResponse
		if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
			t.Fail()
			t.Logf("failed to decode response: %s", err)
		}
		assert.Equal(t, "Error", response.Status)
		assert.Equal(t, constants.ERROR_INVALID_PAYLOAD, response.Error.Code)
		cleanupMongoDB(t)
	})
	t.Run("register password compare test", func(t *testing.T) {
		t.Run("register success with 201 status code and response", func(t *testing.T) {
			// prepare
			email, password := "test@example.com", "123"
			encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))
			data := struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}{
				Email:    email,
				Password: encodedPassword,
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
			dbPass, err := getUserPassword(t, email) // hashed password
			if err != nil {
				t.Fail()
				t.Logf("failed to get password for email: %s", err)
				return
			}
			bcrypt.CompareHashAndPassword([]byte(dbPass), []byte(password))
			cleanupMongoDB(t)
		})
	})
}
