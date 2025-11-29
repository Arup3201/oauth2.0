package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/arup3201/oauth2.0/models"
	"github.com/stretchr/testify/assert"
)

func TestClientRegister(t *testing.T) {
	t.Run("client register success 201 response code", func(t *testing.T) {
		// prepare
		name, redirect := "Test App", "http://example.com/callback"
		data := models.ClientRegisterRequest{
			Name:        name,
			RedirectURI: redirect,
		}
		body := getRequestBody(t, data)
		request, err := http.NewRequest("POST", "/clients", body)
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
		cleanupMongoDB(t)
	})
	t.Run("client register response body check", func(t *testing.T) {
		// prepare
		name, redirect := "Test App", "http://example.com/callback"
		data := models.ClientRegisterRequest{
			Name:        name,
			RedirectURI: redirect,
		}
		body := getRequestBody(t, data)
		request, err := http.NewRequest("POST", "/clients", body)
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
		assert.Equal(t, models.STATUS_SUCCESS, response.Status)
		assert.NotEqual(t, "", response.Data.(map[string]any)["client_id"])
		assert.NotEqual(t, "", response.Data.(map[string]any)["client_secret"])
		assert.Equal(t, name, response.Data.(map[string]any)["client_name"])
		assert.Equal(t, redirect, response.Data.(map[string]any)["client_redirect_uri"])
		cleanupMongoDB(t)
	})
}
