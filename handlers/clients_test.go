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

func registerClient(t testing.TB) (string, string) {
	name, redirect := "Test App", "http://example.com/callback"
	data := models.ClientRegisterRequest{
		Name:        name,
		RedirectURI: redirect,
	}
	body := getRequestBody(t, data)
	request, err := http.NewRequest("POST", "/clients", body)
	if err != nil {
		t.Fatalf("create request error: %s", err)
	}
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, request)

	var response models.HTTPResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode response error: %s", err)
	}

	return response.Data.(map[string]any)["client_id"].(string), response.Data.(map[string]any)["client_secret"].(string)
}

func TestAddClientScopes(t *testing.T) {
	t.Run("add scopes success, response code 200", func(t *testing.T) {
		// prepare
		scopes := []string{"1", "2"} // refer to migrations for scopes
		clientId, clientSecret := registerClient(t)
		data := models.ClientScopesRequest{
			ClientId:     clientId,
			ClientSecret: clientSecret,
			Scopes:       scopes,
		}
		body := getRequestBody(t, data)
		request, err := http.NewRequest("POST", "/clients/scopes", body)
		if err != nil {
			t.Fatalf("create request error: %s", err)
		}
		rec := httptest.NewRecorder()

		// act
		handler.ServeHTTP(rec, request)

		// assert
		assert.Equal(t, http.StatusCreated, rec.Result().StatusCode)
	})
	t.Run("add scopes success, check client scopes", func(t *testing.T) {
		// prepare
		scopes := []string{"1", "2"} // refer to migrations for scopes
		clientId, clientSecret := registerClient(t)
		data := models.ClientScopesRequest{
			ClientId:     clientId,
			ClientSecret: clientSecret,
			Scopes:       scopes,
		}
		body := getRequestBody(t, data)
		request, err := http.NewRequest("POST", "/clients/scopes", body)
		if err != nil {
			t.Fatalf("create request error: %s", err)
		}
		rec := httptest.NewRecorder()

		// act
		handler.ServeHTTP(rec, request)

		// assert
		results, err := getClientScopes(t, clientId)
		if err != nil {
			t.Fail()
			t.Logf("failed to get scopes: %s", err)
			return
		}
		assert.Equal(t, scopes, results)
	})
}
