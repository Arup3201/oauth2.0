package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/arup3201/oauth2.0/db"
	"github.com/arup3201/oauth2.0/models"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	CLIENT_SECRET_LENGTH     = 15
	COLLECTION_CLIENTS       = "clients"
	COLLECTION_CLIENT_SCOPES = "client_scopes"
)

func randomKeyGenerator(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random key generate error: %w", err)
	}

	hasher := sha256.New()
	if _, err := hasher.Write(b); err != nil {
		return "", fmt.Errorf("random key hash error: %w", err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func ClientRegister(w http.ResponseWriter, r *http.Request) {
	respondPayloadError := func(err error) {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to register client",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInternalError := func(err error) {
		errorBody := models.InternalServerError(r.URL.Path, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to register client",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}

	var request models.ClientRegisterRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		respondPayloadError(err)
		return
	}
	if err := validator.New().Struct(request); err != nil {
		respondPayloadError(err)
		return
	}

	id := uuid.New()
	clientId := id.String()

	clientSecret, err := randomKeyGenerator(CLIENT_SECRET_LENGTH)
	if err != nil {
		respondInternalError(fmt.Errorf("client secret generate error: %w", err))
		return
	}

	client, err := db.GetMongoClient()
	if err != nil {
		respondInternalError(err)
		return
	}
	defer db.DisconnectMongoClient(client)

	collection, err := db.GetMongoCollection(client, COLLECTION_CLIENTS)
	if err != nil {
		respondInternalError(err)
		return
	}

	clientObj := models.CreateClient(clientId, clientSecret, request.Name, request.RedirectURI)
	_, err = collection.InsertOne(context.TODO(), clientObj)
	if err != nil {
		respondInternalError(err)
		return
	}

	response := models.HTTPResponse{
		Status:  models.STATUS_SUCCESS,
		Message: "Client registration successful",
		Data: map[string]string{
			"client_id":           clientObj.Id,
			"client_secret":       clientObj.ClientSecret,
			"client_name":         clientObj.Name,
			"client_redirect_uri": clientObj.RedirectURI,
		},
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func AddClientScopes(w http.ResponseWriter, r *http.Request) {
	respondPayloadError := func(err error) {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to add client scopes",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondClientNotFound := func() {
		errorBody := models.ClientNotFound(r.URL.Path, fmt.Errorf("no client found with given clientID"))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to add client scopes",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondSecretMismatch := func(err error) {
		errorBody := models.ClientSecretMismatchError(r.URL.Path, fmt.Errorf("client provided secret key and original mismatch: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to add client scopes",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInternalError := func(err error) {
		errorBody := models.InternalServerError(r.URL.Path, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to add client scopes",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}

	var request models.ClientScopesRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		respondPayloadError(err)
		return
	}
	if err := validator.New().Struct(request); err != nil {
		respondPayloadError(err)
		return
	}

	client, err := db.GetMongoClient()
	if err != nil {
		respondInternalError(err)
		return
	}
	defer db.DisconnectMongoClient(client)

	// find and verify client id and secret

	collection, err := db.GetMongoCollection(client, COLLECTION_CLIENTS)
	if err != nil {
		respondInternalError(err)
		return
	}

	cursor, err := collection.Find(context.TODO(), bson.M{"_id": request.ClientId})
	if err != nil {
		respondInternalError(err)
		return
	}

	var results []models.Client
	err = cursor.All(context.TODO(), &results)
	if err != nil {
		respondInternalError(err)
		return
	}

	if len(results) < 1 {
		respondClientNotFound()
		return
	}

	clientObj := results[0]
	if clientObj.ClientSecret != request.ClientSecret {
		respondSecretMismatch(err)
		return
	}

	// add scopes to the client_scopes collection

	clientScopesCollection, err := db.GetMongoCollection(client, COLLECTION_CLIENT_SCOPES)
	if err != nil {
		respondInternalError(err)
		return
	}

	clientScope := models.CreateClientScope(clientObj.Id, request.Scopes)
	_, err = clientScopesCollection.InsertOne(context.TODO(), clientScope)
	if err != nil {
		respondInternalError(err)
		return
	}

	// HTTP response

	response := models.HTTPResponse{
		Status:  models.STATUS_SUCCESS,
		Message: "User registration successful",
		Data: map[string]any{
			"clientId": clientScope.ClientId,
			"scopes":   clientScope.Scopes,
		},
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}
