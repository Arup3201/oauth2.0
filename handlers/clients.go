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
)

const (
	CLIENT_SECRET_LENGTH = 15
	COLLECTION_CLIENTS   = "clients"
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
