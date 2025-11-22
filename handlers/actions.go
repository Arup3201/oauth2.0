package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/arup3201/oauth2.0/constants"
	"github.com/arup3201/oauth2.0/db"
	"github.com/arup3201/oauth2.0/models"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func Register(w http.ResponseWriter, r *http.Request) {
	var request models.UserRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		errorBody := models.GenerateHTTPError(
			constants.ERROR_INVALID_PAYLOAD,
			"The incoming data is invalid for registration",
			"Payload contains invalid email or password",
			"Please review your email and password and try with a valid email and password",
			r.URL.Path,
			fmt.Errorf("error in decoding register payload: %w", err),
		)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(request.Password)
	if err != nil {
		errorBody := models.GenerateHTTPError(
			constants.ERROR_INVALID_PAYLOAD,
			"The incoming data encoding is invalid",
			"Payload contains invalid password encoding",
			"Please check with your user-agent to send supported password encoding",
			r.URL.Path,
			fmt.Errorf("error in decoding base64 register password: %w", err),
		)
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	request.Password = string(decoded)

	client := db.GetMongoClient()
	defer db.DisconnectMongoClient(client)

	collection := db.GetMongoCollection(client, "users")
	user := models.CreateUser(request.Email, request.Password)
	result, err := collection.InsertOne(context.TODO(), user)

	if err != nil {
		errorBody := models.GenerateHTTPError(
			constants.ERROR_INTERNAL_SERVER,
			"Server failed to register the user",
			"Server failed while adding the user to our database",
			"We are working on our server currently, please come back later for registration",
			r.URL.Path,
			fmt.Errorf("error in inserting user to database: %w", err),
		)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	response := models.HTTPResponse{
		Message: "User registration successful",
		Data: map[string]string{
			"_id": result.InsertedID.(bson.ObjectID).String(),
		},
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}
