package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/arup3201/oauth2.0/db"
	"github.com/arup3201/oauth2.0/models"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"golang.org/x/crypto/bcrypt"
)

func hashPassword(password []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

func createToken(email string, tokenType string, exp time.Time) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256,
		jwt.MapClaims{
			"email": email,
			"type":  tokenType,
			"exp":   exp,
		})

	signSecret := os.Getenv("TOKEN_SECRET")
	if signSecret == "" {
		return "", fmt.Errorf("[ERROR] environment variable TOKEN_SECRET is missing")
	}
	tokenString, err := token.SignedString(signSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func Register(w http.ResponseWriter, r *http.Request) {
	var request models.UserRegisterRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}
	if err := validator.New().Struct(request); err != nil {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
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
		errorBody := models.PasswordEncodingError(r.URL.Path, fmt.Errorf("error in decoding base64 register password: %w", err))
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
	hashed, err := hashPassword([]byte(request.Password))
	if err != nil {
		errorBody := models.InternalServerError(r.URL.Path, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	request.Password = string(hashed)

	client := db.GetMongoClient()
	defer db.DisconnectMongoClient(client)

	collection := db.GetMongoCollection(client, "users")
	user := models.CreateUser(request.Email, request.Password)
	result, err := collection.InsertOne(context.TODO(), user)

	if err != nil {
		errorBody := models.InternalServerError(r.URL.Path, err)
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
		Status:  "Success",
		Message: "User registration successful",
		Data: map[string]string{
			"_id": result.InsertedID.(bson.ObjectID).String(),
		},
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func Login(w http.ResponseWriter, r *http.Request) {
	var request models.UserRegisterRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}
	if err := validator.New().Struct(request); err != nil {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(request.Password)
	if err != nil {
		errorBody := models.PasswordEncodingError(r.URL.Path, fmt.Errorf("error in decoding base64 register password: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	request.Password = string(decoded)

	client := db.GetMongoClient()
	defer db.DisconnectMongoClient(client)

	coll := db.GetMongoCollection(client, "users")
	cursor, err := coll.Find(context.TODO(), bson.M{"email": request.Email})
	if err != nil {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("error in finding user with email: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	var results []models.User
	err = cursor.All(context.TODO(), &results)
	if err != nil {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("error in getting all documents: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	if len(results) < 1 {
		errorBody := models.UserNotFoundError(r.URL.Path, fmt.Errorf("no user found with given email: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	user := results[0]
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		errorBody := models.PasswordMismatchError(r.URL.Path, fmt.Errorf("user provided password and hashed password mismatch: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	authToken, err := createToken(request.Email, "auth", time.Now().Add(time.Minute*5))
	if err != nil {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("error in getting all documents: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	refreshExpTime := time.Now().Add(time.Hour * 24)
	refreshToken, err := createToken(request.Email, "refresh", refreshExpTime)
	if err != nil {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("error in getting all documents: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  "Error",
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
		return
	}

	response := models.HTTPResponse{
		Status:  "Success",
		Message: "User authentication successful",
		Data: map[string]string{
			"token": authToken,
		},
	}
	json.NewEncoder(w).Encode(response)

	cookie := http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   refreshExpTime.Hour() * 3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, &cookie)
}
