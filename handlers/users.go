package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/arup3201/oauth2.0/db"
	"github.com/arup3201/oauth2.0/models"
	"github.com/arup3201/oauth2.0/utils"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/v2/bson"
	"golang.org/x/crypto/bcrypt"
)

const (
	COLLECTION_USERS          = "users"
	COLLECTION_SCOPES         = "scopes"
	COOKIE_REFRESH_TOKEN_NAME = "refresh_token"
	TYPE_AUTHENCATION_TOKEN   = "auth"
	TYPE_REFRESH_TOKEN        = "refresh"
	AUTHENTICATION_TOKEN_EXP  = 15 * time.Minute
	AUTHORIZATION_CODE_EXP    = 10 * time.Minute
	ACCESS_TOKEN_EXP          = 1 * time.Hour
	REFRESH_TOKEN_EXP         = 24 * time.Hour
)

func hashPassword(password []byte) ([]byte, error) {
	hash, err := bcrypt.GenerateFromPassword(password, 10)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

func getJWTExp(duration time.Duration) int64 {
	return time.Now().Add(duration).Unix()
}

func generateAuthenticationToken(userId, email string) (string, error) {
	claims := jwt.MapClaims{
		"sub":   userId,
		"email": email,
		"exp":   getJWTExp(AUTHENTICATION_TOKEN_EXP),
	}
	return utils.GetJWTString(claims)
}

func generateAuthorizationCode(scopes, clientId string) (string, error) {
	claims := jwt.MapClaims{
		"scopes":    scopes,
		"client_id": clientId,
		"exp":       getJWTExp(AUTHORIZATION_CODE_EXP),
	}
	return utils.GetJWTString(claims)
}

func generateAccessToken(sub, email, clientId, scopes string) (string, error) {
	claims := jwt.MapClaims{
		"sub":       sub,
		"email":     email,
		"client_id": clientId,
		"scopes":    scopes,
		"type":      TYPE_AUTHENCATION_TOKEN,
		"exp":       getJWTExp(ACCESS_TOKEN_EXP),
	}
	return utils.GetJWTString(claims)
}

func generateRefreshToken(sub, clientId string) (string, error) {
	claims := jwt.MapClaims{
		"sub":       sub,
		"client_id": clientId,
		"type":      TYPE_REFRESH_TOKEN,
		"exp":       getJWTExp(ACCESS_TOKEN_EXP),
	}
	return utils.GetJWTString(claims)
}

func Register(w http.ResponseWriter, r *http.Request) {
	respondPayloadError := func(err error) {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInternalError := func(err error) {
		errorBody := models.InternalServerError(r.URL.Path, err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondEncodingError := func(err error) {
		errorBody := models.PasswordEncodingError(r.URL.Path, fmt.Errorf("error in decoding base64 register password: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to register",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}

	var request models.UserRegisterRequest
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

	decoded, err := base64.StdEncoding.DecodeString(request.Password)
	if err != nil {
		respondEncodingError(err)
		return
	}

	request.Password = string(decoded)
	hashed, err := hashPassword([]byte(request.Password))
	if err != nil {
		respondInternalError(err)
		return
	}

	request.Password = string(hashed)

	client, err := db.GetMongoClient()
	if err != nil {
		respondInternalError(err)
		return
	}
	defer db.DisconnectMongoClient(client)

	collection, err := db.GetMongoCollection(client, COLLECTION_USERS)
	if err != nil {
		respondInternalError(err)
		return
	}
	id := uuid.New()
	userId := id.String()
	user := models.CreateUser(userId, request.Email, request.Password)
	_, err = collection.InsertOne(context.TODO(), user)

	if err != nil {
		respondInternalError(err)
		return
	}

	response := models.HTTPResponse{
		Status:  models.STATUS_SUCCESS,
		Message: "User registration successful",
		Data: map[string]string{
			"userId": user.Id,
			"email":  user.Email,
		},
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func Login(w http.ResponseWriter, r *http.Request) {
	respondInvalidQuery := func(err error) {
		errorBody := models.InvalidQueryError(r.URL.Path, fmt.Errorf("error parsing request query values: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInvalidPayload := func(err error) {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding register payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInvalidEncoding := func(err error) {
		errorBody := models.PasswordEncodingError(r.URL.Path, fmt.Errorf("error in decoding base64 register password: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInternalError := func(err error) {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("internal server error: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondUserNotFound := func() {
		errorBody := models.UserNotFoundError(r.URL.Path, fmt.Errorf("no user found with given email"))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondPasswordMismatch := func(err error) {
		errorBody := models.PasswordMismatchError(r.URL.Path, fmt.Errorf("user provided password and hashed password mismatch: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: "Failed to login",
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}

	queries := r.URL.Query()
	responseType := queries.Get("response_type")
	clientId := queries.Get("client_id")
	redirectUri := queries.Get("redirect_uri")
	scope := queries.Get("scope")
	state := queries.Get("state")

	if responseType == "" || clientId == "" || redirectUri == "" || scope == "" || state == "" {
		respondInvalidQuery(fmt.Errorf("some of the required queries response_type, client_id, redirect_uri, scope or state are missing or malformed"))
		return
	}

	var request models.UserRegisterRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&request); err != nil {
		respondInvalidPayload(err)
		return
	}
	if err := validator.New().Struct(request); err != nil {
		respondInvalidPayload(err)
		return
	}

	decoded, err := base64.StdEncoding.DecodeString(request.Password)
	if err != nil {
		respondInvalidEncoding(err)
		return
	}

	request.Password = string(decoded)

	client, err := db.GetMongoClient()
	if err != nil {
		respondInternalError(err)
		return
	}
	defer db.DisconnectMongoClient(client)

	coll, err := db.GetMongoCollection(client, COLLECTION_USERS)
	if err != nil {
		respondInternalError(err)
		return
	}
	cursor, err := coll.Find(context.TODO(), bson.M{"email": request.Email})
	if err != nil {
		respondInternalError(err)
		return
	}

	var results []models.User
	err = cursor.All(context.TODO(), &results)
	if err != nil {
		respondInternalError(err)
		return
	}

	if len(results) < 1 {
		respondUserNotFound()
		return
	}

	user := results[0]
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		respondPasswordMismatch(err)
		return
	}

	authenticationToken, err := generateAuthenticationToken(user.Id, user.Email)
	if err != nil {
		respondInternalError(fmt.Errorf("error generating authentication token: %w", err))
		return
	}

	authUrl := `/auth?` +
		`response_type=` + responseType +
		`&client_id=` + clientId +
		`&redirect_uri=` + redirectUri +
		`&scope=` + scope +
		`&state=` + state
	authenticationCookie := &http.Cookie{
		Name:     "authentication",
		Value:    authenticationToken,
		Path:     "/",
		Expires:  time.Now().Add(15 * time.Minute),
		HttpOnly: true,
		Secure:   true,
	}
	http.SetCookie(w, authenticationCookie)
	http.Redirect(w, r, authUrl, http.StatusSeeOther)
}

func RequestAccess(w http.ResponseWriter, r *http.Request) {
	errMessage := "Failed to request access"
	respondInvalidQuery := func(err error) {
		errorBody := models.InvalidQueryError(r.URL.Path, fmt.Errorf("error parsing request query values: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondClientNotFound := func() {
		errorBody := models.ClientNotFound(r.URL.Path, fmt.Errorf("no client found with given clientID"))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondScopeNotFound := func() {
		errorBody := models.ResourceNotFound(r.URL.Path, fmt.Errorf("no scope found with given scope id"))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInternalError := func(err error) {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("internal server error: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}

	queries := r.URL.Query()
	responseType := queries.Get("response_type")
	clientId := queries.Get("client_id")
	redirectUri := queries.Get("redirect_uri")
	scope := queries.Get("scope")
	state := queries.Get("state")

	if responseType == "" || clientId == "" || redirectUri == "" || scope == "" || state == "" {
		respondInvalidQuery(fmt.Errorf("some of the required queries response_type, client_id, redirect_uri, scope or state are missing or malformed"))
		return
	}

	// get mongodb client

	client, err := db.GetMongoClient()
	if err != nil {
		respondInternalError(err)
		return
	}
	defer db.DisconnectMongoClient(client)

	// find and verify client id

	collection, err := db.GetMongoCollection(client, COLLECTION_CLIENTS)
	if err != nil {
		respondInternalError(err)
		return
	}

	cursor, err := collection.Find(context.TODO(), bson.M{"_id": clientId})
	if err != nil {
		respondInternalError(err)
		return
	}

	var clientObjs []models.Client
	err = cursor.All(context.TODO(), &clientObjs)
	if err != nil {
		respondInternalError(err)
		return
	}

	if len(clientObjs) < 1 {
		respondClientNotFound()
		return
	}

	// fetch scopes

	collection, err = db.GetMongoCollection(client, COLLECTION_SCOPES)
	if err != nil {
		respondInternalError(err)
		return
	}

	scopes := strings.Fields(scope)

	scopeDescriptions := []string{}
	for i := range len(scopes) {
		cursor, err = collection.Find(context.TODO(), bson.M{"_id": scopes[i]})
		if err != nil {
			respondInternalError(err)
			return
		}

		var results []models.Scope
		err = cursor.All(context.TODO(), &results)
		if err != nil {
			respondInternalError(err)
			return
		}

		if len(results) < 1 {
			respondScopeNotFound()
			return
		}

		scopeDescriptions = append(scopeDescriptions, results[0].UserFacingDescription)
	}

	// consent page
	templateData := struct {
		AppIcon    string
		ClientName string
		ClientURL  string
		Scopes     []string
	}{
		AppIcon:    string(clientObjs[0].Name[0]),
		ClientName: clientObjs[0].Name,
		ClientURL:  "http://example.com", // TODO: Client web origin URL
		Scopes:     scopeDescriptions,
	}
	err = parseExecuteTemplate("templates/access.tmpl", w, &templateData)
	if err != nil {
		respondInternalError(err)
		return
	}
}

func Authorize(w http.ResponseWriter, r *http.Request) {
	errMessage := "Failed to request access"
	respondInvalidQuery := func(err error) {
		errorBody := models.InvalidQueryError(r.URL.Path, fmt.Errorf("error parsing request query values: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondClientNotFound := func() {
		errorBody := models.ClientNotFound(r.URL.Path, fmt.Errorf("no client found with given clientID"))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInternalError := func(err error) {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("internal server error: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}

	queries := r.URL.Query()
	responseType := queries.Get("response_type")
	clientId := queries.Get("client_id")
	redirectUri := queries.Get("redirect_uri")
	scope := queries.Get("scope")
	state := queries.Get("state")

	if responseType == "" || clientId == "" || redirectUri == "" || scope == "" || state == "" {
		respondInvalidQuery(fmt.Errorf("some of the required queries response_type, client_id, redirect_uri, scope or state are missing or malformed"))
		return
	}

	// get mongodb client

	client, err := db.GetMongoClient()
	if err != nil {
		respondInternalError(err)
		return
	}
	defer db.DisconnectMongoClient(client)

	// verify redirect URI

	collection, err := db.GetMongoCollection(client, COLLECTION_CLIENTS)
	if err != nil {
		respondInternalError(err)
		return
	}

	cursor, err := collection.Find(context.TODO(), bson.M{"_id": clientId})
	if err != nil {
		respondInternalError(err)
		return
	}

	var clientObjs []models.Client
	err = cursor.All(context.TODO(), &clientObjs)
	if err != nil {
		respondInternalError(err)
		return
	}

	if len(clientObjs) < 1 {
		respondClientNotFound()
		return
	}

	if clientObjs[0].RedirectURI != redirectUri {
		respondInvalidQuery(fmt.Errorf("request redirect_uri does not match client's registered redirect_uri"))
		return
	}

	// generate authorization code

	authorizationCode, err := generateAuthorizationCode(scope, clientId)
	if err != nil {
		respondInternalError(fmt.Errorf("authorization code generate error: %w", err))
		return
	}

	// HTTP Redirection with Authorization code

	cookies := r.CookiesNamed("authentication")
	if len(cookies) > 0 {
		url := fmt.Sprintf("%s?code=%s&state=%s&auth=%s", redirectUri, authorizationCode, state, cookies[0].Value)
		http.Redirect(w, r, url, http.StatusSeeOther)
		return
	}

	respondInvalidQuery(fmt.Errorf("user authentication token not found"))
}

func GetToken(w http.ResponseWriter, r *http.Request) {
	errMessage := "error generating token"
	respondInvalidPayload := func(err error) {
		errorBody := models.InvalidPayloadError(r.URL.Path, fmt.Errorf("error in decoding request payload: %w", err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondClientNotFound := func() {
		errorBody := models.ClientNotFound(r.URL.Path, fmt.Errorf("no client found with given clientID"))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}
	respondInternalError := func(err error) {
		errorBody := models.InternalServerError(r.URL.Path, fmt.Errorf("internal server error: %w", err))
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(models.HTTPResponse{
			Status:  models.STATUS_ERROR,
			Message: errMessage,
			Error:   errorBody,
		})
		log.Printf("[ERROR] %s", errorBody)
	}

	var request struct {
		GrantType         string `json:"grant_type" validate:"required"`
		AuthorizationCode string `json:"code" validate:"required"`
		ClientID          string `json:"client_id" validate:"required"`
		ClientSecret      string `json:"client_secret" validate:"required"`
		RedirectURI       string `json:"redirect_uri" validate:"required"`
		AuthToken         string `json:"auth" validate:"required"`
	}

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		respondInvalidPayload(fmt.Errorf("error decoding request: %w", err))
		return
	}
	if err := validator.New().Struct(request); err != nil {
		respondInvalidPayload(fmt.Errorf("error validating request body: %w", err))
		return
	}

	// get mongodb client

	client, err := db.GetMongoClient()
	if err != nil {
		respondInternalError(err)
		return
	}
	defer db.DisconnectMongoClient(client)

	// verify redirect URI

	collection, err := db.GetMongoCollection(client, COLLECTION_CLIENTS)
	if err != nil {
		respondInternalError(err)
		return
	}

	cursor, err := collection.Find(context.TODO(), bson.M{"_id": request.ClientID})
	if err != nil {
		respondInternalError(err)
		return
	}

	var clientObjs []models.Client
	err = cursor.All(context.TODO(), &clientObjs)
	if err != nil {
		respondInternalError(err)
		return
	}

	if len(clientObjs) < 1 {
		respondClientNotFound()
		return
	}

	if clientObjs[0].ClientSecret != request.ClientSecret {
		respondInvalidPayload(fmt.Errorf("client credentials are wrong"))
		return
	}

	if clientObjs[0].RedirectURI != request.RedirectURI {
		respondInvalidPayload(fmt.Errorf("request redirect_uri does not match client's registered redirect_uri"))
		return
	}

	// access token and refresh token

	payload, err := utils.VerifyJWT(request.AuthToken)
	if err != nil {
		respondInvalidPayload(fmt.Errorf("user authentication token not valid: %w", err))
		return
	}
	claims := payload.Claims.(jwt.MapClaims)
	userId, email := claims["sub"].(string), claims["email"].(string)
	payload, err = utils.VerifyJWT(request.AuthorizationCode)
	if err != nil {
		respondInvalidPayload(fmt.Errorf("user authorization code not valid"))
		return
	}
	claims = payload.Claims.(jwt.MapClaims)
	scopes := claims["scopes"].(string)
	accessToken, err := generateAccessToken(userId, email, request.ClientID, scopes)
	if err != nil {
		respondInternalError(err)
		return
	}
	refreshToken, err := generateRefreshToken(userId, request.ClientID)
	if err != nil {
		respondInternalError(err)
		return
	}

	json.NewEncoder(w).Encode(models.HTTPResponse{
		Status:  models.STATUS_SUCCESS,
		Message: "Access token recieved",
		Data: map[string]any{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"refresh_token": refreshToken,
			"expires_in":    ACCESS_TOKEN_EXP.Seconds(),
		},
	})
}
