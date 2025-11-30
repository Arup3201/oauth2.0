package models

import "time"

type Client struct {
	Id           string    `json:"id" bson:"_id"`
	ClientSecret string    `json:"client_secret" bson:"client_secret"`
	Name         string    `json:"name" bson:"name"`
	RedirectURI  string    `json:"redirect_uri" bson:"redirect_uri"`
	CreatedAt    time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" bson:"updated_at"`
}

func CreateClient(id, secret, name, redirect string) Client {
	return Client{
		Id:           id,
		ClientSecret: secret,
		Name:         name,
		RedirectURI:  redirect,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
}

type ClientScope struct {
	ClientId string   `json:"client_id" bson:"client_id"`
	Scopes   []string `json:"scope_ids" bson:"scope_ids"`
}

func CreateClientScope(clientId string, scopes []string) ClientScope {
	return ClientScope{
		ClientId: clientId,
		Scopes:   scopes,
	}
}

type ClientRegisterRequest struct {
	Name        string `json:"name"`
	RedirectURI string `json:"redirect_uri"`
}

type ClientScopesRequest struct {
	ClientId     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"` // slice of scope ids
}
