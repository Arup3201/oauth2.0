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

type ClientScope struct {
	ClientId string `json:"client_id" bson:"client_id"`
	ScopeId  string `json:"scope_id" bson:"scope_id"`
}
