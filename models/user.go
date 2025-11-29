package models

import "time"

type User struct {
	Id        string    `json:"id" bson:"_id"`
	Email     string    `json:"email"  bson:"email"`
	Password  string    `json:"password" bson:"password"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`
}

func CreateUser(id, email, password string) User {
	return User{
		Id:        id,
		Email:     email,
		Password:  password,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

type UserRegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}
