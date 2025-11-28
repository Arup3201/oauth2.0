package models

type Scope struct {
	Id                    string `json:"id" bson:"_id"`
	ApiId                 string `json:"api_id" bson:"api_id"`
	Scope                 string `json:"scope" bson:"scope"`
	UserFacingDescription string `json:"user_facing_description" bson:"user_facing_description"`
}
