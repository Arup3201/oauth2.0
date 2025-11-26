package db

import (
	"context"
	"log"
	"os"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	ENV_MONGODB_URI      = "MONGODB_URI"
	ENV_MONGODB_DATABASE = "MONGODB_DATABASE"
)

func GetMongoClient() *mongo.Client {
	uri := os.Getenv(ENV_MONGODB_URI)
	docs := "www.mongodb.com/docs/drivers/go/current/"
	if uri == "" {
		log.Fatalf("Set your '%s' environment variable. "+
			"See: "+docs+
			"usage-examples/#environment-variable", ENV_MONGODB_URI)
	}
	client, err := mongo.Connect(options.Client().
		ApplyURI(uri))
	if err != nil {
		panic(err)
	}
	return client
}

func DisconnectMongoClient(client *mongo.Client) {
	if err := client.Disconnect(context.TODO()); err != nil {
		panic(err)
	}
}

func GetMongoCollection(client *mongo.Client, collection string) *mongo.Collection {
	db := os.Getenv(ENV_MONGODB_DATABASE)
	return client.Database(db).Collection(collection)
}
