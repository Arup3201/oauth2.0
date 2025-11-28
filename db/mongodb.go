package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	ENV_MONGODB_URI      = "MONGODB_URI"
	ENV_MONGODB_DATABASE = "MONGODB_DATABASE"
)

func GetMongoClient() (*mongo.Client, error) {
	uri := os.Getenv(ENV_MONGODB_URI)
	docs := "www.mongodb.com/docs/drivers/go/current/"
	if uri == "" {
		log.Printf("[ERROR]Set your '%s' environment variable. "+
			"See: "+docs+
			"usage-examples/#environment-variable", ENV_MONGODB_URI)
		return nil, fmt.Errorf("missing environment variable '%s'", ENV_MONGODB_URI)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	client, err := mongo.Connect(ctx, options.Client().
		ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	return client, nil
}

func DisconnectMongoClient(client *mongo.Client) error {
	if err := client.Disconnect(context.TODO()); err != nil {
		return err
	}

	return nil
}

func GetDBName() (string, error) {
	db := os.Getenv(ENV_MONGODB_DATABASE)
	if db == "" {
		return "", fmt.Errorf("missing environment variable '%s'", ENV_MONGODB_DATABASE)
	}
	return db, nil
}

func GetMongoCollection(client *mongo.Client, collection string) (*mongo.Collection, error) {
	db, err := GetDBName()
	if err != nil {
		return nil, err
	}
	return client.Database(db).Collection(collection), nil
}
