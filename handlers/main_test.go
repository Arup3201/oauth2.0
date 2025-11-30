package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/arup3201/oauth2.0/db"
	"github.com/arup3201/oauth2.0/models"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mongodb"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var handler *http.ServeMux

func TestMain(m *testing.M) {
	os.Setenv(db.ENV_MONGODB_DATABASE, "testing")

	// migrations
	client, err := db.GetMongoClient()
	defer db.DisconnectMongoClient(client)
	if err != nil {
		log.Fatalf("mongodb client connection error: %s", err)
	}
	dbName, err := db.GetDBName()
	if err != nil {
		log.Fatalf("mongodb database name error: %s", err)
	}
	driver, err := mongodb.WithInstance(client, &mongodb.Config{
		DatabaseName: dbName,
	})
	if err != nil {
		log.Fatalf("mongodb driver instance create error: %s", err)
	}
	mig, err := migrate.NewWithDatabaseInstance(
		"file://../migrations",
		dbName, driver)
	if err != nil {
		log.Fatalf("mongodb migration error: %s", err)
	}
	if err := mig.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatalf("migration failed: %v", err)
	}

	// HTTP handler
	handler = http.NewServeMux()

	handler.HandleFunc("POST /register", Register)
	handler.HandleFunc("POST /login", Login)

	handler.HandleFunc("POST /clients", ClientRegister)
	handler.HandleFunc("POST /clients/scopes", AddClientScopes)

	// Run test
	code := m.Run()

	os.Exit(code)
}

func getRequestBody(t testing.TB, data any) io.Reader {
	t.Helper()

	out, err := json.Marshal(data)
	if err != nil {
		t.Fail()
		t.Logf("failed to create request body: %s", err)
		return nil
	}

	return bytes.NewBuffer(out)
}

func cleanupMongoDB(t testing.TB) {
	t.Helper()

	client, err := db.GetMongoClient()
	if err != nil {
		t.Fail()
		t.Logf("failed to cleanup users collection: %s", err)
		return
	}

	collections := []string{COLLECTION_USERS, COLLECTION_CLIENTS, COLLECTION_CLIENT_SCOPES}
	for _, collStr := range collections {
		coll, err := db.GetMongoCollection(client, collStr)
		if err != nil {
			t.Fail()
			t.Logf("failed to cleanup '%s' collection: %s", collStr, err)
			return
		}
		_, err = coll.DeleteMany(context.TODO(), bson.M{})
		if err != nil {
			t.Fail()
			t.Logf("failed to cleanup '%s' collection: %s", collStr, err)
			return
		}
	}
}

func diagnoseMongoDB(t testing.TB) {
	t.Helper()

	client, err := db.GetMongoClient()
	if err != nil {
		t.Fail()
		t.Logf("failed to cleanup users collection: %s", err)
		return
	}
	coll, err := db.GetMongoCollection(client, COLLECTION_USERS)
	if err != nil {
		t.Fail()
		t.Logf("failed to cleanup users collection: %s", err)
		return
	}
	cursor, err := coll.Find(context.TODO(), bson.M{})
	if err != nil {
		t.Logf("MongoDB diagnose error: %s", err)
		return
	}

	var results []models.User
	cursor.All(context.TODO(), &results)
	fmt.Printf("MongoDB collections(users): %v\n", results)
}

func getUserPassword(t testing.TB, email string) (string, error) {
	t.Helper()

	client, err := db.GetMongoClient()
	if err != nil {
		return "", fmt.Errorf("failed to cleanup users collection: %s", err)
	}
	coll, err := db.GetMongoCollection(client, COLLECTION_USERS)
	if err != nil {
		return "", fmt.Errorf("failed to cleanup users collection: %s", err)
	}
	cursor, err := coll.Find(context.TODO(), bson.M{"email": email})
	if err != nil {
		return "", err
	}

	var results []models.User
	cursor.All(context.TODO(), &results)
	if len(results) < 1 {
		return "", fmt.Errorf("no match found with given email")
	}
	return results[0].Password, nil
}

func getClientScopes(t testing.TB, clientId string) ([]string, error) {
	t.Helper()

	result := []string{}
	client, err := db.GetMongoClient()
	if err != nil {
		return result, fmt.Errorf("failed to cleanup users collection: %s", err)
	}
	coll, err := db.GetMongoCollection(client, COLLECTION_CLIENT_SCOPES)
	if err != nil {
		return result, fmt.Errorf("failed to cleanup users collection: %s", err)
	}

	cursor, err := coll.Find(context.TODO(), bson.M{"client_id": clientId})
	if err != nil {
		return result, err
	}

	var cScopes []models.ClientScope
	cursor.All(context.TODO(), &cScopes)
	if len(cScopes) < 1 {
		return result, fmt.Errorf("no match found with given clientID")
	}

	result = append(result, cScopes[0].Scopes...)
	return result, nil
}
