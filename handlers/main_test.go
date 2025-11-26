package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/arup3201/oauth2.0/db"
	"github.com/arup3201/oauth2.0/models"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var handler *http.ServeMux

func TestMain(m *testing.M) {
	os.Setenv("MONGODB_DATABASE", "testing")
	handler = http.NewServeMux()
	handler.HandleFunc("POST /register", Register)
	handler.HandleFunc("POST /login", Login)

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

	client := db.GetMongoClient()
	coll := db.GetMongoCollection(client, "users")
	_, err := coll.DeleteMany(context.TODO(), bson.M{})
	if err != nil {
		t.Fail()
		t.Logf("failed to cleanup users collection: %s", err)
		return
	}
}

func diagnoseMongoDB(t testing.TB) {
	t.Helper()

	client := db.GetMongoClient()
	coll := db.GetMongoCollection(client, "users")
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

	client := db.GetMongoClient()
	coll := db.GetMongoCollection(client, "users")
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
