package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/arup3201/oauth2.0/db"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var handler *http.ServeMux

func TestMain(m *testing.M) {
	os.Setenv("MONGODB_DATABASE", "testing")
	handler = http.NewServeMux()
	handler.HandleFunc("GET /register", Register)

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
