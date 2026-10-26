package icloud

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ad/go-findmy/internal/findmy"
)

func TestFetcherReloginsThroughAccountAndRetriesWithTheNewToken(t *testing.T) {
	apple := newFakeApple(t, "hunter2")
	an := &fakeAnisette{}
	a, _ := loggedIn(t, apple, an)
	apple.delegates = func() (int, map[string]any) {
		return 200, map[string]any{"dsid": "42", "delegates": map[string]any{"com.apple.mobileme": map[string]any{
			"service-data": map[string]any{"tokens": map[string]any{"searchPartyToken": "spt2"}},
		}}}
	}

	var tokens []string
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		tokens = append(tokens, user+":"+pass)
		if pass != "spt2" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"acsnLocations":{"statusCode":"200","locationPayload":[]}}`)
	}))
	t.Cleanup(gateway.Close)

	kf, err := findmy.NewKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(kf)
	key, err := findmy.ReadKeyFile(data)
	if err != nil {
		t.Fatal(err)
	}

	f := findmy.NewFetcher(an, a, a.Relogin)
	f.URL = gateway.URL
	if _, err := f.LatestStatic(ctx, []findmy.Key{key}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 || tokens[0] != "1234567890:spt" || tokens[1] != "42:spt2" {
		t.Errorf("fetch auth = %v, want the old token then the relogged one", tokens)
	}
}
