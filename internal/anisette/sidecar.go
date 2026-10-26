package anisette

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const clientInfo = "X-Mme-Client-Info"

type Sidecar struct {
	url    string
	client *http.Client
}

func New(url string) *Sidecar {
	// A resync makes up to four Apple requests with a 30 s timeout each, and /headers waits for it.
	return &Sidecar{url: strings.TrimSuffix(url, "/"), client: &http.Client{Timeout: 3 * time.Minute}}
}

func (s *Sidecar) Headers() (map[string]string, error) {
	h, err := s.call(http.MethodGet, "/headers")
	if err != nil {
		return nil, err
	}
	if h["X-Apple-I-MD"] == "" || h["X-Apple-I-MD-M"] == "" {
		return nil, errors.New("anisette: sidecar headers lack X-Apple-I-MD or X-Apple-I-MD-M")
	}
	// appleservices reads the client info by this exact key; os-findmy-e spells it X-MMe-Client-Info.
	for k, v := range h {
		if k != clientInfo && strings.EqualFold(k, clientInfo) {
			delete(h, k)
			h[clientInfo] = v
		}
	}
	return h, nil
}

func (s *Sidecar) Resync() error {
	_, err := s.call(http.MethodPost, "/resync")
	return err
}

func (s *Sidecar) call(method, path string) (map[string]string, error) {
	req, err := http.NewRequest(method, s.url+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anisette: %w", err)
	}
	defer resp.Body.Close()

	var body map[string]string
	decodeErr := json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anisette: %s %s: %s: %s%s", method, path, resp.Status, body["error"], body["result"])
	}
	if decodeErr != nil {
		return nil, fmt.Errorf("anisette: %s %s: %w", method, path, decodeErr)
	}
	return body, nil
}
