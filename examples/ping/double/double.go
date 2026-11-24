// Package double is a tiny in-memory implementation of examples/ping/openapi.yaml. It
// exists to prove the contract-test harness; real services keep their own double/ package.
package double

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

const (
	pingID    = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"
	createdAt = "2026-11-24T13:05:11.120Z"
)

type ping struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

type stored struct {
	status int
	body   []byte
}

// Double serves the ping contract with deterministic IDs and time, seeded with the spec's example.
type Double struct {
	mu    sync.Mutex
	pings map[string]ping
	keys  map[string]stored
}

// New returns a Double seeded so the spec's examples resolve.
func New() *Double {
	return &Double{
		pings: map[string]ping{pingID: {ID: pingID, Message: "hello", CreatedAt: createdAt}},
		keys:  map[string]stored{},
	}
}

func problem(w http.ResponseWriter, status int, code, title string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "urn:hostry:problem:" + code, "title": title, "status": status, "code": code,
	})
}

func writeJSON(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ServeHTTP implements http.Handler.
func (d *Double) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case r.URL.Path == "/v1/pings" && r.Method == http.MethodPost:
		d.create(w, r)
	case r.URL.Path == "/v1/pings" && r.Method == http.MethodGet:
		items := make([]ping, 0, len(d.pings))
		if p, ok := d.pings[pingID]; ok {
			items = append(items, p)
		}
		b, _ := json.Marshal(map[string]any{"items": items})
		writeJSON(w, http.StatusOK, b)
	case strings.HasPrefix(r.URL.Path, "/v1/pings/") && r.Method == http.MethodGet:
		p, ok := d.pings[strings.TrimPrefix(r.URL.Path, "/v1/pings/")]
		if !ok {
			problem(w, http.StatusNotFound, "not_found", "Not found")
			return
		}
		b, _ := json.Marshal(p)
		writeJSON(w, http.StatusOK, b)
	default:
		problem(w, http.StatusNotFound, "not_found", "Not found")
	}
}

func (d *Double) create(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Idempotency-Key")
	if key == "" || len(key) > 128 {
		problem(w, http.StatusUnprocessableEntity, "idempotency.key_invalid", "Validation failed")
		return
	}
	if s, ok := d.keys[key]; ok {
		writeJSON(w, s.status, s.body)
		return
	}
	var in struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Message == "" {
		problem(w, http.StatusUnprocessableEntity, "validation", "Validation failed")
		return
	}
	// Deterministic: the double always creates the spec's example ping.
	p := ping{ID: pingID, Message: in.Message, CreatedAt: createdAt}
	d.pings[p.ID] = p
	b, _ := json.Marshal(p)
	d.keys[key] = stored{http.StatusCreated, b}
	writeJSON(w, http.StatusCreated, b)
}
