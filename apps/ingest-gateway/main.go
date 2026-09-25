package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// Configuration from environment.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	rawStoreRoot := os.Getenv("RAW_STORE_ROOT")
	if rawStoreRoot == "" {
		rawStoreRoot = "./data"
	}

	// Initialize components.
	store := NewLocalFSStore(rawStoreRoot)
	bus := NewInMemoryBus()
	svc := NewIngestService(store, bus)

	mux := http.NewServeMux()

	// POST /api/v1/events/raw — ingest a raw event.
	mux.HandleFunc("POST /api/v1/events/raw", func(w http.ResponseWriter, r *http.Request) {
		sourceID := r.Header.Get("X-Source-ID")
		if sourceID == "" {
			sourceID = r.URL.Query().Get("source_id")
		}
		if sourceID == "" {
			http.Error(w, `{"error":"X-Source-ID header or source_id query param required"}`, http.StatusBadRequest)
			return
		}

		transport := r.Header.Get("X-Transport")
		if transport == "" {
			transport = r.URL.Query().Get("transport")
		}
		if transport == "" {
			transport = "unknown"
		}

		rawBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"reading body: %s"}`, err), http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		if len(rawBytes) == 0 {
			http.Error(w, `{"error":"request body must not be empty"}`, http.StatusBadRequest)
			return
		}

		envelope, decision, err := svc.IngestWithContext(r.Context(), sourceID, transport, rawBytes)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if decision.Status == StatusQuarantined {
			w.WriteHeader(http.StatusAccepted)
		} else {
			w.WriteHeader(http.StatusCreated)
		}
		json.NewEncoder(w).Encode(envelope)
	})

	// GET /healthz — liveness probe.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("ingest-gateway listening on :%s (raw store: %s)", port, rawStoreRoot)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen error: %v", err)
		}
	}()

	<-stop
	log.Println("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("shutdown error: %v", err)
	}
	log.Println("ingest-gateway stopped")
}
