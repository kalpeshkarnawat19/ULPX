package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RawStore is the interface for immutable raw event byte storage.
// Implementations must guarantee write-once semantics: storing bytes
// for an event ID that already exists must return an error.
type RawStore interface {
	// Store persists rawBytes immutably and returns the raw_ref path.
	Store(eventID, sourceID string, rawBytes []byte) (rawRef string, err error)

	// Load reads raw bytes back by rawRef for verification.
	Load(rawRef string) ([]byte, error)
}

// LocalFSStore implements RawStore using the local filesystem.
// Raw bytes are stored at: <root>/raw/<YYYY>/<MM>/<DD>/<source_id>/<event_id>
// Files are written atomically (write-to-temp then rename) to prevent
// partial writes. Overwriting an existing file is forbidden.
type LocalFSStore struct {
	Root string // Base directory for raw storage.
}

// NewLocalFSStore creates a new LocalFSStore rooted at the given directory.
func NewLocalFSStore(root string) *LocalFSStore {
	return &LocalFSStore{Root: root}
}

// Store writes rawBytes to disk. The storage path follows the convention:
//
//	raw/<YYYY>/<MM>/<DD>/<source_id>/<event_id>
//
// Returns an error if a file at that path already exists (immutability).
func (s *LocalFSStore) Store(eventID, sourceID string, rawBytes []byte) (string, error) {
	now := time.Now().UTC()
	rawRef := fmt.Sprintf("raw/%04d/%02d/%02d/%s/%s",
		now.Year(), now.Month(), now.Day(), sourceID, eventID)

	absPath := filepath.Join(s.Root, rawRef)

	// Immutability check: refuse to overwrite.
	if _, err := os.Stat(absPath); err == nil {
		return "", fmt.Errorf("raw event already exists at %s", rawRef)
	}

	dir := filepath.Dir(absPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating directory %s: %w", dir, err)
	}

	// Atomic write: temp file then rename to prevent partial writes.
	tmp := absPath + ".tmp"
	if err := os.WriteFile(tmp, rawBytes, 0o444); err != nil {
		return "", fmt.Errorf("writing temp file: %w", err)
	}
	if err := os.Rename(tmp, absPath); err != nil {
		os.Remove(tmp) // best-effort cleanup
		return "", fmt.Errorf("renaming temp to final: %w", err)
	}

	return rawRef, nil
}

// Load reads raw bytes back from disk by rawRef.
func (s *LocalFSStore) Load(rawRef string) ([]byte, error) {
	absPath := filepath.Join(s.Root, rawRef)
	data, err := os.ReadFile(absPath)
	if err != nil {
		return nil, fmt.Errorf("reading raw event at %s: %w", rawRef, err)
	}
	return data, nil
}
