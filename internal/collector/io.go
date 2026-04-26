package collector

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hardik/kubesplaining/internal/models"
)

// WriteSnapshot serializes snapshot to path as indented JSON, creating parent directories as needed.
func WriteSnapshot(path string, snapshot models.Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create snapshot directory: %w", err)
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create snapshot file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(snapshot); err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}

	return nil
}

// ReadSnapshot deserializes a snapshot previously written by WriteSnapshot.
func ReadSnapshot(path string) (models.Snapshot, error) {
	file, err := os.Open(path)
	if err != nil {
		return models.Snapshot{}, fmt.Errorf("open snapshot: %w", err)
	}
	defer file.Close()

	var snapshot models.Snapshot
	if err := json.NewDecoder(file).Decode(&snapshot); err != nil {
		return models.Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}

	return snapshot, nil
}
