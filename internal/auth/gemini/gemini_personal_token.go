// Package gemini provides authentication and token management functionality
// for Google's Gemini AI services. It handles OAuth2 token storage, serialization,
// and retrieval for maintaining authenticated sessions with the Gemini API.
package gemini

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/misc"
	log "github.com/sirupsen/logrus"
)

// GeminiPersonalTokenStorage stores OAuth2 token for personal Google account
// without projectId requirement (free-tier access via cloudcode-pa.googleapis.com).
// This is used for personal OAuth authentication similar to gemini-cli behavior.
type GeminiPersonalTokenStorage struct {
	// Token holds the raw OAuth2 token data, including access and refresh tokens.
	Token any `json:"token"`

	// Email is the email address of the authenticated user.
	Email string `json:"email"`

	// Type indicates the authentication provider type, always "gemini-personal" for this storage.
	Type string `json:"type"`
}

// SaveTokenToFile serializes the Gemini personal token storage to a JSON file.
// This method creates the necessary directory structure and writes the token
// data in JSON format to the specified file path for persistent storage.
//
// Parameters:
//   - authFilePath: The full path where the token file should be saved
//
// Returns:
//   - error: An error if the operation fails, nil otherwise
func (ts *GeminiPersonalTokenStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	ts.Type = "gemini-personal"
	if err := os.MkdirAll(filepath.Dir(authFilePath), 0700); err != nil {
		return fmt.Errorf("failed to create directory: %v", err)
	}

	f, err := os.Create(authFilePath)
	if err != nil {
		return fmt.Errorf("failed to create token file: %w", err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			log.Errorf("failed to close file: %v", errClose)
		}
	}()

	if err = json.NewEncoder(f).Encode(ts); err != nil {
		return fmt.Errorf("failed to write token to file: %w", err)
	}
	return nil
}

// PersonalCredentialFileName returns the filename used to persist Gemini personal OAuth credentials.
// Unlike the standard Gemini CLI credentials, this does not include a projectId
// since personal OAuth does not require Google Cloud project association.
func PersonalCredentialFileName(email string) string {
	return fmt.Sprintf("gemini-personal-%s.json", strings.TrimSpace(email))
}
