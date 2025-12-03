// Package cmd provides command-line interface functionality for the CLI Proxy API server.
// It includes authentication flows for various AI service providers, service startup,
// and other command-line operations.
package cmd

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v6/internal/auth/gemini"
	"github.com/router-for-me/CLIProxyAPI/v6/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// DoPersonalLogin handles Google Gemini personal account authentication
// without requiring a Google Cloud project ID (free-tier access).
// This is similar to the gemini-cli behavior where users can authenticate
// with their personal Google account without needing to set up billing
// or associate a Google Cloud project.
//
// Parameters:
//   - cfg: The application configuration
//   - options: Login options including browser behavior and prompts
func DoPersonalLogin(cfg *config.Config, options *LoginOptions) {
	if options == nil {
		options = &LoginOptions{}
	}

	ctx := context.Background()

	loginOpts := &sdkAuth.LoginOptions{
		NoBrowser: options.NoBrowser,
		ProjectID: "", // No project required for personal OAuth
		Metadata:  map[string]string{},
		Prompt:    options.Prompt,
	}

	authenticator := sdkAuth.NewGeminiAuthenticator()
	record, errLogin := authenticator.Login(ctx, cfg, loginOpts)
	if errLogin != nil {
		log.Fatalf("Gemini personal authentication failed: %v", errLogin)
		return
	}

	// Extract token data from existing storage
	existingStorage, ok := record.Storage.(*gemini.GeminiTokenStorage)
	if !ok || existingStorage == nil {
		log.Fatal("Gemini personal authentication failed: unsupported token storage")
		return
	}

	// Create personal storage (without projectId)
	personalStorage := &gemini.GeminiPersonalTokenStorage{
		Token: existingStorage.Token,
		Email: existingStorage.Email,
		Type:  "gemini-personal",
	}

	geminiAuth := gemini.NewGeminiAuth()
	httpClient, errClient := geminiAuth.GetAuthenticatedClient(ctx, existingStorage, cfg, options.NoBrowser)
	if errClient != nil {
		log.Fatalf("Gemini personal authentication failed: %v", errClient)
		return
	}

	log.Info("Authentication successful.")

	// Perform setup WITHOUT projectId
	projectID, errSetup := performGeminiPersonalSetup(ctx, httpClient, personalStorage.Email)
	if errSetup != nil {
		log.Fatalf("Failed to complete personal user setup: %v", errSetup)
		return
	}

	// Update record for personal auth
	updatePersonalAuthRecord(record, personalStorage, projectID)

	store := sdkAuth.GetTokenStore()
	if setter, okSetter := store.(interface{ SetBaseDir(string) }); okSetter && cfg != nil {
		setter.SetBaseDir(cfg.AuthDir)
	}

	savedPath, errSave := store.Save(ctx, record)
	if errSave != nil {
		log.Fatalf("Failed to save token to file: %v", errSave)
		return
	}

	if savedPath != "" {
		fmt.Printf("Authentication saved to %s\n", savedPath)
	}

	fmt.Println("Gemini personal authentication successful!")
}

// performGeminiPersonalSetup calls the Gemini CLI setup endpoints WITHOUT cloudaicompanionProject.
// This enables free-tier access through personal Google accounts.
// It returns the managed project ID if one is assigned to the user.
func performGeminiPersonalSetup(ctx context.Context, httpClient *http.Client, email string) (string, error) {
	metadata := map[string]string{
		"ideType":    "IDE_UNSPECIFIED",
		"platform":   "PLATFORM_UNSPECIFIED",
		"pluginType": "GEMINI",
	}

	// loadCodeAssist WITHOUT cloudaicompanionProject (for free-tier)
	loadReqBody := map[string]any{
		"metadata": metadata,
		// NO cloudaicompanionProject for personal accounts
	}

	var loadResp map[string]any
	if errLoad := callGeminiCLI(ctx, httpClient, "loadCodeAssist", loadReqBody, &loadResp); errLoad != nil {
		return "", fmt.Errorf("load code assist: %w", errLoad)
	}

	// Extract managed project ID if present
	var managedProjectID string
	if pid, ok := loadResp["cloudaicompanionProject"].(string); ok {
		managedProjectID = pid
	}

	// Get default tier (usually "free-tier" for personal accounts)
	tierID := "legacy-tier"
	if tiers, okTiers := loadResp["allowedTiers"].([]any); okTiers {
		for _, rawTier := range tiers {
			tier, okTier := rawTier.(map[string]any)
			if !okTier {
				continue
			}
			if isDefault, okDefault := tier["isDefault"].(bool); okDefault && isDefault {
				if id, okID := tier["id"].(string); okID && strings.TrimSpace(id) != "" {
					tierID = strings.TrimSpace(id)
					break
				}
			}
		}
	}

	// Check if onboarding needed
	currentTier := ""
	if ct, ok := loadResp["currentTier"].(string); ok {
		currentTier = ct
	}

	if currentTier == "" {
		// onboardUser WITHOUT cloudaicompanionProject
		onboardReqBody := map[string]any{
			"tierId":   tierID,
			"metadata": metadata,
			// NO cloudaicompanionProject for personal accounts
		}

		for {
			var onboardResp map[string]any
			if errOnboard := callGeminiCLI(ctx, httpClient, "onboardUser", onboardReqBody, &onboardResp); errOnboard != nil {
				return "", fmt.Errorf("onboard user: %w", errOnboard)
			}

			if done, okDone := onboardResp["done"].(bool); okDone && done {
				// Extract project ID from response
				if resp, okResp := onboardResp["response"].(map[string]any); okResp {
					if cp, okCP := resp["cloudaicompanionProject"].(map[string]any); okCP {
						if id, okID := cp["id"].(string); okID {
							managedProjectID = id
						}
					}
				}
				log.Infof("Personal onboarding complete for %s", email)
				return managedProjectID, nil
			}

			log.Println("Onboarding in progress, waiting 5 seconds...")
			time.Sleep(5 * time.Second)
		}
	}

	log.Infof("User %s already onboarded", email)
	return managedProjectID, nil
}

// updatePersonalAuthRecord updates the auth record for personal OAuth storage.
func updatePersonalAuthRecord(record *cliproxyauth.Auth, storage *gemini.GeminiPersonalTokenStorage, projectID string) {
	if record == nil || storage == nil {
		return
	}

	finalName := gemini.PersonalCredentialFileName(storage.Email)

	if record.Metadata == nil {
		record.Metadata = make(map[string]any)
	}
	record.Metadata["email"] = storage.Email
	if projectID != "" {
		record.Metadata["project_id"] = projectID
	}

	record.ID = finalName
	record.FileName = finalName
	record.Provider = "gemini-personal"
	record.Storage = storage
}
