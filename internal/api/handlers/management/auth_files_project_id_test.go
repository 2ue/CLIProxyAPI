package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestListAuthFiles_IncludesProjectIDFromManager(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	fileName := "antigravity-user@example.com-project-a.json"
	filePath := filepath.Join(authDir, fileName)
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"antigravity","email":"user@example.com","project_id":"project-a"}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "antigravity",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path": filePath,
		},
		Metadata: map[string]any{
			"type":       "antigravity",
			"email":      "user@example.com",
			"project_id": "project-a",
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = &memoryAuthStore{}

	entry := firstAuthFileEntry(t, h)
	if got := entry["project_id"]; got != "project-a" {
		t.Fatalf("expected project_id %q, got %#v", "project-a", got)
	}
}

func TestListAuthFilesFromDisk_IncludesProjectID(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	filePath := filepath.Join(authDir, "antigravity-user@example.com-project-a.json")
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"antigravity","email":"user@example.com","project_id":"project-a"}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)

	entry := firstAuthFileEntry(t, h)
	if got := entry["project_id"]; got != "project-a" {
		t.Fatalf("expected project_id %q, got %#v", "project-a", got)
	}
}

func TestListAuthFiles_IncludesWebsocketsFromManager(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	fileName := "codex-user@example.com-pro.json"
	filePath := filepath.Join(authDir, fileName)
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"codex","email":"user@example.com"}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	manager := coreauth.NewManager(nil, nil, nil)
	record := &coreauth.Auth{
		ID:       fileName,
		FileName: fileName,
		Provider: "codex",
		Status:   coreauth.StatusActive,
		Attributes: map[string]string{
			"path":       filePath,
			"websockets": "true",
		},
		Metadata: map[string]any{
			"type": "codex",
		},
	}
	if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
		t.Fatalf("failed to register auth record: %v", errRegister)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = &memoryAuthStore{}

	entry := firstAuthFileEntry(t, h)
	if got := entry["websockets"]; got != true {
		t.Fatalf("expected websockets true, got %#v", got)
	}
}

func TestListAuthFilesFromDisk_IncludesWebsockets(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	filePath := filepath.Join(authDir, "codex-user@example.com-pro.json")
	if errWrite := os.WriteFile(filePath, []byte(`{"type":"codex","email":"user@example.com","websockets":false}`), 0o600); errWrite != nil {
		t.Fatalf("failed to write auth file: %v", errWrite)
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)

	entry := firstAuthFileEntry(t, h)
	if got := entry["websockets"]; got != false {
		t.Fatalf("expected websockets false, got %#v", got)
	}
}

func TestListAuthFiles_IncludesExplicitCloakCacheUserIDFromManager(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	manager := coreauth.NewManager(nil, nil, nil)
	for _, test := range []struct {
		name  string
		value bool
	}{
		{name: "claude-true.json", value: true},
		{name: "claude-false.json", value: false},
	} {
		filePath := filepath.Join(authDir, test.name)
		if errWrite := os.WriteFile(filePath, []byte(`{"type":"claude"}`), 0o600); errWrite != nil {
			t.Fatalf("failed to write auth file: %v", errWrite)
		}
		record := &coreauth.Auth{
			ID:       test.name,
			FileName: test.name,
			Provider: "claude",
			Status:   coreauth.StatusActive,
			Attributes: map[string]string{
				"path": filePath,
			},
			Metadata: map[string]any{
				"cloak_cache_user_id": test.value,
			},
		}
		if _, errRegister := manager.Register(context.Background(), record); errRegister != nil {
			t.Fatalf("failed to register auth record: %v", errRegister)
		}
	}

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)
	h.tokenStore = &memoryAuthStore{}
	for _, test := range []struct {
		name  string
		value bool
	}{
		{name: "claude-true.json", value: true},
		{name: "claude-false.json", value: false},
	} {
		entry := firstAuthFileEntryNamed(t, h, test.name)
		if got := entry["cloak_cache_user_id"]; got != test.value {
			t.Fatalf("cloak_cache_user_id = %#v, want %v", got, test.value)
		}
	}
}

func TestListAuthFilesFromDisk_IncludesExplicitCloakCacheUserIDAndOmitsMissing(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	authDir := t.TempDir()
	tests := []struct {
		name string
		json string
		want any
	}{
		{name: "true.json", json: `{"type":"claude","cloak_cache_user_id":true}`, want: true},
		{name: "false.json", json: `{"type":"claude","cloak_cache_user_id":false}`, want: false},
		{name: "missing.json", json: `{"type":"claude"}`, want: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if errWrite := os.WriteFile(filepath.Join(authDir, test.name), []byte(test.json), 0o600); errWrite != nil {
				t.Fatalf("failed to write auth file: %v", errWrite)
			}
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, nil)
			entry := firstAuthFileEntryNamed(t, h, test.name)
			got, exists := entry["cloak_cache_user_id"]
			if test.want == nil {
				if exists {
					t.Fatalf("expected missing cloak_cache_user_id to be omitted, got %#v", got)
				}
				return
			}
			if !exists || got != test.want {
				t.Fatalf("cloak_cache_user_id = %#v, want %#v", got, test.want)
			}
		})
	}
}

func firstAuthFileEntry(t *testing.T, h *Handler) map[string]any {
	return firstAuthFileEntryNamed(t, h, "")
}

func firstAuthFileEntryNamed(t *testing.T, h *Handler, name string) map[string]any {
	t.Helper()

	rec := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(rec)
	path := "/v0/management/auth-files"
	if name != "" {
		path += "?name=" + name
	}
	ginCtx.Request = httptest.NewRequest(http.MethodGet, path, nil)

	h.ListAuthFiles(ginCtx)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected list status %d, got %d with body %s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var payload map[string]any
	if errUnmarshal := json.Unmarshal(rec.Body.Bytes(), &payload); errUnmarshal != nil {
		t.Fatalf("failed to decode list payload: %v", errUnmarshal)
	}
	filesRaw, ok := payload["files"].([]any)
	if !ok {
		t.Fatalf("expected files array, payload: %#v", payload)
	}
	if len(filesRaw) != 1 {
		t.Fatalf("expected 1 auth entry, got %d", len(filesRaw))
	}
	fileEntry, ok := filesRaw[0].(map[string]any)
	if !ok {
		t.Fatalf("expected file entry object, got %#v", filesRaw[0])
	}
	return fileEntry
}
