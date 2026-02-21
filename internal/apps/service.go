package apps

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	sprites "github.com/superfly/sprites-go"
)

const (
	defaultBashTimeoutSeconds = 120
	maxBashTimeoutSeconds     = 600
	defaultLogLines           = 200
	maxLogLines               = 1000
	maxFileListEntries        = 1000
)

// Service owns app metadata persistence and Sprite operations.
type Service struct {
	userDB      *db.UserDB
	userID      string
	spriteToken string
	client      *sprites.Client
}

func looksLikeFlyToken(token string) bool {
	token = strings.TrimSpace(token)
	return strings.HasPrefix(token, "FlyV1 ") ||
		strings.HasPrefix(token, "fm2_") ||
		strings.HasPrefix(token, "fo1_")
}

// ResolveSpriteToken returns a usable Sprites bearer token from either:
// 1) a direct sprite token, or
// 2) a Fly token (SPRITE_FLY_TOKEN / FLY_API_TOKEN / FlyV1 token) exchanged via Sprites API.
func ResolveSpriteToken(ctx context.Context, spriteToken, flyToken, orgSlug, inviteCode string) (string, error) {
	spriteToken = strings.TrimSpace(spriteToken)
	flyToken = strings.TrimSpace(flyToken)
	orgSlug = strings.TrimSpace(orgSlug)
	inviteCode = strings.TrimSpace(inviteCode)

	if orgSlug == "" {
		orgSlug = "personal"
	}

	// Direct sprite token path.
	if spriteToken != "" && !looksLikeFlyToken(spriteToken) {
		return spriteToken, nil
	}

	// Fly token exchange path.
	rawFly := flyToken
	if rawFly == "" && looksLikeFlyToken(spriteToken) {
		rawFly = spriteToken
	}
	rawFly = strings.TrimPrefix(strings.TrimSpace(rawFly), "FlyV1 ")
	if rawFly == "" {
		return "", nil
	}

	resolved, err := sprites.CreateToken(ctx, rawFly, orgSlug, inviteCode)
	if err != nil {
		return "", fmt.Errorf("failed to exchange fly token for sprite token: %w", err)
	}
	return strings.TrimSpace(resolved), nil
}

// NewService creates a new apps service for a user-scoped database.
func NewService(userDB *db.UserDB, userID, spriteToken string) *Service {
	svc := &Service{
		userDB:      userDB,
		userID:      userID,
		spriteToken: strings.TrimSpace(spriteToken),
	}
	if svc.spriteToken != "" {
		svc.client = sprites.New(svc.spriteToken)
	}
	return svc
}

func (s *Service) requireClient() error {
	if s.userDB == nil {
		return errors.New("user database not available")
	}
	if s.client == nil {
		return errors.New("SPRITE_TOKEN is not configured on the server")
	}
	return nil
}

func (s *Service) Create(ctx context.Context, candidateNames []string) (*AppCreateResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	if len(candidateNames) == 0 {
		return nil, errors.New("at least one candidate name is required")
	}

	attempts := make([]AppCreateAttempt, 0, len(candidateNames))
	for _, raw := range candidateNames {
		name := strings.TrimSpace(raw)
		if name == "" {
			attempts = append(attempts, AppCreateAttempt{
				Name:       raw,
				Accepted:   false,
				Message:    "name is empty",
				Suggestion: "Try another name.",
			})
			continue
		}

		if _, err := s.getMetadata(ctx, name); err == nil {
			attempts = append(attempts, AppCreateAttempt{
				Name:       name,
				Accepted:   false,
				Message:    "app already exists for this user",
				Suggestion: "Try another name.",
			})
			continue
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}

		sprite, err := s.client.CreateSprite(ctx, name, nil)
		if err != nil {
			attempts = append(attempts, toCreateAttempt(name, err))
			continue
		}

		if err := sprite.UpdateURLSettings(ctx, &sprites.URLSettings{Auth: "public"}); err != nil {
			_ = s.client.DeleteSprite(ctx, name)
			attempts = append(attempts, toCreateAttempt(name, err))
			continue
		}

		publicURL := ""
		status := "created"
		if fresh, err := s.client.GetSprite(ctx, name); err == nil {
			publicURL = strings.TrimSpace(fresh.URL)
			if fresh.Status != "" {
				status = fresh.Status
			}
		}

		now := time.Now().UTC().Unix()
		if _, err := s.userDB.DB().ExecContext(ctx, `
			INSERT INTO apps(name, sprite_name, public_url, status, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?)
		`, name, name, publicURL, status, now, now); err != nil {
			_ = s.client.DeleteSprite(ctx, name)
			return nil, fmt.Errorf("failed to persist app metadata: %w", err)
		}

		attempts = append(attempts, AppCreateAttempt{Name: name, Accepted: true})
		return &AppCreateResult{
			Created:   true,
			Name:      name,
			PublicURL: publicURL,
			Status:    status,
			Attempts:  attempts,
			Message:   "app created",
		}, nil
	}

	return &AppCreateResult{
		Created:  false,
		Attempts: attempts,
		Message:  "no candidate name was accepted by Fly Sprites. Try another name.",
	}, nil
}

func (s *Service) WriteFile(ctx context.Context, appName, relPath, content string) (*AppWriteResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}

	cleanPath, fullPath, err := sanitizePath(relPath)
	if err != nil {
		return nil, err
	}

	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	py := "import base64, pathlib, sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(base64.b64decode(sys.argv[2]))"
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(ctx, "python3", "-c", py, fullPath, b64)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to write file on sprite: %v: %s", err, strings.TrimSpace(string(out)))
	}

	if err := s.touch(ctx, meta.Name, meta.Status, meta.PublicURL); err != nil {
		return nil, err
	}
	return &AppWriteResult{
		App:          meta.Name,
		Path:         cleanPath,
		BytesWritten: len(content),
	}, nil
}

func (s *Service) ReadFile(ctx context.Context, appName, relPath string) (*AppReadResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}

	cleanPath, fullPath, err := sanitizePath(relPath)
	if err != nil {
		return nil, err
	}

	py := "import base64, pathlib, sys; p=pathlib.Path(sys.argv[1]); sys.stdout.write(base64.b64encode(p.read_bytes()).decode())"
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(ctx, "python3", "-c", py, fullPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to read file on sprite: %v: %s", err, strings.TrimSpace(string(output)))
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(output)))
	if err != nil {
		return nil, fmt.Errorf("failed to decode file content: %w", err)
	}

	return &AppReadResult{
		App:     meta.Name,
		Path:    cleanPath,
		Content: string(decoded),
	}, nil
}

func (s *Service) RunBash(ctx context.Context, appName, command string, timeoutSeconds int) (*AppBashResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}

	if timeoutSeconds <= 0 {
		timeoutSeconds = defaultBashTimeoutSeconds
	}
	if timeoutSeconds > maxBashTimeoutSeconds {
		return nil, fmt.Errorf("timeout_seconds must be <= %d", maxBashTimeoutSeconds)
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "bash", "-lc", command)
	cmd.Dir = "/home/sprite"
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	runtimeMS := time.Since(start).Milliseconds()

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()
	exitCode := cmd.ExitCode()
	if exitCode < 0 {
		exitCode = 0
	}

	var exitErr *sprites.ExitError
	if runErr != nil {
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			exitCode = -1
			stderr = fmt.Sprintf("command timed out after %d seconds", timeoutSeconds)
		} else {
			return nil, fmt.Errorf("failed to run command on sprite: %w", runErr)
		}
	}

	portStatus, warning := s.detectPortAndService(ctx, meta.SpriteName)
	nextStatus := meta.Status
	if portStatus == "listening" {
		nextStatus = "running"
	} else if portStatus == "not_listening" {
		nextStatus = "stopped"
	}

	if err := s.touch(ctx, meta.Name, nextStatus, meta.PublicURL); err != nil {
		return nil, err
	}

	return &AppBashResult{
		Stdout:         stdout,
		Stderr:         stderr,
		ExitCode:       exitCode,
		RuntimeMS:      runtimeMS,
		PortStatus:     portStatus,
		PublicURL:      meta.PublicURL,
		Warning:        warning,
		TimeoutSeconds: timeoutSeconds,
	}, nil
}

func (s *Service) List(ctx context.Context) ([]AppMetadata, error) {
	rows, err := s.userDB.DB().QueryContext(ctx, `
		SELECT name, sprite_name, COALESCE(public_url, ''), status, created_at, updated_at
		FROM apps
		ORDER BY updated_at DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to list apps: %w", err)
	}
	defer rows.Close()

	var apps []AppMetadata
	for rows.Next() {
		var rec AppMetadata
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(&rec.Name, &rec.SpriteName, &rec.PublicURL, &rec.Status, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan app row: %w", err)
		}
		rec.CreatedAt = time.Unix(createdAt, 0).UTC()
		rec.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		apps = append(apps, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate app rows: %w", err)
	}

	return apps, nil
}

// Get returns metadata for a single app by name.
func (s *Service) Get(ctx context.Context, appName string) (*AppMetadata, error) {
	if s.userDB == nil {
		return nil, errors.New("user database not available")
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found")
		}
		return nil, err
	}
	return meta, nil
}

// ListFiles lists files and directories under /home/sprite for an app.
func (s *Service) ListFiles(ctx context.Context, appName string) (*AppListFilesResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}

	script := fmt.Sprintf(`import json, pathlib
root = pathlib.Path("/home/sprite")
skip_names = {"node_modules",".git",".venv","venv","__pycache__"}
entries = []
for p in sorted(root.rglob("*")):
    rel = p.relative_to(root).as_posix()
    if not rel:
        continue
    parts = rel.split("/")
    if any(part.startswith(".") for part in parts):
        continue
    if any(part in skip_names for part in parts):
        continue
    try:
        st = p.stat()
    except Exception:
        continue
    kind = "dir" if p.is_dir() else "file"
    size = int(st.st_size) if p.is_file() else 0
    entries.append({
        "path": rel,
        "kind": kind,
        "size_bytes": size,
        "modified_unix": int(st.st_mtime),
    })
    if len(entries) >= %d:
        break
print(json.dumps(entries))`, maxFileListEntries)

	cmd := s.client.Sprite(meta.SpriteName).CommandContext(ctx, "python3", "-c", script)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list files on sprite: %v: %s", err, strings.TrimSpace(string(output)))
	}

	var raw []struct {
		Path         string `json:"path"`
		Kind         string `json:"kind"`
		SizeBytes    int64  `json:"size_bytes"`
		ModifiedUnix int64  `json:"modified_unix"`
	}
	if err := json.Unmarshal(output, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse file list: %w", err)
	}

	files := make([]AppFileEntry, 0, len(raw))
	for _, item := range raw {
		files = append(files, AppFileEntry{
			Path:       item.Path,
			Kind:       item.Kind,
			SizeBytes:  item.SizeBytes,
			ModifiedAt: time.Unix(item.ModifiedUnix, 0).UTC(),
		})
	}

	return &AppListFilesResult{
		App:   meta.Name,
		Files: files,
	}, nil
}

// TailLogs returns recent journal output from a sprite.
func (s *Service) TailLogs(ctx context.Context, appName string, lines int) (*AppLogsResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}

	if lines <= 0 {
		lines = defaultLogLines
	}
	if lines > maxLogLines {
		lines = maxLogLines
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(defaultBashTimeoutSeconds)*time.Second)
	defer cancel()

	cmdText := fmt.Sprintf("if command -v journalctl >/dev/null 2>&1; then journalctl -n %d --no-pager; else echo 'journalctl unavailable on this sprite runtime'; fi", lines)
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "bash", "-lc", cmdText)
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	start := time.Now()
	runErr := cmd.Run()
	runtimeMS := time.Since(start).Milliseconds()

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()
	exitCode := cmd.ExitCode()
	if exitCode < 0 {
		exitCode = 0
	}

	var exitErr *sprites.ExitError
	if runErr != nil {
		if errors.As(runErr, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			exitCode = -1
			stderr = fmt.Sprintf("log command timed out after %d seconds", defaultBashTimeoutSeconds)
		} else {
			return nil, fmt.Errorf("failed to tail logs on sprite: %w", runErr)
		}
	}

	return &AppLogsResult{
		App:       meta.Name,
		Lines:     lines,
		Output:    stdout,
		Stderr:    stderr,
		ExitCode:  exitCode,
		RuntimeMS: runtimeMS,
	}, nil
}

func (s *Service) Delete(ctx context.Context, appName string) (*AppDeleteResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}

	if err := s.client.DeleteSprite(ctx, meta.SpriteName); err != nil && !isSpriteNotFound(err) {
		return nil, fmt.Errorf("failed to delete sprite: %w", err)
	}
	if _, err := s.userDB.DB().ExecContext(ctx, `DELETE FROM apps WHERE name = ?`, meta.Name); err != nil {
		return nil, fmt.Errorf("failed to delete app metadata: %w", err)
	}

	return &AppDeleteResult{
		App:     meta.Name,
		Deleted: true,
	}, nil
}

func (s *Service) getMetadata(ctx context.Context, appName string) (*AppMetadata, error) {
	var rec AppMetadata
	var createdAt int64
	var updatedAt int64
	err := s.userDB.DB().QueryRowContext(ctx, `
		SELECT name, sprite_name, COALESCE(public_url, ''), status, created_at, updated_at
		FROM apps
		WHERE name = ?
	`, appName).Scan(&rec.Name, &rec.SpriteName, &rec.PublicURL, &rec.Status, &createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	rec.CreatedAt = time.Unix(createdAt, 0).UTC()
	rec.UpdatedAt = time.Unix(updatedAt, 0).UTC()
	return &rec, nil
}

func (s *Service) touch(ctx context.Context, appName, status, publicURL string) error {
	now := time.Now().UTC().Unix()
	_, err := s.userDB.DB().ExecContext(ctx, `
		UPDATE apps
		SET status = ?, public_url = ?, updated_at = ?
		WHERE name = ?
	`, status, publicURL, now, appName)
	if err != nil {
		return fmt.Errorf("failed to update app metadata: %w", err)
	}
	return nil
}

func (s *Service) detectPortAndService(ctx context.Context, spriteName string) (string, string) {
	sprite := s.client.Sprite(spriteName)
	portCmd := sprite.CommandContext(ctx, "bash", "-lc", "if command -v ss >/dev/null 2>&1; then if ss -tln 2>/dev/null | grep -q ':8080'; then echo listening; else echo not_listening; fi; else echo unknown; fi")
	out, err := portCmd.Output()
	if err != nil {
		return "unknown", "Port probe failed after app_bash."
	}

	status := strings.TrimSpace(string(out))
	if status == "" {
		status = "unknown"
	}
	if status != "listening" {
		if status == "unknown" {
			return status, "Warning: ss is unavailable on this sprite runtime; port 8080 status could not be determined."
		}
		return status, ""
	}

	serviceCmd := sprite.CommandContext(ctx, "bash", "-lc", "if command -v sprite-env >/dev/null 2>&1; then sprite-env services list 2>/dev/null; else echo __no_sprite_env__; fi")
	serviceOut, err := serviceCmd.Output()
	if err != nil {
		return status, ""
	}
	text := strings.TrimSpace(string(serviceOut))
	lower := strings.ToLower(text)
	if text == "" || strings.Contains(lower, "no services") || strings.Contains(text, "__no_sprite_env__") {
		return status, "Warning: process listening on 8080 but no persistent service registered. Use sprite-env services create to ensure app survives Sprite sleep."
	}
	return status, ""
}

func sanitizePath(raw string) (string, string, error) {
	candidate := strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if candidate == "" {
		return "", "", errors.New("path is required")
	}
	cleaned := path.Clean(candidate)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return "", "", errors.New("path must be relative to /home/sprite and must not traverse parent directories")
	}
	return cleaned, path.Join("/home/sprite", cleaned), nil
}

func toCreateAttempt(name string, err error) AppCreateAttempt {
	attempt := AppCreateAttempt{
		Name:       name,
		Accepted:   false,
		Message:    err.Error(),
		Suggestion: "Try another name.",
	}
	if apiErr := sprites.IsAPIError(err); apiErr != nil {
		attempt.ErrorCode = apiErr.ErrorCode
		attempt.Message = apiErr.Message
		attempt.RetryAfterSeconds = apiErr.GetRetryAfterSeconds()
		if apiErr.GetRetryAfterSeconds() > 0 {
			attempt.Suggestion = fmt.Sprintf("Retry after %d seconds or try another name.", apiErr.GetRetryAfterSeconds())
		}
	}
	return attempt
}

func isSpriteNotFound(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}
