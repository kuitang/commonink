package apps

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	sprites "github.com/superfly/sprites-go"
)

const (
	defaultBashTimeoutSeconds = 120
	maxBashTimeoutSeconds     = 600
	maxBashOutputBytes        = 1 << 20
	maxAppWriteFiles          = 64
	maxAppWritePathBytes      = 1024
	maxAppWriteFileBytes      = 1 << 20
	maxAppWriteTotalBytes     = 8 << 20
	defaultLogLines           = 200
	maxLogLines               = 1000
	maxFileListEntries        = 1000
	defaultSpriteAPITimeout   = 45 * time.Second
	defaultSpriteIOTimeout    = 120 * time.Second
	defaultSpriteProbeTimeout = 10 * time.Second
)

// Service owns app metadata persistence and Sprite operations.
type Service struct {
	userDB      *db.UserDB
	userID      string
	spriteToken string
	client      *sprites.Client
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

		createCtx, createCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
		sprite, err := s.client.CreateSprite(createCtx, name, nil)
		createCancel()
		if err != nil {
			attempts = append(attempts, toCreateAttempt(name, err))
			continue
		}
		spriteName := strings.TrimSpace(sprite.Name())
		if spriteName == "" {
			attemptErr := errors.New("sprite API returned empty sprite name")
			if cleanupErr := s.deleteSpriteBestEffort(ctx, name, "app_create sprite.create cleanup"); cleanupErr != nil {
				attemptErr = fmt.Errorf("%w (plus cleanup failure: %v)", attemptErr, cleanupErr)
			}
			attempts = append(attempts, toCreateAttempt(name, attemptErr))
			continue
		}

		settingsCtx, settingsCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
		if err := sprite.UpdateURLSettings(settingsCtx, &sprites.URLSettings{Auth: "public"}); err != nil {
			settingsCancel()
			attemptErr := err
			if cleanupErr := s.deleteSpriteBestEffort(ctx, spriteName, "app_create sprite.url_settings cleanup"); cleanupErr != nil {
				attemptErr = fmt.Errorf("%w (plus cleanup failure: %v)", err, cleanupErr)
			}
			attempts = append(attempts, toCreateAttempt(name, attemptErr))
			continue
		}
		settingsCancel()

		publicURL := ""
		status := "created"
		getCtx, getCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
		fresh, err := s.client.GetSprite(getCtx, spriteName)
		getCancel()
		if err != nil {
			verifyErr := fmt.Errorf("failed to verify created sprite metadata: %w", err)
			cleanupErr := s.deleteSpriteBestEffort(ctx, spriteName, "app_create sprite.get cleanup")
			if cleanupErr != nil {
				verifyErr = fmt.Errorf("%w (plus cleanup failure: %v)", verifyErr, cleanupErr)
			}
			attempts = append(attempts, toCreateAttempt(name, verifyErr))
			continue
		}
		if freshName := strings.TrimSpace(fresh.Name()); freshName != "" {
			spriteName = freshName
		}
		publicURL = strings.TrimSpace(fresh.URL)
		if fresh.Status != "" {
			status = fresh.Status
		}

		now := time.Now().UTC().Unix()
		if _, err := s.userDB.DB().ExecContext(ctx, `
			INSERT INTO apps(name, sprite_name, public_url, status, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?)
		`, name, spriteName, publicURL, status, now, now); err != nil {
			if cleanupErr := s.deleteSpriteBestEffort(ctx, spriteName, "app_create metadata insert cleanup"); cleanupErr != nil {
				return nil, fmt.Errorf("failed to persist app metadata: %w (plus cleanup failure: %v)", err, cleanupErr)
			}
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

func (s *Service) WriteFiles(ctx context.Context, appName string, files []AppWriteFileInput) (*AppWriteResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, errors.New("files is required")
	}
	if len(files) > maxAppWriteFiles {
		return nil, fmt.Errorf("files must contain <= %d items", maxAppWriteFiles)
	}

	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}
	if err := s.verifySpriteBinding(ctx, meta); err != nil {
		return nil, err
	}

	type validatedWrite struct {
		path    string
		content string
	}
	validated := make([]validatedWrite, 0, len(files))
	seen := make(map[string]struct{}, len(files))
	totalBytes := 0
	for i, file := range files {
		cleanPath, _, sanitizeErr := sanitizePath(file.Path)
		if sanitizeErr != nil {
			return nil, fmt.Errorf("files[%d].path invalid: %w", i, sanitizeErr)
		}
		if len(cleanPath) > maxAppWritePathBytes {
			return nil, fmt.Errorf("files[%d].path must be <= %d bytes", i, maxAppWritePathBytes)
		}
		contentBytes := len(file.Content)
		if contentBytes > maxAppWriteFileBytes {
			return nil, fmt.Errorf("files[%d].content must be <= %d bytes", i, maxAppWriteFileBytes)
		}
		totalBytes += contentBytes
		if totalBytes > maxAppWriteTotalBytes {
			return nil, fmt.Errorf("total file content must be <= %d bytes", maxAppWriteTotalBytes)
		}
		if _, exists := seen[cleanPath]; exists {
			return nil, fmt.Errorf("duplicate file path: %q", cleanPath)
		}
		seen[cleanPath] = struct{}{}
		validated = append(validated, validatedWrite{
			path:    cleanPath,
			content: file.Content,
		})
	}

	fs := s.client.Sprite(meta.SpriteName).FilesystemAt("/home/sprite")
	runCtx, runCancel := context.WithTimeout(ctx, defaultSpriteIOTimeout)
	defer runCancel()

	filesWritten := make([]AppWriteFileResult, 0, len(validated))
	for _, write := range validated {
		if writeErr := fs.WriteFileContext(runCtx, write.path, []byte(write.content), 0o644); writeErr != nil {
			return nil, fmt.Errorf("failed to write file %q on sprite after %d/%d files: %w", write.path, len(filesWritten), len(validated), writeErr)
		}
		filesWritten = append(filesWritten, AppWriteFileResult{
			Path:         write.path,
			BytesWritten: len(write.content),
		})
	}

	if err := s.touch(ctx, meta.Name, meta.Status, meta.PublicURL); err != nil {
		return nil, err
	}
	return &AppWriteResult{
		App:               meta.Name,
		FilesWritten:      filesWritten,
		TotalBytesWritten: totalBytes,
		TotalFilesWritten: len(filesWritten),
	}, nil
}

func (s *Service) ReadFiles(ctx context.Context, appName string, paths []string) (*AppReadResult, error) {
	if err := s.requireClient(); err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, errors.New("files is required")
	}
	if len(paths) > maxAppWriteFiles {
		return nil, fmt.Errorf("files must contain <= %d items", maxAppWriteFiles)
	}

	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		return nil, err
	}
	if err := s.verifySpriteBinding(ctx, meta); err != nil {
		return nil, err
	}

	cleanPaths := make([]string, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for i, rawPath := range paths {
		cleanPath, _, sanitizeErr := sanitizePath(rawPath)
		if sanitizeErr != nil {
			return nil, fmt.Errorf("files[%d].path invalid: %w", i, sanitizeErr)
		}
		if len(cleanPath) > maxAppWritePathBytes {
			return nil, fmt.Errorf("files[%d].path must be <= %d bytes", i, maxAppWritePathBytes)
		}
		if _, exists := seen[cleanPath]; exists {
			return nil, fmt.Errorf("duplicate file path: %q", cleanPath)
		}
		seen[cleanPath] = struct{}{}
		cleanPaths = append(cleanPaths, cleanPath)
	}

	fs := s.client.Sprite(meta.SpriteName).FilesystemAt("/home/sprite")
	_, runCancel := context.WithTimeout(ctx, defaultSpriteIOTimeout)
	defer runCancel()
	files := make([]AppWriteFileInput, 0, len(cleanPaths))
	totalBytes := 0
	for _, cleanPath := range cleanPaths {
		decoded, readErr := fs.ReadFile(cleanPath)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read file %q on sprite after %d/%d files: %w", cleanPath, len(files), len(cleanPaths), readErr)
		}
		contentBytes := len(decoded)
		if contentBytes > maxAppWriteFileBytes {
			return nil, fmt.Errorf("file %q exceeds max supported size %d bytes", cleanPath, maxAppWriteFileBytes)
		}
		totalBytes += contentBytes
		if totalBytes > maxAppWriteTotalBytes {
			return nil, fmt.Errorf("total file content must be <= %d bytes", maxAppWriteTotalBytes)
		}
		files = append(files, AppWriteFileInput{
			Path:    cleanPath,
			Content: string(decoded),
		})
	}

	return &AppReadResult{
		App:   meta.Name,
		Files: files,
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
	if err := s.verifySpriteBinding(ctx, meta); err != nil {
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
	stdoutBuf := newCappedOutputBuffer(maxBashOutputBytes)
	stderrBuf := newCappedOutputBuffer(maxBashOutputBytes)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

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
	} else {
	}

	portStatus, warning, probeErr := s.detectPortAndService(ctx, meta.SpriteName)
	if probeErr != nil {
		return nil, fmt.Errorf("failed to probe sprite runtime after command: %w", probeErr)
	}
	nextStatus := meta.Status
	if portStatus == "listening" {
		nextStatus = "running"
	} else if portStatus == "not_listening" {
		nextStatus = "stopped"
	}

	if err := s.touch(ctx, meta.Name, nextStatus, meta.PublicURL); err != nil {
		return nil, err
	}
	if warning != "" {
	}

	return &AppBashResult{
		Stdout:          stdout,
		Stderr:          stderr,
		StdoutTruncated: stdoutBuf.Truncated(),
		StderrTruncated: stderrBuf.Truncated(),
		ExitCode:        exitCode,
		RuntimeMS:       runtimeMS,
		PortStatus:      portStatus,
		PublicURL:       meta.PublicURL,
		Warning:         warning,
		TimeoutSeconds:  timeoutSeconds,
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
	if err := s.verifySpriteBinding(ctx, meta); err != nil {
		return nil, err
	}

	listCmd := "find /home/sprite -mindepth 1 " +
		"\\( -path '*/.*' -o -path '*/node_modules' -o -path '*/node_modules/*' " +
		"-o -path '*/venv' -o -path '*/venv/*' -o -path '*/__pycache__' -o -path '*/__pycache__/*' \\) " +
		"-prune -o -printf '%P\\0%y\\0%s\\0%T@\\0'"

	runCtx, runCancel := context.WithTimeout(ctx, defaultSpriteIOTimeout)
	defer runCancel()
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "bash", "-lc", listCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to list files on sprite: %v: %s", err, strings.TrimSpace(string(output)))
	}

	tokens := bytes.Split(output, []byte{0})
	if n := len(tokens); n > 0 && len(tokens[n-1]) == 0 {
		tokens = tokens[:n-1]
	}
	if len(tokens)%4 != 0 {
		return nil, fmt.Errorf("failed to parse files listing output")
	}
	files := make([]AppFileEntry, 0, len(tokens)/4)
	for i := 0; i+3 < len(tokens); i += 4 {
		relPath := string(tokens[i])
		if relPath == "" {
			continue
		}

		kind := "file"
		if string(tokens[i+1]) == "d" {
			kind = "dir"
		}

		sizeBytes := int64(0)
		if kind == "file" {
			parsed, parseErr := strconv.ParseInt(string(tokens[i+2]), 10, 64)
			if parseErr != nil || parsed < 0 {
				return nil, fmt.Errorf("failed to parse file size for %q", relPath)
			}
			sizeBytes = parsed
		}

		modifiedAt := time.Unix(0, 0).UTC()
		if modifiedRaw := string(tokens[i+3]); modifiedRaw != "" {
			parsed, parseErr := strconv.ParseFloat(modifiedRaw, 64)
			if parseErr != nil || parsed < 0 {
				return nil, fmt.Errorf("failed to parse modified time for %q", relPath)
			}
			modifiedAt = time.Unix(int64(parsed), 0).UTC()
		}

		files = append(files, AppFileEntry{
			Path:       relPath,
			Kind:       kind,
			SizeBytes:  sizeBytes,
			ModifiedAt: modifiedAt,
		})
	}

	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})
	if len(files) > maxFileListEntries {
		files = files[:maxFileListEntries]
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
	if err := s.verifySpriteBinding(ctx, meta); err != nil {
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

	cmdText := fmt.Sprintf("if command -v journalctl >/dev/null 2>&1; then journalctl -n %d --no-pager; elif [ -f '/.sprite/logs/services/web.log' ]; then tail -n %d '/.sprite/logs/services/web.log'; elif ls /.sprite/logs/services/*.log >/dev/null 2>&1; then tail -n %d /.sprite/logs/services/*.log; else echo 'no logs available on this sprite runtime'; fi", lines, lines, lines)
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
	} else {
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
	if err := s.verifySpriteBinding(ctx, meta); err != nil {
		return nil, err
	}

	deleteCtx, deleteCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
	err = s.client.DeleteSprite(deleteCtx, meta.SpriteName)
	deleteCancel()
	if err != nil {
		return nil, fmt.Errorf("failed to delete sprite %q: %w", meta.SpriteName, err)
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

func (s *Service) verifySpriteBinding(ctx context.Context, meta *AppMetadata) error {
	if meta == nil {
		return errors.New("app metadata is missing")
	}
	spriteName := strings.TrimSpace(meta.SpriteName)
	if spriteName == "" {
		return errors.New("app metadata missing sprite name")
	}

	verifyCtx, cancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
	defer cancel()
	sprite, err := s.client.GetSprite(verifyCtx, spriteName)
	if err != nil {
		return fmt.Errorf("failed to verify sprite %q: %w", spriteName, err)
	}

	expectedHost := normalizedURLHost(meta.PublicURL)
	if expectedHost == "" {
		return nil
	}
	actualHost := normalizedURLHost(sprite.URL)
	if actualHost == "" {
		return fmt.Errorf("sprite %q verification failed: API returned empty URL", spriteName)
	}
	if !strings.EqualFold(expectedHost, actualHost) {
		return fmt.Errorf("sprite binding mismatch for app %q: metadata host=%q but sprite host=%q (sprite_name=%q)", meta.Name, expectedHost, actualHost, spriteName)
	}
	return nil
}

func normalizedURLHost(raw string) string {
	text := strings.TrimSpace(raw)
	if text == "" {
		return ""
	}
	parsed, err := url.Parse(text)
	if err == nil && parsed.Hostname() != "" {
		return strings.ToLower(parsed.Hostname())
	}
	if !strings.Contains(text, "://") {
		parsedWithScheme, parseErr := url.Parse("https://" + text)
		if parseErr == nil && parsedWithScheme.Hostname() != "" {
			return strings.ToLower(parsedWithScheme.Hostname())
		}
	}
	return ""
}

func (s *Service) detectPortAndService(ctx context.Context, spriteName string) (string, string, error) {
	sprite := s.client.Sprite(spriteName)
	portProbeCmd := "if command -v ss >/dev/null 2>&1; then if ss -tln 2>/dev/null | grep -q ':8080'; then echo listening; else echo not_listening; fi; else echo unknown; fi"
	portCtx, portCancel := context.WithTimeout(ctx, defaultSpriteProbeTimeout)
	defer portCancel()
	portCmd := sprite.CommandContext(portCtx, "bash", "-lc", portProbeCmd)
	out, err := portCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("port probe command failed: %w", err)
	}

	status := strings.TrimSpace(string(out))
	if status == "" {
		status = "unknown"
	}
	if status != "listening" && status != "not_listening" && status != "unknown" {
		return "", "", fmt.Errorf("port probe returned unexpected status %q", status)
	}
	if status != "listening" {
		if status == "unknown" {
			return status, "Warning: ss is unavailable on this sprite runtime; port 8080 status could not be determined.", nil
		}
		return status, "", nil
	}

	serviceProbeCmd := "if command -v sprite-env >/dev/null 2>&1; then sprite-env services list 2>/dev/null; else echo __no_sprite_env__; fi"
	serviceCtx, serviceCancel := context.WithTimeout(ctx, defaultSpriteProbeTimeout)
	defer serviceCancel()
	serviceCmd := sprite.CommandContext(serviceCtx, "bash", "-lc", serviceProbeCmd)
	serviceOut, err := serviceCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("service probe command failed: %w", err)
	}
	text := strings.TrimSpace(string(serviceOut))
	lower := strings.ToLower(text)
	if text == "" || strings.Contains(lower, "no services") || strings.Contains(text, "__no_sprite_env__") {
		return status, "Warning: process listening on 8080 but no persistent service registered. Use sprite-env services create to ensure app survives Sprite sleep.", nil
	}
	return status, "", nil
}

func (s *Service) deleteSpriteBestEffort(ctx context.Context, spriteName, reason string) error {
	deleteCtx, cancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
	defer cancel()
	if err := s.client.DeleteSprite(deleteCtx, spriteName); err != nil && !isSpriteNotFound(err) {
		return fmt.Errorf("cleanup delete failed: %w", err)
	}
	return nil
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

type cappedOutputBuffer struct {
	maxBytes  int
	buf       bytes.Buffer
	truncated bool
}

func newCappedOutputBuffer(maxBytes int) *cappedOutputBuffer {
	return &cappedOutputBuffer{maxBytes: maxBytes}
}

func (b *cappedOutputBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.maxBytes <= 0 {
		b.truncated = true
		return len(p), nil
	}
	remaining := b.maxBytes - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *cappedOutputBuffer) String() string {
	return b.buf.String()
}

func (b *cappedOutputBuffer) Truncated() bool {
	return b.truncated
}
