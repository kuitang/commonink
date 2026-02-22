package apps

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/db"
	"github.com/kuitang/agent-notes/internal/logutil"
	sprites "github.com/superfly/sprites-go"
)

const (
	defaultBashTimeoutSeconds = 120
	maxBashTimeoutSeconds     = 600
	defaultLogLines           = 200
	maxLogLines               = 1000
	maxFileListEntries        = 1000
	maxLoggedValueChars       = 240
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
	appLogf("app_create start user=%q candidates=%d", s.userID, len(candidateNames))
	if err := s.requireClient(); err != nil {
		appLogf("app_create rejected user=%q err=%v", s.userID, err)
		return nil, err
	}
	if len(candidateNames) == 0 {
		appLogf("app_create rejected user=%q reason=%q", s.userID, "at least one candidate name is required")
		return nil, errors.New("at least one candidate name is required")
	}

	attempts := make([]AppCreateAttempt, 0, len(candidateNames))
	for _, raw := range candidateNames {
		name := strings.TrimSpace(raw)
		if name == "" {
			appLogf("app_create candidate rejected user=%q candidate=%q reason=%q", s.userID, raw, "empty name")
			attempts = append(attempts, AppCreateAttempt{
				Name:       raw,
				Accepted:   false,
				Message:    "name is empty",
				Suggestion: "Try another name.",
			})
			continue
		}

		if _, err := s.getMetadata(ctx, name); err == nil {
			appLogf("app_create candidate rejected user=%q app=%q reason=%q", s.userID, name, "app already exists")
			attempts = append(attempts, AppCreateAttempt{
				Name:       name,
				Accepted:   false,
				Message:    "app already exists for this user",
				Suggestion: "Try another name.",
			})
			continue
		} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
			appLogf("app_create metadata lookup failed user=%q app=%q err=%v", s.userID, name, err)
			return nil, err
		}

		appLogf("app_create sprite.create start user=%q app=%q timeout=%s", s.userID, name, defaultSpriteAPITimeout)
		createCtx, createCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
		sprite, err := s.client.CreateSprite(createCtx, name, nil)
		createCancel()
		if err != nil {
			appLogf("app_create sprite.create failed user=%q app=%q err=%v", s.userID, name, err)
			attempts = append(attempts, toCreateAttempt(name, err))
			continue
		}
		appLogf("app_create sprite.create success user=%q app=%q", s.userID, name)

		appLogf("app_create sprite.url_settings start user=%q app=%q auth=%q", s.userID, name, "public")
		settingsCtx, settingsCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
		if err := sprite.UpdateURLSettings(settingsCtx, &sprites.URLSettings{Auth: "public"}); err != nil {
			settingsCancel()
			appLogf("app_create sprite.url_settings failed user=%q app=%q err=%v", s.userID, name, err)
			s.deleteSpriteBestEffort(ctx, name, "app_create sprite.url_settings cleanup")
			attempts = append(attempts, toCreateAttempt(name, err))
			continue
		}
		settingsCancel()
		appLogf("app_create sprite.url_settings success user=%q app=%q", s.userID, name)

		publicURL := ""
		status := "created"
		getCtx, getCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
		if fresh, err := s.client.GetSprite(getCtx, name); err == nil {
			getCancel()
			publicURL = strings.TrimSpace(fresh.URL)
			if fresh.Status != "" {
				status = fresh.Status
			}
			appLogf("app_create sprite.get success user=%q app=%q status=%q url=%q", s.userID, name, status, publicURL)
		} else {
			getCancel()
			appLogf("app_create sprite.get failed user=%q app=%q err=%v", s.userID, name, err)
		}

		now := time.Now().UTC().Unix()
		appLogf("app_create metadata insert start user=%q app=%q sprite=%q status=%q url=%q", s.userID, name, name, status, publicURL)
		if _, err := s.userDB.DB().ExecContext(ctx, `
			INSERT INTO apps(name, sprite_name, public_url, status, created_at, updated_at)
			VALUES(?, ?, ?, ?, ?, ?)
		`, name, name, publicURL, status, now, now); err != nil {
			appLogf("app_create metadata insert failed user=%q app=%q err=%v", s.userID, name, err)
			s.deleteSpriteBestEffort(ctx, name, "app_create metadata insert cleanup")
			return nil, fmt.Errorf("failed to persist app metadata: %w", err)
		}
		appLogf("app_create success user=%q app=%q sprite=%q status=%q url=%q attempts=%d", s.userID, name, name, status, publicURL, len(attempts)+1)

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

	appLogf("app_create exhausted user=%q candidates=%d", s.userID, len(candidateNames))
	return &AppCreateResult{
		Created:  false,
		Attempts: attempts,
		Message:  "no candidate name was accepted by Fly Sprites. Try another name.",
	}, nil
}

func (s *Service) WriteFile(ctx context.Context, appName, relPath, content string) (*AppWriteResult, error) {
	appLogf("app_write start user=%q app=%q path=%q content_bytes=%d", s.userID, appName, relPath, len(content))
	if err := s.requireClient(); err != nil {
		appLogf("app_write rejected user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appLogf("app_write metadata missing user=%q app=%q", s.userID, appName)
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		appLogf("app_write metadata lookup failed user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	appLogf("app_write metadata loaded user=%q app=%q sprite=%q status=%q", s.userID, meta.Name, meta.SpriteName, meta.Status)

	cleanPath, fullPath, err := sanitizePath(relPath)
	if err != nil {
		appLogf("app_write sanitize_path failed user=%q app=%q path=%q err=%v", s.userID, appName, relPath, err)
		return nil, err
	}
	appLogf("app_write sanitize_path success user=%q app=%q path=%q full_path=%q", s.userID, appName, cleanPath, fullPath)

	b64 := base64.StdEncoding.EncodeToString([]byte(content))
	py := "import base64, pathlib, sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(base64.b64decode(sys.argv[2]))"
	runCtx, runCancel := context.WithTimeout(ctx, defaultSpriteIOTimeout)
	defer runCancel()
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "python3", "-c", py, fullPath, b64)
	appLogf("app_write sprite.command start user=%q app=%q sprite=%q interpreter=%q path=%q", s.userID, appName, meta.SpriteName, "python3", cleanPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		appLogf("app_write sprite.command failed user=%q app=%q sprite=%q output=%q err=%v", s.userID, appName, meta.SpriteName, logutil.TruncateForLog(string(out), maxLoggedValueChars), err)
		return nil, fmt.Errorf("failed to write file on sprite: %v: %s", err, strings.TrimSpace(string(out)))
	}
	appLogf("app_write sprite.command success user=%q app=%q sprite=%q path=%q bytes=%d", s.userID, appName, meta.SpriteName, cleanPath, len(content))

	if err := s.touch(ctx, meta.Name, meta.Status, meta.PublicURL); err != nil {
		appLogf("app_write metadata touch failed user=%q app=%q err=%v", s.userID, meta.Name, err)
		return nil, err
	}
	appLogf("app_write success user=%q app=%q path=%q bytes=%d", s.userID, meta.Name, cleanPath, len(content))
	return &AppWriteResult{
		App:          meta.Name,
		Path:         cleanPath,
		BytesWritten: len(content),
	}, nil
}

func (s *Service) ReadFile(ctx context.Context, appName, relPath string) (*AppReadResult, error) {
	appLogf("app_read start user=%q app=%q path=%q", s.userID, appName, relPath)
	if err := s.requireClient(); err != nil {
		appLogf("app_read rejected user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appLogf("app_read metadata missing user=%q app=%q", s.userID, appName)
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		appLogf("app_read metadata lookup failed user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	appLogf("app_read metadata loaded user=%q app=%q sprite=%q", s.userID, meta.Name, meta.SpriteName)

	cleanPath, fullPath, err := sanitizePath(relPath)
	if err != nil {
		appLogf("app_read sanitize_path failed user=%q app=%q path=%q err=%v", s.userID, appName, relPath, err)
		return nil, err
	}
	appLogf("app_read sanitize_path success user=%q app=%q path=%q full_path=%q", s.userID, appName, cleanPath, fullPath)

	py := "import base64, pathlib, sys; p=pathlib.Path(sys.argv[1]); sys.stdout.write(base64.b64encode(p.read_bytes()).decode())"
	runCtx, runCancel := context.WithTimeout(ctx, defaultSpriteIOTimeout)
	defer runCancel()
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "python3", "-c", py, fullPath)
	appLogf("app_read sprite.command start user=%q app=%q sprite=%q interpreter=%q path=%q", s.userID, appName, meta.SpriteName, "python3", cleanPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		appLogf("app_read sprite.command failed user=%q app=%q sprite=%q output=%q err=%v", s.userID, appName, meta.SpriteName, logutil.TruncateForLog(string(output), maxLoggedValueChars), err)
		return nil, fmt.Errorf("failed to read file on sprite: %v: %s", err, strings.TrimSpace(string(output)))
	}
	appLogf("app_read sprite.command success user=%q app=%q sprite=%q output_bytes=%d", s.userID, appName, meta.SpriteName, len(output))

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(output)))
	if err != nil {
		appLogf("app_read decode failed user=%q app=%q path=%q err=%v", s.userID, appName, cleanPath, err)
		return nil, fmt.Errorf("failed to decode file content: %w", err)
	}
	appLogf("app_read success user=%q app=%q path=%q content_bytes=%d", s.userID, appName, cleanPath, len(decoded))

	return &AppReadResult{
		App:     meta.Name,
		Path:    cleanPath,
		Content: string(decoded),
	}, nil
}

func (s *Service) RunBash(ctx context.Context, appName, command string, timeoutSeconds int) (*AppBashResult, error) {
	appLogf("app_bash start user=%q app=%q timeout_seconds=%d command=%q", s.userID, appName, timeoutSeconds, logutil.TruncateForLog(command, maxLoggedValueChars))
	if err := s.requireClient(); err != nil {
		appLogf("app_bash rejected user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appLogf("app_bash metadata missing user=%q app=%q", s.userID, appName)
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		appLogf("app_bash metadata lookup failed user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	appLogf("app_bash metadata loaded user=%q app=%q sprite=%q status=%q public_url=%q", s.userID, meta.Name, meta.SpriteName, meta.Status, meta.PublicURL)

	if timeoutSeconds <= 0 {
		timeoutSeconds = defaultBashTimeoutSeconds
		appLogf("app_bash timeout defaulted user=%q app=%q timeout_seconds=%d", s.userID, appName, timeoutSeconds)
	}
	if timeoutSeconds > maxBashTimeoutSeconds {
		appLogf("app_bash timeout rejected user=%q app=%q timeout_seconds=%d max=%d", s.userID, appName, timeoutSeconds, maxBashTimeoutSeconds)
		return nil, fmt.Errorf("timeout_seconds must be <= %d", maxBashTimeoutSeconds)
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()

	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "bash", "-lc", command)
	cmd.Dir = "/home/sprite"
	appLogf("app_bash sprite.command start user=%q app=%q sprite=%q dir=%q command=%q timeout_seconds=%d", s.userID, meta.Name, meta.SpriteName, cmd.Dir, logutil.TruncateForLog(command, maxLoggedValueChars), timeoutSeconds)
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
			appLogf("app_bash sprite.command exit_error user=%q app=%q sprite=%q exit_code=%d runtime_ms=%d stdout_bytes=%d stderr_bytes=%d", s.userID, meta.Name, meta.SpriteName, exitCode, runtimeMS, len(stdout), len(stderr))
		} else if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			exitCode = -1
			stderr = fmt.Sprintf("command timed out after %d seconds", timeoutSeconds)
			appLogf("app_bash sprite.command timeout user=%q app=%q sprite=%q timeout_seconds=%d runtime_ms=%d", s.userID, meta.Name, meta.SpriteName, timeoutSeconds, runtimeMS)
		} else {
			appLogf("app_bash sprite.command failed user=%q app=%q sprite=%q err=%v", s.userID, meta.Name, meta.SpriteName, runErr)
			return nil, fmt.Errorf("failed to run command on sprite: %w", runErr)
		}
	} else {
		appLogf("app_bash sprite.command success user=%q app=%q sprite=%q exit_code=%d runtime_ms=%d stdout_bytes=%d stderr_bytes=%d", s.userID, meta.Name, meta.SpriteName, exitCode, runtimeMS, len(stdout), len(stderr))
	}

	portStatus, warning := s.detectPortAndService(ctx, meta.SpriteName)
	nextStatus := meta.Status
	if portStatus == "listening" {
		nextStatus = "running"
	} else if portStatus == "not_listening" {
		nextStatus = "stopped"
	}

	if err := s.touch(ctx, meta.Name, nextStatus, meta.PublicURL); err != nil {
		appLogf("app_bash metadata touch failed user=%q app=%q next_status=%q err=%v", s.userID, meta.Name, nextStatus, err)
		return nil, err
	}
	if warning != "" {
		appLogf("app_bash port probe warning user=%q app=%q sprite=%q warning=%q", s.userID, meta.Name, meta.SpriteName, warning)
	}
	appLogf("app_bash success user=%q app=%q sprite=%q exit_code=%d runtime_ms=%d port_status=%q next_status=%q", s.userID, meta.Name, meta.SpriteName, exitCode, runtimeMS, portStatus, nextStatus)

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
	appLogf("app_list start user=%q", s.userID)
	rows, err := s.userDB.DB().QueryContext(ctx, `
		SELECT name, sprite_name, COALESCE(public_url, ''), status, created_at, updated_at
		FROM apps
		ORDER BY updated_at DESC
	`)
	if err != nil {
		appLogf("app_list query failed user=%q err=%v", s.userID, err)
		return nil, fmt.Errorf("failed to list apps: %w", err)
	}
	defer rows.Close()

	var apps []AppMetadata
	for rows.Next() {
		var rec AppMetadata
		var createdAt int64
		var updatedAt int64
		if err := rows.Scan(&rec.Name, &rec.SpriteName, &rec.PublicURL, &rec.Status, &createdAt, &updatedAt); err != nil {
			appLogf("app_list scan failed user=%q err=%v", s.userID, err)
			return nil, fmt.Errorf("failed to scan app row: %w", err)
		}
		rec.CreatedAt = time.Unix(createdAt, 0).UTC()
		rec.UpdatedAt = time.Unix(updatedAt, 0).UTC()
		apps = append(apps, rec)
	}
	if err := rows.Err(); err != nil {
		appLogf("app_list iteration failed user=%q err=%v", s.userID, err)
		return nil, fmt.Errorf("failed to iterate app rows: %w", err)
	}

	appLogf("app_list success user=%q total=%d", s.userID, len(apps))
	return apps, nil
}

// Get returns metadata for a single app by name.
func (s *Service) Get(ctx context.Context, appName string) (*AppMetadata, error) {
	appLogf("app_get start user=%q app=%q", s.userID, appName)
	if s.userDB == nil {
		appLogf("app_get rejected user=%q app=%q err=%q", s.userID, appName, "user database not available")
		return nil, errors.New("user database not available")
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appLogf("app_get missing user=%q app=%q", s.userID, appName)
			return nil, fmt.Errorf("app not found")
		}
		appLogf("app_get metadata lookup failed user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	appLogf("app_get success user=%q app=%q sprite=%q status=%q", s.userID, meta.Name, meta.SpriteName, meta.Status)
	return meta, nil
}

// ListFiles lists files and directories under /home/sprite for an app.
func (s *Service) ListFiles(ctx context.Context, appName string) (*AppListFilesResult, error) {
	appLogf("app_files_list start user=%q app=%q", s.userID, appName)
	if err := s.requireClient(); err != nil {
		appLogf("app_files_list rejected user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appLogf("app_files_list metadata missing user=%q app=%q", s.userID, appName)
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		appLogf("app_files_list metadata lookup failed user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}

	listCmd := "find /home/sprite -mindepth 1 " +
		"\\( -path '*/.*' -o -path '*/node_modules' -o -path '*/node_modules/*' " +
		"-o -path '*/venv' -o -path '*/venv/*' -o -path '*/__pycache__' -o -path '*/__pycache__/*' \\) " +
		"-prune -o -printf '%P\\0%y\\0%s\\0%T@\\0'"

	runCtx, runCancel := context.WithTimeout(ctx, defaultSpriteIOTimeout)
	defer runCancel()
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "bash", "-lc", listCmd)
	appLogf("app_files_list sprite.command start user=%q app=%q sprite=%q command=%q", s.userID, appName, meta.SpriteName, logutil.TruncateForLog(listCmd, maxLoggedValueChars))
	output, err := cmd.CombinedOutput()
	if err != nil {
		appLogf("app_files_list sprite.command failed user=%q app=%q sprite=%q output=%q err=%v", s.userID, appName, meta.SpriteName, logutil.TruncateForLog(string(output), maxLoggedValueChars), err)
		return nil, fmt.Errorf("failed to list files on sprite: %v: %s", err, strings.TrimSpace(string(output)))
	}
	appLogf("app_files_list sprite.command success user=%q app=%q sprite=%q output_bytes=%d", s.userID, appName, meta.SpriteName, len(output))

	tokens := bytes.Split(output, []byte{0})
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
			if parsed, parseErr := strconv.ParseInt(string(tokens[i+2]), 10, 64); parseErr == nil && parsed > 0 {
				sizeBytes = parsed
			}
		}

		modifiedAt := time.Unix(0, 0).UTC()
		if modifiedRaw := string(tokens[i+3]); modifiedRaw != "" {
			if parsed, parseErr := strconv.ParseFloat(modifiedRaw, 64); parseErr == nil && parsed >= 0 {
				modifiedAt = time.Unix(int64(parsed), 0).UTC()
			}
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
	appLogf("app_files_list success user=%q app=%q files=%d", s.userID, appName, len(files))

	return &AppListFilesResult{
		App:   meta.Name,
		Files: files,
	}, nil
}

// TailLogs returns recent journal output from a sprite.
func (s *Service) TailLogs(ctx context.Context, appName string, lines int) (*AppLogsResult, error) {
	appLogf("app_logs start user=%q app=%q lines=%d", s.userID, appName, lines)
	if err := s.requireClient(); err != nil {
		appLogf("app_logs rejected user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appLogf("app_logs metadata missing user=%q app=%q", s.userID, appName)
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		appLogf("app_logs metadata lookup failed user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}

	if lines <= 0 {
		lines = defaultLogLines
		appLogf("app_logs lines defaulted user=%q app=%q lines=%d", s.userID, appName, lines)
	}
	if lines > maxLogLines {
		lines = maxLogLines
		appLogf("app_logs lines clamped user=%q app=%q lines=%d", s.userID, appName, lines)
	}

	runCtx, cancel := context.WithTimeout(ctx, time.Duration(defaultBashTimeoutSeconds)*time.Second)
	defer cancel()

	cmdText := fmt.Sprintf("if command -v journalctl >/dev/null 2>&1; then journalctl -n %d --no-pager; elif [ -f '/.sprite/logs/services/web.log' ]; then tail -n %d '/.sprite/logs/services/web.log'; elif ls /.sprite/logs/services/*.log >/dev/null 2>&1; then tail -n %d /.sprite/logs/services/*.log; else echo 'no logs available on this sprite runtime'; fi", lines, lines, lines)
	cmd := s.client.Sprite(meta.SpriteName).CommandContext(runCtx, "bash", "-lc", cmdText)
	appLogf("app_logs sprite.command start user=%q app=%q sprite=%q command=%q", s.userID, appName, meta.SpriteName, logutil.TruncateForLog(cmdText, maxLoggedValueChars))
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
			appLogf("app_logs sprite.command exit_error user=%q app=%q sprite=%q exit_code=%d runtime_ms=%d stdout_bytes=%d stderr_bytes=%d", s.userID, appName, meta.SpriteName, exitCode, runtimeMS, len(stdout), len(stderr))
		} else if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			exitCode = -1
			stderr = fmt.Sprintf("log command timed out after %d seconds", defaultBashTimeoutSeconds)
			appLogf("app_logs sprite.command timeout user=%q app=%q sprite=%q runtime_ms=%d", s.userID, appName, meta.SpriteName, runtimeMS)
		} else {
			appLogf("app_logs sprite.command failed user=%q app=%q sprite=%q err=%v", s.userID, appName, meta.SpriteName, runErr)
			return nil, fmt.Errorf("failed to tail logs on sprite: %w", runErr)
		}
	} else {
		appLogf("app_logs sprite.command success user=%q app=%q sprite=%q exit_code=%d runtime_ms=%d stdout_bytes=%d stderr_bytes=%d", s.userID, appName, meta.SpriteName, exitCode, runtimeMS, len(stdout), len(stderr))
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
	appLogf("app_delete start user=%q app=%q", s.userID, appName)
	if err := s.requireClient(); err != nil {
		appLogf("app_delete rejected user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}
	meta, err := s.getMetadata(ctx, appName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			appLogf("app_delete metadata missing user=%q app=%q", s.userID, appName)
			return nil, fmt.Errorf("app not found, use app_create first")
		}
		appLogf("app_delete metadata lookup failed user=%q app=%q err=%v", s.userID, appName, err)
		return nil, err
	}

	appLogf("app_delete sprite.delete start user=%q app=%q sprite=%q", s.userID, meta.Name, meta.SpriteName)
	deleteCtx, deleteCancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
	err = s.client.DeleteSprite(deleteCtx, meta.SpriteName)
	deleteCancel()
	if err != nil && !isSpriteNotFound(err) {
		appLogf("app_delete sprite.delete failed user=%q app=%q sprite=%q err=%v", s.userID, meta.Name, meta.SpriteName, err)
		return nil, fmt.Errorf("failed to delete sprite: %w", err)
	}
	appLogf("app_delete sprite.delete complete user=%q app=%q sprite=%q", s.userID, meta.Name, meta.SpriteName)
	if _, err := s.userDB.DB().ExecContext(ctx, `DELETE FROM apps WHERE name = ?`, meta.Name); err != nil {
		appLogf("app_delete metadata delete failed user=%q app=%q err=%v", s.userID, meta.Name, err)
		return nil, fmt.Errorf("failed to delete app metadata: %w", err)
	}
	appLogf("app_delete success user=%q app=%q", s.userID, meta.Name)

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
	appLogf("app_touch start user=%q app=%q status=%q public_url=%q", s.userID, appName, status, publicURL)
	_, err := s.userDB.DB().ExecContext(ctx, `
		UPDATE apps
		SET status = ?, public_url = ?, updated_at = ?
		WHERE name = ?
	`, status, publicURL, now, appName)
	if err != nil {
		appLogf("app_touch failed user=%q app=%q status=%q err=%v", s.userID, appName, status, err)
		return fmt.Errorf("failed to update app metadata: %w", err)
	}
	appLogf("app_touch success user=%q app=%q status=%q", s.userID, appName, status)
	return nil
}

func (s *Service) detectPortAndService(ctx context.Context, spriteName string) (string, string) {
	sprite := s.client.Sprite(spriteName)
	portProbeCmd := "if command -v ss >/dev/null 2>&1; then if ss -tln 2>/dev/null | grep -q ':8080'; then echo listening; else echo not_listening; fi; else echo unknown; fi"
	portCtx, portCancel := context.WithTimeout(ctx, defaultSpriteProbeTimeout)
	defer portCancel()
	portCmd := sprite.CommandContext(portCtx, "bash", "-lc", portProbeCmd)
	appLogf("app_bash probe.port start user=%q sprite=%q command=%q", s.userID, spriteName, logutil.TruncateForLog(portProbeCmd, maxLoggedValueChars))
	out, err := portCmd.Output()
	if err != nil {
		appLogf("app_bash probe.port failed user=%q sprite=%q err=%v", s.userID, spriteName, err)
		return "unknown", "Port probe failed after app_bash."
	}

	status := strings.TrimSpace(string(out))
	if status == "" {
		status = "unknown"
	}
	appLogf("app_bash probe.port success user=%q sprite=%q status=%q raw=%q", s.userID, spriteName, status, logutil.TruncateForLog(string(out), maxLoggedValueChars))
	if status != "listening" {
		if status == "unknown" {
			return status, "Warning: ss is unavailable on this sprite runtime; port 8080 status could not be determined."
		}
		return status, ""
	}

	serviceProbeCmd := "if command -v sprite-env >/dev/null 2>&1; then sprite-env services list 2>/dev/null; else echo __no_sprite_env__; fi"
	serviceCtx, serviceCancel := context.WithTimeout(ctx, defaultSpriteProbeTimeout)
	defer serviceCancel()
	serviceCmd := sprite.CommandContext(serviceCtx, "bash", "-lc", serviceProbeCmd)
	appLogf("app_bash probe.service start user=%q sprite=%q command=%q", s.userID, spriteName, logutil.TruncateForLog(serviceProbeCmd, maxLoggedValueChars))
	serviceOut, err := serviceCmd.Output()
	if err != nil {
		appLogf("app_bash probe.service failed user=%q sprite=%q err=%v", s.userID, spriteName, err)
		return status, ""
	}
	text := strings.TrimSpace(string(serviceOut))
	lower := strings.ToLower(text)
	appLogf("app_bash probe.service success user=%q sprite=%q output=%q", s.userID, spriteName, logutil.TruncateForLog(text, maxLoggedValueChars))
	if text == "" || strings.Contains(lower, "no services") || strings.Contains(text, "__no_sprite_env__") {
		return status, "Warning: process listening on 8080 but no persistent service registered. Use sprite-env services create to ensure app survives Sprite sleep."
	}
	return status, ""
}

func (s *Service) deleteSpriteBestEffort(ctx context.Context, spriteName, reason string) {
	deleteCtx, cancel := context.WithTimeout(ctx, defaultSpriteAPITimeout)
	defer cancel()
	if err := s.client.DeleteSprite(deleteCtx, spriteName); err != nil && !isSpriteNotFound(err) {
		appLogf("%s user=%q sprite=%q cleanup_delete_failed=true err=%v", reason, s.userID, spriteName, err)
		return
	}
	appLogf("%s user=%q sprite=%q cleanup_delete_complete=true", reason, s.userID, spriteName)
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

func appLogf(format string, args ...any) {
	log.Printf("[APPS] "+format, args...)
}
