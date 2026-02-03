// Package oauth provides OAuth 2.1 authorization server handlers.
// This file implements the Authorization and Token endpoints per RFC 6749/OAuth 2.1.
package oauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/kuitang/agent-notes/internal/auth"
	"github.com/kuitang/agent-notes/internal/db/sessions"
	"github.com/kuitang/agent-notes/internal/web"
)

// Errors for OAuth handlers.
var (
	ErrMissingParameter           = errors.New("oauth: missing required parameter")
	ErrInvalidResponseType        = errors.New("oauth: invalid response_type")
	ErrInvalidCodeChallengeMethod = errors.New("oauth: invalid code_challenge_method")
	ErrResourceMismatch           = errors.New("oauth: resource parameter does not match server resource")
	ErrUserNotAuthenticated       = errors.New("oauth: user not authenticated")
	ErrConsentDenied              = errors.New("oauth: consent denied")
)

// Default scopes when none are requested.
const DefaultScopes = "notes:read notes:write"

// Scope descriptions for the consent page.
var scopeDescriptions = map[string]string{
	"notes:read":  "View and read your notes",
	"notes:write": "Create, update, and delete your notes",
}

// Handler provides HTTP handlers for OAuth 2.1 endpoints.
type Handler struct {
	provider       *Provider
	sessionService *auth.SessionService
	consentService *auth.ConsentService
	renderer       *web.Renderer
}

// NewHandler creates a new OAuth handler.
func NewHandler(provider *Provider, sessionService *auth.SessionService, consentService *auth.ConsentService, renderer *web.Renderer) *Handler {
	return &Handler{
		provider:       provider,
		sessionService: sessionService,
		consentService: consentService,
		renderer:       renderer,
	}
}

// RegisterRoutes registers all OAuth routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /oauth/authorize", h.HandleAuthorize)
	mux.HandleFunc("POST /oauth/consent", h.HandleConsentSubmit)
	mux.HandleFunc("POST /oauth/token", h.HandleToken)
}

// =============================================================================
// Authorization Endpoint
// =============================================================================

// AuthorizeRequest contains the parsed authorization request parameters.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

// HandleAuthorize handles GET /oauth/authorize.
// This implements the OAuth 2.1 authorization endpoint with PKCE.
func (h *Handler) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Parse request parameters
	req, err := h.parseAuthorizeRequest(r)
	if err != nil {
		h.renderAuthError(w, r, "", "", err)
		return
	}

	// Validate client
	client, err := h.provider.GetClient(r.Context(), req.ClientID)
	if err != nil {
		h.renderAuthError(w, r, req.RedirectURI, req.State, ErrInvalidClient)
		return
	}

	// Validate redirect_uri
	if err := h.provider.ValidateClientRedirectURI(client, req.RedirectURI); err != nil {
		// Do NOT redirect to untrusted redirect_uri
		h.renderAuthError(w, r, "", "", err)
		return
	}

	// Validate response_type
	if req.ResponseType != "code" {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "unsupported_response_type", "Only code response type is supported")
		return
	}

	// Validate PKCE is present
	if req.CodeChallenge == "" {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "invalid_request", "code_challenge is required")
		return
	}

	// Validate code_challenge_method is S256
	if req.CodeChallengeMethod != "S256" {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "invalid_request", "code_challenge_method must be S256")
		return
	}

	// Validate resource matches server's resource
	if req.Resource != "" && req.Resource != h.provider.Resource() {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "invalid_target", "resource parameter does not match server resource")
		return
	}

	// Check if user is authenticated
	sessionID, err := auth.GetFromRequest(r)
	if err != nil {
		// User not logged in - redirect to login with return URL
		h.redirectToLogin(w, r, req)
		return
	}

	userID, err := h.sessionService.Validate(r.Context(), sessionID)
	if err != nil {
		// Session invalid - redirect to login
		h.redirectToLogin(w, r, req)
		return
	}

	// Parse requested scopes
	requestedScopes := auth.StringToScopes(req.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = auth.StringToScopes(DefaultScopes)
		req.Scope = DefaultScopes
	}

	// Check if user has already consented
	hasConsent, err := h.consentService.HasConsent(r.Context(), userID, req.ClientID, requestedScopes)
	if err != nil {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "Failed to check consent")
		return
	}

	if hasConsent {
		// User already consented - generate code and redirect
		h.issueAuthorizationCode(w, r, req, userID)
		return
	}

	// User needs to consent - render consent page
	h.renderConsentPage(w, r, req, client)
}

// parseAuthorizeRequest extracts and validates the authorization request parameters.
func (h *Handler) parseAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {
	q := r.URL.Query()

	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, fmt.Errorf("%w: client_id", ErrMissingParameter)
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		return nil, fmt.Errorf("%w: redirect_uri", ErrMissingParameter)
	}

	responseType := q.Get("response_type")
	if responseType == "" {
		return nil, fmt.Errorf("%w: response_type", ErrMissingParameter)
	}

	state := q.Get("state")
	if state == "" {
		return nil, fmt.Errorf("%w: state", ErrMissingParameter)
	}

	codeChallenge := q.Get("code_challenge")
	if codeChallenge == "" {
		return nil, fmt.Errorf("%w: code_challenge", ErrMissingParameter)
	}

	codeChallengeMethod := q.Get("code_challenge_method")
	if codeChallengeMethod == "" {
		return nil, fmt.Errorf("%w: code_challenge_method", ErrMissingParameter)
	}

	return &AuthorizeRequest{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		ResponseType:        responseType,
		Scope:               q.Get("scope"),
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Resource:            q.Get("resource"),
	}, nil
}

// redirectToLogin redirects the user to the login page with a return URL.
func (h *Handler) redirectToLogin(w http.ResponseWriter, r *http.Request, req *AuthorizeRequest) {
	// Build the return URL (the current authorize request)
	returnURL := r.URL.String()

	// Redirect to login with return_to parameter
	loginURL := "/login?return_to=" + url.QueryEscape(returnURL)
	http.Redirect(w, r, loginURL, http.StatusFound)
}

// renderConsentPage renders the OAuth consent page.
func (h *Handler) renderConsentPage(w http.ResponseWriter, r *http.Request, req *AuthorizeRequest, client *Client) {
	// Build scope descriptions for the template
	scopes := buildScopeList(req.Scope)

	// Store auth request in session cookie for consent form submission
	// We encode essential params to validate on POST
	authReqData := url.Values{
		"client_id":             {req.ClientID},
		"redirect_uri":          {req.RedirectURI},
		"scope":                 {req.Scope},
		"state":                 {req.State},
		"code_challenge":        {req.CodeChallenge},
		"code_challenge_method": {req.CodeChallengeMethod},
		"resource":              {req.Resource},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_auth_req",
		Value:    base64.RawURLEncoding.EncodeToString([]byte(authReqData.Encode())),
		Path:     "/oauth",
		HttpOnly: true,
		Secure:   auth.GetSecureCookies(),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600, // 10 minutes
	})

	data := map[string]interface{}{
		"Title":       "Authorize " + client.ClientName,
		"ClientName":  client.ClientName,
		"ClientID":    client.ClientID,
		"Scopes":      scopes,
		"State":       req.State,
		"RedirectURI": req.RedirectURI,
	}

	if err := h.renderer.Render(w, "oauth/consent.html", data); err != nil {
		h.renderAuthError(w, r, req.RedirectURI, req.State, fmt.Errorf("failed to render consent page: %w", err))
	}
}

// ScopeInfo holds scope name and description for the consent page.
type ScopeInfo struct {
	Name        string
	Description string
}

// buildScopeList creates the scope list with descriptions for the consent page.
func buildScopeList(scopeString string) []ScopeInfo {
	scopes := auth.StringToScopes(scopeString)
	if len(scopes) == 0 {
		scopes = auth.StringToScopes(DefaultScopes)
	}

	result := make([]ScopeInfo, 0, len(scopes))
	for _, scope := range scopes {
		desc, ok := scopeDescriptions[scope]
		if !ok {
			desc = scope // Use scope name as description if unknown
		}
		result = append(result, ScopeInfo{
			Name:        scope,
			Description: desc,
		})
	}
	return result
}

// issueAuthorizationCode generates an authorization code and redirects to the client.
func (h *Handler) issueAuthorizationCode(w http.ResponseWriter, r *http.Request, req *AuthorizeRequest, userID string) {
	// Determine resource - use server's resource if not specified
	resource := req.Resource
	if resource == "" {
		resource = h.provider.Resource()
	}

	// Create authorization code
	code, err := h.provider.CreateAuthorizationCode(r.Context(), AuthorizationCodeParams{
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Resource:            resource,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if err != nil {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "Failed to create authorization code")
		return
	}

	// Redirect to client with code
	redirectURL, _ := url.Parse(req.RedirectURI)
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", req.State)
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// HandleConsentSubmit handles POST /oauth/consent when user submits the consent form.
func (h *Handler) HandleConsentSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	decision := r.FormValue("decision")

	// Retrieve auth request from cookie
	cookie, err := r.Cookie("oauth_auth_req")
	if err != nil {
		http.Error(w, "Missing authorization request", http.StatusBadRequest)
		return
	}

	// Decode auth request
	authReqBytes, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}

	authReqValues, err := url.ParseQuery(string(authReqBytes))
	if err != nil {
		http.Error(w, "Invalid authorization request", http.StatusBadRequest)
		return
	}

	req := &AuthorizeRequest{
		ClientID:            authReqValues.Get("client_id"),
		RedirectURI:         authReqValues.Get("redirect_uri"),
		Scope:               authReqValues.Get("scope"),
		State:               authReqValues.Get("state"),
		CodeChallenge:       authReqValues.Get("code_challenge"),
		CodeChallengeMethod: authReqValues.Get("code_challenge_method"),
		Resource:            authReqValues.Get("resource"),
	}

	// Clear the auth request cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_auth_req",
		Value:    "",
		Path:     "/oauth",
		HttpOnly: true,
		Secure:   auth.GetSecureCookies(),
		MaxAge:   -1,
	})

	// Verify user is still authenticated
	sessionID, err := auth.GetFromRequest(r)
	if err != nil {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "User not authenticated")
		return
	}

	userID, err := h.sessionService.Validate(r.Context(), sessionID)
	if err != nil {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "Session expired")
		return
	}

	// Handle decision
	if decision != "allow" {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "access_denied", "User denied consent")
		return
	}

	// Record consent
	scopes := auth.StringToScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = auth.StringToScopes(DefaultScopes)
		req.Scope = DefaultScopes
	}

	if err := h.consentService.RecordConsent(r.Context(), userID, req.ClientID, scopes); err != nil {
		h.redirectWithError(w, r, req.RedirectURI, req.State, "server_error", "Failed to record consent")
		return
	}

	// Issue authorization code
	h.issueAuthorizationCode(w, r, req, userID)
}

// =============================================================================
// Token Endpoint
// =============================================================================

// TokenRequest contains the parsed token request parameters.
type TokenRequest struct {
	GrantType    string
	ClientID     string
	ClientSecret string
	Code         string
	RedirectURI  string
	CodeVerifier string
	RefreshToken string
	Resource     string
}

// TokenResponse is the OAuth token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenErrorResponse is the OAuth error response.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// HandleToken handles POST /oauth/token.
// This implements the OAuth 2.1 token endpoint for authorization_code and refresh_token grants.
func (h *Handler) HandleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeTokenError(w, http.StatusMethodNotAllowed, "invalid_request", "Method not allowed")
		return
	}

	// Parse form or JSON body
	contentType := r.Header.Get("Content-Type")
	var req TokenRequest
	var err error

	if strings.HasPrefix(contentType, "application/json") {
		err = json.NewDecoder(r.Body).Decode(&req)
	} else {
		err = r.ParseForm()
		if err == nil {
			req = TokenRequest{
				GrantType:    r.FormValue("grant_type"),
				ClientID:     r.FormValue("client_id"),
				ClientSecret: r.FormValue("client_secret"),
				Code:         r.FormValue("code"),
				RedirectURI:  r.FormValue("redirect_uri"),
				CodeVerifier: r.FormValue("code_verifier"),
				RefreshToken: r.FormValue("refresh_token"),
				Resource:     r.FormValue("resource"),
			}
		}
	}

	if err != nil {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "Failed to parse request")
		return
	}

	// Check for Basic auth as alternative client authentication
	if req.ClientID == "" || req.ClientSecret == "" {
		if username, password, ok := r.BasicAuth(); ok {
			if req.ClientID == "" {
				req.ClientID = username
			}
			if req.ClientSecret == "" {
				req.ClientSecret = password
			}
		}
	}

	// Validate required parameters
	if req.GrantType == "" {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "grant_type is required")
		return
	}

	if req.ClientID == "" {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return
	}

	// Dispatch to appropriate grant handler
	switch req.GrantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(w, r, &req)
	case "refresh_token":
		h.handleRefreshTokenGrant(w, r, &req)
	default:
		h.writeTokenError(w, http.StatusBadRequest, "unsupported_grant_type", "Grant type not supported")
	}
}

// handleAuthorizationCodeGrant handles the authorization_code grant type.
func (h *Handler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, req *TokenRequest) {
	// Validate required parameters
	if req.Code == "" {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	if req.RedirectURI == "" {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
		return
	}

	// Get authorization code
	authCode, err := h.provider.GetAuthorizationCode(r.Context(), req.Code)
	if err != nil {
		if errors.Is(err, ErrInvalidCode) {
			h.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Authorization code is invalid or expired")
		} else {
			h.writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to validate authorization code")
		}
		return
	}

	// Verify client_id matches
	if authCode.ClientID != req.ClientID {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "client_id does not match")
		return
	}

	// Verify redirect_uri matches
	if authCode.RedirectURI != req.RedirectURI {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri does not match")
		return
	}

	// Get client to check if public or confidential
	client, err := h.provider.GetClient(r.Context(), req.ClientID)
	if err != nil {
		h.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
		return
	}

	// Authenticate client based on type
	if client.IsPublic {
		// Public client - PKCE verification is REQUIRED, no client_secret check
		if req.CodeVerifier == "" {
			h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "code_verifier is required for public clients")
			return
		}
		// client_secret should not be provided for public clients
		if req.ClientSecret != "" {
			h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "client_secret must not be provided for public clients")
			return
		}
	} else {
		// Confidential client - client_secret is REQUIRED
		if req.ClientSecret == "" {
			h.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client_secret is required for confidential clients")
			return
		}
		// Verify client secret
		if err := VerifySecret(client.ClientSecretHash, req.ClientSecret); err != nil {
			h.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
			return
		}
	}

	// Verify PKCE
	if authCode.CodeChallenge != "" {
		if !verifyPKCE(req.CodeVerifier, authCode.CodeChallenge) {
			h.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid code_verifier")
			return
		}
	}

	// Verify resource if provided
	if req.Resource != "" && req.Resource != authCode.Resource {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_target", "resource does not match authorization code")
		return
	}

	// Delete the authorization code (one-time use)
	if err := h.provider.DeleteAuthorizationCode(r.Context(), req.Code); err != nil {
		// Log error but continue - code will expire anyway
	}

	// Create tokens
	tokens, err := h.provider.CreateTokens(r.Context(), TokenParams{
		ClientID:            req.ClientID,
		UserID:              authCode.UserID,
		Scope:               authCode.Scope,
		Resource:            authCode.Resource,
		IncludeRefreshToken: true,
	})
	if err != nil {
		h.writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to create tokens")
		return
	}

	// Write response
	h.writeTokenResponse(w, tokens)
}

// handleRefreshTokenGrant handles the refresh_token grant type.
func (h *Handler) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, req *TokenRequest) {
	// Validate required parameters
	if req.RefreshToken == "" {
		h.writeTokenError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
		return
	}

	// Get client to check if public or confidential
	client, err := h.provider.GetClient(r.Context(), req.ClientID)
	if err != nil {
		h.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Client not found")
		return
	}

	// Authenticate client
	if !client.IsPublic {
		// Confidential client - client_secret is REQUIRED
		if req.ClientSecret == "" {
			h.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "client_secret is required for confidential clients")
			return
		}
		if err := VerifySecret(client.ClientSecretHash, req.ClientSecret); err != nil {
			h.writeTokenError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
			return
		}
	}

	// Refresh tokens (this also validates the refresh token and client)
	tokens, err := h.provider.RefreshTokens(r.Context(), req.RefreshToken, TokenParams{
		ClientID:            req.ClientID,
		IncludeRefreshToken: true,
	})
	if err != nil {
		if errors.Is(err, ErrInvalidToken) || errors.Is(err, ErrInvalidClient) {
			h.writeTokenError(w, http.StatusBadRequest, "invalid_grant", "Invalid refresh token")
		} else {
			h.writeTokenError(w, http.StatusInternalServerError, "server_error", "Failed to refresh tokens")
		}
		return
	}

	// Write response
	h.writeTokenResponse(w, tokens)
}

// verifyPKCE verifies the code_verifier against the code_challenge using S256.
func verifyPKCE(codeVerifier, codeChallenge string) bool {
	if codeVerifier == "" || codeChallenge == "" {
		return false
	}

	// Compute S256 challenge from verifier
	h := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])

	// Constant-time comparison
	return subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) == 1
}

// =============================================================================
// Response Helpers
// =============================================================================

// writeTokenResponse writes a successful token response.
func (h *Handler) writeTokenResponse(w http.ResponseWriter, tokens *TokenResult) {
	resp := TokenResponse{
		AccessToken:  tokens.AccessToken,
		TokenType:    tokens.TokenType,
		ExpiresIn:    tokens.ExpiresIn,
		RefreshToken: tokens.RefreshToken,
		Scope:        tokens.Scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(resp)
}

// writeTokenError writes an OAuth token error response.
func (h *Handler) writeTokenError(w http.ResponseWriter, status int, errorCode, description string) {
	resp := TokenErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

// redirectWithError redirects to the client with an error.
func (h *Handler) redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errorCode, description string) {
	if redirectURI == "" {
		// Cannot redirect - render error page
		h.renderAuthError(w, r, "", "", fmt.Errorf("%s: %s", errorCode, description))
		return
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		h.renderAuthError(w, r, "", "", fmt.Errorf("invalid redirect_uri: %w", err))
		return
	}

	q := redirectURL.Query()
	q.Set("error", errorCode)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// renderAuthError renders an authorization error page.
func (h *Handler) renderAuthError(w http.ResponseWriter, r *http.Request, redirectURI, state string, err error) {
	// If we have a redirect URI and state, redirect with error
	if redirectURI != "" {
		h.redirectWithError(w, r, redirectURI, state, "server_error", err.Error())
		return
	}

	// Otherwise render error page
	if h.renderer != nil {
		h.renderer.RenderError(w, http.StatusBadRequest, err.Error())
	} else {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// =============================================================================
// Consent Database Integration
// =============================================================================

// ConsentDBService wraps the consent service to use the actual database.
// This integrates with the sessions database for OAuth consent storage.
type ConsentDBService struct {
	queries *sessions.Queries
}

// NewConsentDBService creates a new consent DB service.
func NewConsentDBService(queries *sessions.Queries) *ConsentDBService {
	return &ConsentDBService{queries: queries}
}

// HasConsent checks if the user has consented to the given scopes for the client.
func (s *ConsentDBService) HasConsent(ctx context.Context, userID, clientID string, scopes []string) (bool, error) {
	consent, err := s.queries.GetConsent(ctx, sessions.GetConsentParams{
		UserID:   userID,
		ClientID: clientID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}

	// Check if all requested scopes are in the consented scopes
	consentedScopes := auth.StringToScopes(consent.Scopes)
	consentedSet := make(map[string]bool)
	for _, s := range consentedScopes {
		consentedSet[s] = true
	}

	for _, scope := range scopes {
		if !consentedSet[scope] {
			return false, nil
		}
	}

	return true, nil
}

// RecordConsent records the user's consent for the given scopes.
func (s *ConsentDBService) RecordConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	scopeString := auth.ScopesToString(scopes)

	// Try to get existing consent to merge scopes
	existing, err := s.queries.GetConsent(ctx, sessions.GetConsentParams{
		UserID:   userID,
		ClientID: clientID,
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}

	now := time.Now().Unix()

	if errors.Is(err, sql.ErrNoRows) {
		// No existing consent - create new
		_, err = s.queries.CreateConsent(ctx, sessions.CreateConsentParams{
			ID:        uuid.New().String(),
			UserID:    userID,
			ClientID:  clientID,
			Scopes:    scopeString,
			GrantedAt: now,
		})
		return err
	}

	// Existing consent - merge scopes
	existingScopes := auth.StringToScopes(existing.Scopes)
	mergedScopes := mergeScopes(existingScopes, scopes)
	mergedScopeString := auth.ScopesToString(mergedScopes)

	_, err = s.queries.UpdateConsentScopes(ctx, sessions.UpdateConsentScopesParams{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    mergedScopeString,
		GrantedAt: now,
	})
	return err
}

// mergeScopes merges two scope lists and returns a deduplicated sorted list.
func mergeScopes(a, b []string) []string {
	seen := make(map[string]bool)
	for _, s := range a {
		seen[s] = true
	}
	for _, s := range b {
		seen[s] = true
	}

	result := make([]string, 0, len(seen))
	for s := range seen {
		result = append(result, s)
	}
	return result
}
