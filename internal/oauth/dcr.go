// dcr.go implements RFC 7591 Dynamic Client Registration for OAuth 2.1.
// Supports public and confidential clients.
package oauth

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kuitang/agent-notes/internal/db/sessions"
)

// DCRRequest represents the client registration request per RFC 7591.
type DCRRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// DCRResponse represents the client registration response per RFC 7591.
type DCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"` // Only for confidential clients
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"` // 0 means never expires
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	ClientName              string   `json:"client_name,omitempty"`
}

// DCRError represents an error response per RFC 7591.
type DCRError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// DCR error codes per RFC 7591.
const (
	DCRErrorInvalidRedirectURI       = "invalid_redirect_uri"
	DCRErrorInvalidClientMetadata    = "invalid_client_metadata"
	DCRErrorInvalidSoftwareStatement = "invalid_software_statement"
	DCRErrorUnapprovedSoftware       = "unapproved_software_statement"
)

// DCR handles POST /oauth/register for RFC 7591 Dynamic Client Registration.
func (p *Provider) DCR(w http.ResponseWriter, r *http.Request) {
	// Only allow POST
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var req DCRRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeDCRError(w, http.StatusBadRequest, DCRErrorInvalidClientMetadata, "Invalid JSON request body")
		return
	}

	// Validate redirect_uris are present
	if len(req.RedirectURIs) == 0 {
		writeDCRError(w, http.StatusBadRequest, DCRErrorInvalidClientMetadata, "redirect_uris is required")
		return
	}

	// Validate redirect_uris
	if err := validateRedirectURIs(req.RedirectURIs); err != nil {
		writeDCRError(w, http.StatusBadRequest, DCRErrorInvalidRedirectURI, err.Error())
		return
	}

	// Determine client type from token_endpoint_auth_method
	isPublic := isPublicClient(req.TokenEndpointAuthMethod)

	// Validate token_endpoint_auth_method
	if !isValidAuthMethod(req.TokenEndpointAuthMethod) {
		writeDCRError(w, http.StatusBadRequest, DCRErrorInvalidClientMetadata,
			"Invalid token_endpoint_auth_method. Allowed: none, client_secret_post, client_secret_basic")
		return
	}

	// Determine auth method (default based on client type)
	authMethod := req.TokenEndpointAuthMethod
	if authMethod == "" {
		if isPublic {
			authMethod = "none"
		} else {
			authMethod = "client_secret_post"
		}
	}

	// Default grant_types and response_types if not provided
	grantTypes := req.GrantTypes
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code", "refresh_token"}
	}

	responseTypes := req.ResponseTypes
	if len(responseTypes) == 0 {
		responseTypes = []string{"code"}
	}

	// Generate client credentials
	clientID, err := GenerateSecureID()
	if err != nil {
		writeDCRError(w, http.StatusInternalServerError, DCRErrorInvalidClientMetadata, "Failed to generate client_id")
		return
	}

	var clientSecret string
	var clientSecretHash sql.NullString

	if !isPublic {
		// Confidential client - generate and hash secret
		clientSecret, err = GenerateSecureSecret()
		if err != nil {
			writeDCRError(w, http.StatusInternalServerError, DCRErrorInvalidClientMetadata, "Failed to generate client_secret")
			return
		}
		hash, err := p.secretHash.HashSecret(clientSecret)
		if err != nil {
			writeDCRError(w, http.StatusInternalServerError, DCRErrorInvalidClientMetadata, "Failed to hash client_secret")
			return
		}
		clientSecretHash = sql.NullString{String: hash, Valid: true}
	}

	// Store the client
	now := time.Now()
	isPublicInt := int64(0)
	if isPublic {
		isPublicInt = 1
	}

	err = p.queries.CreateOAuthClient(r.Context(), sessions.CreateOAuthClientParams{
		ClientID:         clientID,
		ClientSecretHash: clientSecretHash,
		ClientName:       sql.NullString{String: req.ClientName, Valid: req.ClientName != ""},
		RedirectUris:     serializeRedirectURIs(req.RedirectURIs),
		IsPublic:         isPublicInt,
		TokenEndpointAuthMethod: sql.NullString{
			String: authMethod,
			Valid:  true,
		},
		CreatedAt: now.Unix(),
	})
	if err != nil {
		writeDCRError(w, http.StatusInternalServerError, DCRErrorInvalidClientMetadata, "Failed to store client")
		return
	}

	// Build response
	resp := DCRResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypes,
		ResponseTypes:           responseTypes,
		TokenEndpointAuthMethod: authMethod,
		ClientName:              req.ClientName,
	}

	// Only include client_secret for confidential clients
	if !isPublic {
		resp.ClientSecret = clientSecret
		// client_secret_expires_at = 0 means never expires
		resp.ClientSecretExpiresAt = 0
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// validateRedirectURIs checks all redirect_uris are valid absolute URLs.
func validateRedirectURIs(uris []string) error {
	for _, uri := range uris {
		if err := validateRedirectURI(uri); err != nil {
			return err
		}
	}
	return nil
}

// validateRedirectURI validates one redirect URI for DCR.
func validateRedirectURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return &redirectURIError{uri: raw, reason: "must not be empty"}
	}

	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" || parsed.Host == "" {
		return &redirectURIError{uri: raw, reason: "must be an absolute URI with scheme and host"}
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "http" {
		if !isAllowedInsecureLoopbackRedirectHost(parsed.Hostname()) {
			return &redirectURIError{uri: raw, reason: "scheme must be https"}
		}
	} else if scheme != "https" {
		return &redirectURIError{uri: raw, reason: "scheme must be https"}
	}

	if parsed.Fragment != "" {
		return &redirectURIError{uri: raw, reason: "must not include fragment"}
	}

	return nil
}

func isAllowedInsecureLoopbackRedirectHost(host string) bool {
	if host == "localhost" {
		return true
	}

	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// isPublicClient determines if the client is public based on auth method.
func isPublicClient(authMethod string) bool {
	// "none" or empty indicates public-client auth behavior.
	return authMethod == "none" || authMethod == ""
}

// isValidAuthMethod checks if the auth method is supported.
func isValidAuthMethod(method string) bool {
	switch method {
	case "", "none", "client_secret_post", "client_secret_basic":
		return true
	default:
		return false
	}
}

// redirectURIError is an error for invalid redirect URIs.
type redirectURIError struct {
	uri    string
	reason string
}

func (e *redirectURIError) Error() string {
	if e.reason == "" {
		return "invalid redirect URI: " + e.uri
	}
	return "invalid redirect URI: " + e.reason
}

// writeDCRError writes an RFC 7591 error response.
func writeDCRError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(DCRError{
		Error:            errorCode,
		ErrorDescription: description,
	})
}
