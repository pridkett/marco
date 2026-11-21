package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/pridkett/marco/internal/auth"
	"github.com/pridkett/marco/internal/config"
)

const (
	managementPrefix = "/api/v1"
	mcpPath          = managementPrefix + "/mcp"
	resourceMetadata = "/.well-known/oauth-protected-resource"
	managementRead   = "marco:read"
	managementWrite  = "marco:policies:write"
	managementLimit  = 1 << 20
)

const managementPageDefault = 50

type managementError struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

func badInput(message string) *managementError {
	return &managementError{http.StatusBadRequest, message}
}

func unavailable(message string) *managementError {
	return &managementError{http.StatusServiceUnavailable, message}
}

type operation struct {
	method, path string
	tool         mcpTool
	write        bool
	queryNumbers []string
	invoke       func(context.Context, auth.AccessToken, json.RawMessage) (any, *managementError)
}

func managementOperation[I, O any](method, path, name, description string, schema json.RawMessage, queryNumbers []string,
	write bool, handler func(context.Context, auth.AccessToken, I) (O, *managementError)) operation {
	return operation{
		method: method, path: managementPrefix + path, write: write, queryNumbers: queryNumbers,
		tool: mcpTool{Name: name, Description: description, InputSchema: schema, Annotations: toolAnnotations{ReadOnly: !write}},
		invoke: func(ctx context.Context, actor auth.AccessToken, raw json.RawMessage) (any, *managementError) {
			var in I
			raw = bytes.TrimSpace(raw)
			if len(raw) == 0 {
				raw = json.RawMessage("{}")
			}
			if raw[0] != '{' || config.DecodeJSON(bytes.NewReader(raw), &in) != nil {
				return nil, badInput("Provide a JSON object matching the operation's arguments.")
			}
			ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			return handler(ctx, actor, in)
		},
	}
}

func (s *server) managementOperations() []operation {
	defaultPage, maxPage := s.managementPageLimits()
	return []operation{
		managementOperation(http.MethodGet, "/dashboard", "get_dashboard",
			"Get DNS counts, activity buckets, cache hit rate, blocking status, and top clients and domains. Defaults to 24h. "+
				"Rankings are cached for a minute. rankings.asOf gives their time and rankings.updating means newer ones are being calculated. "+
				"When rankingsPending is true, the first rankings are still being calculated, so ask again in a few seconds.",
			objectSchema(dashboardSchema), nil, false, s.managementDashboard),
		managementOperation(http.MethodGet, "/query-log", "search_query_log",
			"Search retained DNS history, newest first. Pass next as before to fetch an older page with the same filters.",
			pagedSchema(historyProperties, defaultPage, maxPage), []string{"before", "limit"}, false, s.managementHistory),
		managementOperation(http.MethodPost, "/policies/test", "test_policy",
			"Preview a DNS query for a client IP using a domain or HTTP(S) URL. Explains the selected policy and result without contacting an upstream.",
			objectSchema(previewSchema), nil, false, s.managementPreview),
		managementOperation(http.MethodGet, "/policies", "get_policies",
			"Get current policy settings, valid reference IDs, and the revision needed for a policy edit.",
			objectSchema(""), nil, false, s.managementPolicies),
		managementOperation(http.MethodPatch, "/policies", "update_policies",
			"Update the configured DNS policies at the supplied revision. Fetch get_policies first. Default and assignments replace those sections. Groups and services merge by key, with null deleting an entry. Requires marco:policies:write.",
			objectSchema(policyPatchSchema), nil, true, s.managementPatchPolicy),
		managementOperation(http.MethodGet, "/devices", "list_clients",
			"Find UniFi, manual, and legacy clients. Get addresses, presence, assigned policies, DNS publication and last site poll. Pass next as after to continue.",
			pagedSchema(devicesProperties, defaultPage, maxPage), []string{"limit"}, false, s.managementDevices),
	}
}

func (s *server) managementPageLimits() (defaultPage, maxPage int) {
	maxPage = s.hooks.ManagementMaxPageSize
	if maxPage == 0 {
		maxPage = config.DefaultManagementMaxPageSize
	}
	return min(managementPageDefault, maxPage), maxPage
}

func (s *server) managementPageSize(limit int) (int, *managementError) {
	defaultPage, maxPage := s.managementPageLimits()
	if limit < 0 || limit > maxPage {
		return 0, badInput(fmt.Sprintf("The page limit must be between 1 and %d.", maxPage))
	}
	if limit == 0 {
		return defaultPage, nil
	}
	return limit, nil
}

func (s *server) registerManagement(mux *http.ServeMux) {
	resource := s.auth.PublicOrigin() + mcpPath
	metadataPath := resourceMetadata + mcpPath
	for _, path := range []string{metadataPath, resourceMetadata} {
		mux.HandleFunc("GET "+path, s.secure(func(w http.ResponseWriter, _ *http.Request) {
			writeManagementJSON(w, http.StatusOK, map[string]any{
				"resource":                 resource,
				"resource_name":            "Marco management",
				"authorization_servers":    []string{s.auth.OIDCIssuer()},
				"scopes_supported":         []string{managementRead, managementWrite},
				"bearer_methods_supported": []string{"header"},
			})
		}))
	}
	operations := s.managementOperations()
	mux.HandleFunc(mcpPath, s.managementProtected(resource, func(w http.ResponseWriter, r *http.Request, actor auth.AccessToken) {
		serveMCP(w, r, operations, actor, s.auth.PublicOrigin()+metadataPath, s.hooks.Version)
	}))
	for _, op := range operations {
		mux.HandleFunc(op.method+" "+op.path, s.managementProtected(resource, func(w http.ResponseWriter, r *http.Request, actor auth.AccessToken) {
			if !requireManagementWrite(w, actor, s.auth.PublicOrigin()+metadataPath, op) {
				return
			}
			raw, err := restArguments(w, r, op)
			if err != nil {
				writeManagementJSON(w, err.Status, err)
				return
			}
			result, err := op.invoke(r.Context(), actor, raw)
			if err != nil {
				writeManagementJSON(w, err.Status, err)
				return
			}
			writeManagementJSON(w, http.StatusOK, result)
		}))
	}
}

func (s *server) managementProtected(resource string, next func(http.ResponseWriter, *http.Request, auth.AccessToken)) http.HandlerFunc {
	metadata := s.auth.PublicOrigin() + resourceMetadata + mcpPath
	return s.secure(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.AccessOriginAllowed(r) {
			writeManagementJSON(w, http.StatusForbidden, &managementError{http.StatusForbidden, "This request origin is not allowed."})
			return
		}

		headers := r.Header.Values("Authorization")
		if len(headers) != 1 {
			bearerChallenge(w, http.StatusUnauthorized, "", metadata, managementRead)
			return
		}
		scheme, raw, ok := strings.Cut(headers[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
			bearerChallenge(w, http.StatusUnauthorized, "invalid_token", metadata, managementRead)
			return
		}
		actor, err := s.auth.VerifyAccessToken(r.Context(), strings.TrimLeft(raw, " "), resource)
		if errors.Is(err, auth.ErrCredentials) {
			bearerChallenge(w, http.StatusUnauthorized, "invalid_token", metadata, managementRead)
			return
		}
		if err != nil {
			failure := unavailable("The configured identity provider is temporarily unavailable.")
			writeManagementJSON(w, failure.Status, failure)
			return
		}
		if !slices.Contains(actor.Scopes, managementRead) {
			bearerChallenge(w, http.StatusForbidden, "insufficient_scope", metadata, managementRead)
			return
		}
		next(w, r, actor)
	})
}

func requireManagementWrite(w http.ResponseWriter, actor auth.AccessToken, metadata string, op operation) bool {
	if op.write && !slices.Contains(actor.Scopes, managementWrite) {
		bearerChallenge(w, http.StatusForbidden, "insufficient_scope", metadata, managementRead+" "+managementWrite)
		return false
	}
	return true
}

func bearerChallenge(w http.ResponseWriter, status int, code, metadata, scopes string) {
	challenge := fmt.Sprintf("Bearer resource_metadata=%q, scope=%q", metadata, scopes)
	message := "A valid bearer token is required."
	if code != "" {
		challenge += fmt.Sprintf(", error=%q", code)
	}
	if status == http.StatusForbidden {
		message = "The bearer token lacks the required permissions."
	}
	w.Header().Set("WWW-Authenticate", challenge)
	writeManagementJSON(w, status, &managementError{status, message})
}

func restArguments(w http.ResponseWriter, r *http.Request, op operation) (json.RawMessage, *managementError) {
	if op.method != http.MethodGet {
		return managementBody(w, r)
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, badInput("The query parameters are invalid.")
	}
	args := make(map[string]any, len(values))
	for key, value := range values {
		if len(value) != 1 {
			return nil, badInput("Pass each query parameter once.")
		}
		if slices.Contains(op.queryNumbers, key) {
			n, err := strconv.ParseInt(value[0], 10, 64)
			if err != nil {
				return nil, badInput("The cursor or limit must be an integer.")
			}
			args[key] = n
		} else {
			args[key] = value[0]
		}
	}
	raw, _ := json.Marshal(args)
	return raw, nil
}

func managementBody(w http.ResponseWriter, r *http.Request) (json.RawMessage, *managementError) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		return nil, &managementError{http.StatusUnsupportedMediaType, "Send an application/json request body."}
	}
	r.Body = http.MaxBytesReader(w, r.Body, managementLimit)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			return nil, &managementError{http.StatusRequestEntityTooLarge, "The request body is too large."}
		}
		return nil, badInput("The request body could not be read.")
	}
	if !utf8.Valid(raw) || !json.Valid(raw) {
		return nil, badInput("Send a single valid UTF-8 JSON document.")
	}
	return raw, nil
}

func writeManagementJSON(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}
