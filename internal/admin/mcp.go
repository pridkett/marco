package admin

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/pridkett/marco/internal/auth"
)

const (
	currentMCPVersion = "2026-07-28"
	legacyMCPVersion  = "2025-11-25"
	mcpVersionHeader  = "MCP-Protocol-Version"
)

var mcpVersions = []string{currentMCPVersion, legacyMCPVersion, "2025-06-18", "2025-03-26"}

type toolAnnotations struct {
	ReadOnly bool `json:"readOnlyHint"`
}

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Annotations toolAnnotations `json:"annotations"`
}

type mcpRequest struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type mcpParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Name            string          `json:"name"`
	URI             string          `json:"uri"`
	Arguments       json.RawMessage `json:"arguments"`
	Meta            struct {
		Version      string          `json:"io.modelcontextprotocol/protocolVersion"`
		Info         json.RawMessage `json:"io.modelcontextprotocol/clientInfo"`
		Capabilities json.RawMessage `json:"io.modelcontextprotocol/clientCapabilities"`
	} `json:"_meta"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type mcpResponse struct {
	Version string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

func serveMCP(w http.ResponseWriter, r *http.Request, ops []operation, actor auth.AccessToken, metadata, version string) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	reply := mcpResponse{Version: "2.0"}
	fail := func(status, code int, message string, data any) {
		reply.Error = &mcpError{code, message, data}
		writeManagementJSON(w, status, reply)
	}
	raw, err := managementBody(w, r)
	if err != nil {
		fail(err.Status, -32700, err.Message, nil)
		return
	}
	var req mcpRequest
	if json.Unmarshal(raw, &req) != nil || req.Version != "2.0" || req.Method == "" {
		fail(http.StatusBadRequest, -32600, "Invalid JSON-RPC request.", nil)
		return
	}
	if len(req.ID) != 0 {
		if !validMCPID(req.ID) {
			fail(http.StatusBadRequest, -32600, "Use a string or integer request ID.", nil)
			return
		}
		reply.ID = req.ID
	}
	var params mcpParams
	if len(req.Params) != 0 && (!jsonObject(req.Params) || json.Unmarshal(req.Params, &params) != nil) {
		fail(http.StatusBadRequest, -32602, "Provide a JSON object for params.", nil)
		return
	}

	header := r.Header.Get(mcpVersionHeader)
	if version := params.Meta.Version; version != "" && !slices.Contains(mcpVersions, version) ||
		header != "" && !slices.Contains(mcpVersions, header) {
		requested := header
		if params.Meta.Version != "" && !slices.Contains(mcpVersions, params.Meta.Version) {
			requested = params.Meta.Version
		}
		fail(http.StatusBadRequest, -32022, "Unsupported protocol version.",
			map[string]any{"supported": mcpVersions, "requested": requested})
		return
	}
	modern := header == currentMCPVersion || params.Meta.Version == currentMCPVersion
	if modern && len(req.ID) != 0 && !mcpHeadersMatch(r, req.Method, params) {
		fail(http.StatusBadRequest, -32020, "MCP request headers must match the request body.", nil)
		return
	}
	if len(req.ID) == 0 {
		if !strings.HasPrefix(req.Method, "notifications/") {
			fail(http.StatusBadRequest, -32600, "A request ID is required.", nil)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if version == "" {
		version = "dev"
	}
	info := map[string]string{"name": "marco", "title": "Marco", "version": version}
	capabilities := map[string]any{"tools": struct{}{}}
	result := map[string]any{}
	if modern {
		result["resultType"] = "complete"
	}
	switch req.Method {
	case "initialize":
		if modern || params.ProtocolVersion == "" {
			fail(http.StatusBadRequest, -32602, "Provide a handshake protocol version.", nil)
			return
		}
		version := params.ProtocolVersion
		if !slices.Contains(mcpVersions[1:], version) {
			version = legacyMCPVersion
		}
		result["protocolVersion"] = version
		result["serverInfo"] = info
		result["capabilities"] = capabilities
	case "server/discover":
		result["resultType"] = "complete"
		result["supportedVersions"] = mcpVersions
		result["capabilities"] = capabilities
		result["_meta"] = map[string]any{"io.modelcontextprotocol/serverInfo": info}
	case "ping":
	case "tools/list":
		tools := make([]mcpTool, 0, len(ops))
		for _, op := range ops {
			tools = append(tools, op.tool)
		}
		result["tools"] = tools
	case "tools/call":
		i := slices.IndexFunc(ops, func(op operation) bool { return op.tool.Name == params.Name })
		if i < 0 {
			fail(http.StatusOK, -32602, "Unknown tool.", nil)
			return
		}
		op := ops[i]
		if !requireManagementWrite(w, actor, metadata, op) {
			return
		}
		output, problem := op.invoke(r.Context(), actor, params.Arguments)
		if problem != nil {
			result["isError"] = true
			output = problem
		}
		content, marshalErr := json.Marshal(output)
		if marshalErr != nil {
			fail(http.StatusInternalServerError, -32603, "The tool result could not be encoded.", nil)
			return
		}
		result["structuredContent"] = json.RawMessage(content)
		result["content"] = []map[string]string{{"type": "text", "text": string(content)}}
	default:
		status := http.StatusOK
		if modern {
			status = http.StatusNotFound
		}
		fail(status, -32601, "Method not found.", nil)
		return
	}
	reply.Result = result
	writeManagementJSON(w, http.StatusOK, reply)
}

func validMCPID(id json.RawMessage) bool {
	if id[0] == '"' {
		return true
	}
	return (id[0] == '-' || id[0] >= '0' && id[0] <= '9') && !strings.ContainsAny(string(id), ".eE")
}

func jsonObject(raw json.RawMessage) bool {
	return bytes.HasPrefix(bytes.TrimSpace(raw), []byte("{"))
}

func mcpHeadersMatch(r *http.Request, method string, p mcpParams) bool {
	if !matchesHeader(r, mcpVersionHeader, currentMCPVersion) || p.Meta.Version != currentMCPVersion ||
		!matchesHeader(r, "Mcp-Method", method) || !jsonObject(p.Meta.Info) || !jsonObject(p.Meta.Capabilities) {
		return false
	}
	switch method {
	case "tools/call", "prompts/get":
		return matchesHeader(r, "Mcp-Name", p.Name)
	case "resources/read":
		return matchesHeader(r, "Mcp-Name", p.URI)
	default:
		return true
	}
}

func matchesHeader(r *http.Request, key, value string) bool {
	headers := r.Header.Values(key)
	if len(headers) != 1 || value == "" {
		return false
	}
	header := headers[0]
	if key == "Mcp-Name" && strings.HasPrefix(header, "=?base64?") && strings.HasSuffix(header, "?=") {
		decoded, err := base64.StdEncoding.DecodeString(header[len("=?base64?") : len(header)-len("?=")])
		return err == nil && string(decoded) == value
	}
	return header == value
}
