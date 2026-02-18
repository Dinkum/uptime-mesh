package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	agentVersion = "0.2.0"
)

type Config struct {
	EnvFile                   string
	LogFile                   string
	LogLevel                  string
	APIServerURL              string
	NodeID                    string
	IdentityDir               string
	HeartbeatIntervalSeconds  int
	HeartbeatTTLSeconds       int
	EnableWireGuard           bool
	MeshCIDR                  string
	PrimaryIface              string
	SecondaryIface            string
	PrimaryRouterIP           string
	SecondaryRouterIP         string
	PrimaryMetric             int
	SecondaryMetric           int
	FailoverThreshold         int
	FailbackStableCount       int
	FailbackEnabled           bool
	CommandTimeoutSeconds     int
	PingTimeoutSeconds        int
	WGKeyDir                  string
	WGLocalAddress            string
	PrimaryListenPort         int
	SecondaryListenPort       int
	PeerPort                  int
	PeerAllowedIPs            string
	PersistentKeepaliveSeconds int
	PrimaryPeerPublicKey      string
	SecondaryPeerPublicKey    string
	PrimaryPeerEndpoint       string
	SecondaryPeerEndpoint     string
	EnableUnixSocketAPI       bool
	UnixSocketPath            string
}

type Logger struct {
	mu       sync.Mutex
	level    int
	filePath string
	file     *os.File
}

type FailoverState struct {
	ActiveIface       string
	PrimaryFailures   int
	PrimarySuccesses  int
	SecondaryFailures int
	SecondarySuccesses int
}

type Agent struct {
	cfg    Config
	log    *Logger
	client *http.Client
	state  FailoverState
	mu     sync.RWMutex

	lastTickAt         time.Time
	lastTickDurationMs int64
	lastTickError      string
	lastHeartbeatAt    time.Time
	lastHeartbeatError string
	lastStatusPatch    map[string]any
}

type wgPeerIntent struct {
	publicKey          string
	endpoint           string
	allowedIPs         string
	persistentKeepalive int
}

func main() {
	envFile := flag.String("env-file", ".env", "Path to env file")
	once := flag.Bool("once", false, "Run one agent iteration and exit")
	flag.Parse()

	cfg, err := loadConfig(*envFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger, err := newLogger(cfg.LogLevel, cfg.LogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger error: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	logger.Info("agent", "agent.start", "Starting Go node agent", map[string]any{
		"version":            agentVersion,
		"node_id":            cfg.NodeID,
		"api_url":            cfg.APIServerURL,
		"heartbeat_interval": cfg.HeartbeatIntervalSeconds,
		"wireguard_enabled":  cfg.EnableWireGuard,
		"env_file":           cfg.EnvFile,
	})

	agent := &Agent{
		cfg: cfg,
		log: logger,
		client: &http.Client{
			Timeout: time.Duration(cfg.CommandTimeoutSeconds) * time.Second,
		},
		state: FailoverState{ActiveIface: cfg.PrimaryIface},
		lastStatusPatch: map[string]any{},
	}

	if *once {
		if err := agent.tick(context.Background()); err != nil {
			logger.Error("agent", "agent.tick", "One-shot run failed", map[string]any{
				"error": err.Error(),
			})
			os.Exit(1)
		}
		logger.Info("agent", "agent.stop", "One-shot run completed", nil)
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if cfg.EnableUnixSocketAPI {
		if err := agent.startUnixSocketAPI(ctx); err != nil {
			logger.Error("agent.admin", "socket.start", "Failed to start unix socket admin API", map[string]any{
				"socket_path": cfg.UnixSocketPath,
				"error":       err.Error(),
			})
			os.Exit(1)
		}
	} else {
		logger.Info("agent.admin", "socket.skip", "Unix socket admin API disabled", map[string]any{
			"socket_path": cfg.UnixSocketPath,
		})
	}

	interval := time.Duration(cfg.HeartbeatIntervalSeconds) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := agent.tick(ctx); err != nil {
		logger.Warn("agent", "agent.tick", "Initial tick failed", map[string]any{
			"error": err.Error(),
		})
	}

	for {
		select {
		case <-ctx.Done():
			logger.Info("agent", "agent.stop", "Stopping Go node agent", nil)
			return
		case <-ticker.C:
			if err := agent.tick(ctx); err != nil {
				logger.Warn("agent", "agent.tick", "Tick failed", map[string]any{
					"error": err.Error(),
				})
			}
		}
	}
}

func loadConfig(envFile string) (Config, error) {
	env := loadEnvFile(envFile)
	get := func(key string, fallback string) string {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
		if v := strings.TrimSpace(env[key]); v != "" {
			return v
		}
		return fallback
	}
	parseInt := func(key string, fallback int) int {
		v := get(key, "")
		if v == "" {
			return fallback
		}
		parsed, err := strconv.Atoi(v)
		if err != nil {
			return fallback
		}
		return parsed
	}
	parseBool := func(key string, fallback bool) bool {
		v := strings.ToLower(strings.TrimSpace(get(key, "")))
		if v == "" {
			return fallback
		}
		switch v {
		case "1", "true", "yes", "y", "on":
			return true
		case "0", "false", "no", "n", "off":
			return false
		default:
			return fallback
		}
	}
	logFile := get("AGENT_LOG_FILE", "")
	if strings.TrimSpace(logFile) == "" {
		logFile = get("LOG_FILE", "data/agent.log")
	}

	cfg := Config{
		EnvFile:                  envFile,
		LogFile:                  logFile,
		LogLevel:                 get("LOG_LEVEL", "INFO"),
		APIServerURL:             strings.TrimSuffix(get("RUNTIME_API_BASE_URL", "http://127.0.0.1:8010"), "/"),
		NodeID:                   get("RUNTIME_NODE_ID", ""),
		IdentityDir:              get("RUNTIME_IDENTITY_DIR", "data/identities"),
		HeartbeatIntervalSeconds: parseInt("RUNTIME_HEARTBEAT_INTERVAL_SECONDS", 15),
		HeartbeatTTLSeconds:      parseInt("RUNTIME_HEARTBEAT_TTL_SECONDS", 45),
		EnableWireGuard:          parseBool("RUNTIME_WG_CONFIGURE", true),
		MeshCIDR:                 get("RUNTIME_MESH_CIDR", "10.42.0.0/16"),
		PrimaryIface:             get("RUNTIME_WG_PRIMARY_IFACE", "wg-mesh0"),
		SecondaryIface:           get("RUNTIME_WG_SECONDARY_IFACE", "wg-mesh1"),
		PrimaryRouterIP:          get("RUNTIME_WG_PRIMARY_ROUTER_IP", ""),
		SecondaryRouterIP:        get("RUNTIME_WG_SECONDARY_ROUTER_IP", ""),
		PrimaryMetric:            parseInt("RUNTIME_ROUTE_PRIMARY_METRIC", 100),
		SecondaryMetric:          parseInt("RUNTIME_ROUTE_SECONDARY_METRIC", 200),
		FailoverThreshold:        parseInt("RUNTIME_FAILOVER_THRESHOLD", 3),
		FailbackStableCount:      parseInt("RUNTIME_FAILBACK_STABLE_COUNT", 6),
		FailbackEnabled:          parseBool("RUNTIME_FAILBACK_ENABLED", false),
		CommandTimeoutSeconds:    parseInt("RUNTIME_COMMAND_TIMEOUT_SECONDS", 6),
		PingTimeoutSeconds:       parseInt("RUNTIME_PING_TIMEOUT_SECONDS", 1),
		WGKeyDir:                 get("RUNTIME_WG_KEY_DIR", "data/wireguard"),
		WGLocalAddress:           get("RUNTIME_WG_LOCAL_ADDRESS", ""),
		PrimaryListenPort:        parseInt("RUNTIME_WG_PRIMARY_LISTEN_PORT", 51820),
		SecondaryListenPort:      parseInt("RUNTIME_WG_SECONDARY_LISTEN_PORT", 51821),
		PeerPort:                 parseInt("RUNTIME_WG_PEER_PORT", 51820),
		PeerAllowedIPs:           get("RUNTIME_WG_PEER_ALLOWED_IPS", ""),
		PersistentKeepaliveSeconds: parseInt("RUNTIME_WG_PERSISTENT_KEEPALIVE_SECONDS", 25),
		PrimaryPeerPublicKey:     get("RUNTIME_WG_PRIMARY_PEER_PUBLIC_KEY", ""),
		SecondaryPeerPublicKey:   get("RUNTIME_WG_SECONDARY_PEER_PUBLIC_KEY", ""),
		PrimaryPeerEndpoint:      get("RUNTIME_WG_PRIMARY_PEER_ENDPOINT", ""),
		SecondaryPeerEndpoint:    get("RUNTIME_WG_SECONDARY_PEER_ENDPOINT", ""),
		EnableUnixSocketAPI:      parseBool("AGENT_ENABLE_UNIX_SOCKET", true),
		UnixSocketPath:           get("AGENT_UNIX_SOCKET", "data/agent.sock"),
	}

	if cfg.NodeID == "" {
		return Config{}, errors.New("RUNTIME_NODE_ID is required")
	}
	if cfg.HeartbeatIntervalSeconds < 5 {
		cfg.HeartbeatIntervalSeconds = 5
	}
	if cfg.HeartbeatTTLSeconds < 10 {
		cfg.HeartbeatTTLSeconds = 10
	}
	if cfg.FailoverThreshold < 1 {
		cfg.FailoverThreshold = 1
	}
	if cfg.FailbackStableCount < 1 {
		cfg.FailbackStableCount = 1
	}
	if cfg.PrimaryListenPort < 0 || cfg.PrimaryListenPort > 65535 {
		cfg.PrimaryListenPort = 51820
	}
	if cfg.SecondaryListenPort < 0 || cfg.SecondaryListenPort > 65535 {
		cfg.SecondaryListenPort = 51821
	}
	if cfg.PeerPort < 1 || cfg.PeerPort > 65535 {
		cfg.PeerPort = 51820
	}
	if cfg.PersistentKeepaliveSeconds < 0 {
		cfg.PersistentKeepaliveSeconds = 0
	}
	return cfg, nil
}

func loadEnvFile(path string) map[string]string {
	out := map[string]string{}
	content, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		raw := strings.TrimSpace(line)
		if raw == "" || strings.HasPrefix(raw, "#") || !strings.Contains(raw, "=") {
			continue
		}
		key, value, _ := strings.Cut(raw, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		value = strings.Trim(value, `"'`)
		out[key] = value
	}
	return out
}

func newLogger(level string, filePath string) (*Logger, error) {
	lvl := parseLogLevel(level)
	path := strings.TrimSpace(filePath)
	if path == "" {
		path = "data/app.log"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	return &Logger{
		level:    lvl,
		filePath: path,
		file:     f,
	}, nil
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *Logger) Debug(category, event, msg string, fields map[string]any) {
	l.log(10, "DEBUG", category, event, msg, fields)
}

func (l *Logger) Info(category, event, msg string, fields map[string]any) {
	l.log(20, "INFO", category, event, msg, fields)
}

func (l *Logger) Warn(category, event, msg string, fields map[string]any) {
	l.log(30, "WARNING", category, event, msg, fields)
}

func (l *Logger) Error(category, event, msg string, fields map[string]any) {
	l.log(40, "ERROR", category, event, msg, fields)
}

func (a *Agent) snapshotStatus() map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()

	statusPatch := map[string]any{}
	for key, value := range a.lastStatusPatch {
		statusPatch[key] = value
	}

	lastTickAt := ""
	if !a.lastTickAt.IsZero() {
		lastTickAt = a.lastTickAt.UTC().Format(time.RFC3339Nano)
	}
	lastHeartbeatAt := ""
	if !a.lastHeartbeatAt.IsZero() {
		lastHeartbeatAt = a.lastHeartbeatAt.UTC().Format(time.RFC3339Nano)
	}

	return map[string]any{
		"node_id":                a.cfg.NodeID,
		"agent_version":          agentVersion,
		"wireguard_enabled":      a.cfg.EnableWireGuard,
		"active_iface":           a.state.ActiveIface,
		"primary_failures":       a.state.PrimaryFailures,
		"primary_successes":      a.state.PrimarySuccesses,
		"secondary_failures":     a.state.SecondaryFailures,
		"secondary_successes":    a.state.SecondarySuccesses,
		"last_tick_at":           lastTickAt,
		"last_tick_duration_ms":  a.lastTickDurationMs,
		"last_tick_error":        a.lastTickError,
		"last_heartbeat_at":      lastHeartbeatAt,
		"last_heartbeat_error":   a.lastHeartbeatError,
		"latest_status_patch":    statusPatch,
		"unix_socket_api_enabled": a.cfg.EnableUnixSocketAPI,
		"unix_socket_path":       a.cfg.UnixSocketPath,
	}
}

func writeJSON(w http.ResponseWriter, statusCode int, payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "json encode error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

func (a *Agent) startUnixSocketAPI(ctx context.Context) error {
	socketPath := strings.TrimSpace(a.cfg.UnixSocketPath)
	if socketPath == "" {
		return errors.New("AGENT_UNIX_SOCKET is empty")
	}
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0o755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on unix socket: %w", err)
	}
	if chmodErr := os.Chmod(socketPath, 0o600); chmodErr != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		return fmt.Errorf("chmod socket: %w", chmodErr)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"detail": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":        "ok",
			"node_id":       a.cfg.NodeID,
			"agent_version": agentVersion,
		})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"detail": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"agent_version": agentVersion,
			"node_id":       a.cfg.NodeID,
		})
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"detail": "method not allowed"})
			return
		}
		writeJSON(w, http.StatusOK, a.snapshotStatus())
	})

	server := &http.Server{Handler: mux}
	a.log.Info("agent.admin", "socket.start", "Started unix socket admin API", map[string]any{
		"socket_path": socketPath,
	})

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		_ = listener.Close()
		_ = os.Remove(socketPath)
		a.log.Info("agent.admin", "socket.stop", "Stopped unix socket admin API", map[string]any{
			"socket_path": socketPath,
		})
	}()

	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			a.log.Error("agent.admin", "socket.error", "Unix socket admin API failed", map[string]any{
				"socket_path": socketPath,
				"error":       serveErr.Error(),
			})
		}
	}()

	return nil
}

func (l *Logger) log(severity int, levelName, category, event, msg string, fields map[string]any) {
	if severity < l.level {
		return
	}
	ts := time.Now().UTC().Format("2006-01-02 15:04:05.000")
	symbol := levelSymbol(levelName)
	renderFields := map[string]any{}
	for k, v := range fields {
		renderFields[k] = v
	}

	parts := []string{
		ts,
		fmt.Sprintf("%-8s", levelName),
		category,
	}

	if strings.TrimSpace(event) != "" {
		if event == "operation.step" {
			stepName := strings.TrimSpace(fmt.Sprintf("%v", renderFields["step"]))
			childName := strings.TrimSpace(fmt.Sprintf("%v", renderFields["child"]))
			delete(renderFields, "step")
			delete(renderFields, "child")
			delete(renderFields, "step_depth")
			if stepName != "" {
				if childName != "" {
					parts = append(parts, fmt.Sprintf("%s >> %s >> %s", symbol, stepName, childName))
				} else {
					parts = append(parts, fmt.Sprintf("%s >> %s", symbol, stepName))
				}
			} else {
				parts = append(parts, fmt.Sprintf("%s %s", symbol, event))
			}
		} else {
			parts = append(parts, fmt.Sprintf("%s %s", symbol, event))
		}
	} else if strings.TrimSpace(msg) != "" {
		parts = append(parts, fmt.Sprintf("%s %s", symbol, msg))
	}

	if strings.TrimSpace(msg) != "" {
		parts = append(parts, msg)
	}

	if len(renderFields) > 0 {
		keys := make([]string, 0, len(renderFields))
		for k := range renderFields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s: %v", k, renderFields[k]))
		}
	}

	line := strings.Join(parts, " | ") + "\n"
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = os.Stdout.WriteString(line)
	if l.file != nil {
		_, _ = l.file.WriteString(line)
	}
}

func parseLogLevel(level string) int {
	switch strings.ToUpper(strings.TrimSpace(level)) {
	case "DEBUG":
		return 10
	case "WARNING", "WARN":
		return 30
	case "ERROR":
		return 40
	case "CRITICAL":
		return 50
	default:
		return 20
	}
}

func levelSymbol(levelName string) string {
	switch strings.ToUpper(strings.TrimSpace(levelName)) {
	case "DEBUG":
		return "(?)"
	case "INFO":
		return "(*)"
	case "WARNING", "WARN":
		return "(!)"
	case "ERROR":
		return "(x)"
	case "CRITICAL":
		return "(X)"
	default:
		return "(?)"
	}
}

func (a *Agent) tick(ctx context.Context) error {
	start := time.Now()
	a.mu.RLock()
	activeIface := a.state.ActiveIface
	a.mu.RUnlock()
	a.log.Info("agent.loop", "tick.start", "Starting loop tick", map[string]any{
		"active_iface": activeIface,
	})

	statusPatch := map[string]any{
		"agent_runtime_enabled": true,
		"agent_version":         agentVersion,
		"agent_loop_at":         time.Now().UTC().Format(time.RFC3339Nano),
	}

	if a.cfg.EnableWireGuard {
		wgPatch := a.reconcileWireGuard(ctx)
		for k, v := range wgPatch {
			statusPatch[k] = v
		}
	} else {
		a.log.Info("agent.wireguard", "reconcile.skip", "WireGuard reconcile disabled", nil)
	}
	a.mu.Lock()
	a.lastStatusPatch = map[string]any{}
	for key, value := range statusPatch {
		a.lastStatusPatch[key] = value
	}
	a.mu.Unlock()

	if err := a.sendHeartbeat(ctx, statusPatch); err != nil {
		a.mu.Lock()
		a.lastTickAt = time.Now().UTC()
		a.lastTickDurationMs = time.Since(start).Milliseconds()
		a.lastTickError = err.Error()
		a.mu.Unlock()
		a.log.Error("agent.heartbeat", "publish.fail", "Heartbeat publish failed", map[string]any{
			"error": err.Error(),
		})
		return err
	}
	a.mu.Lock()
	a.lastTickAt = time.Now().UTC()
	a.lastTickDurationMs = time.Since(start).Milliseconds()
	a.lastTickError = ""
	activeIface = a.state.ActiveIface
	a.mu.Unlock()

	a.log.Info("agent.loop", "tick.complete", "Completed loop tick", map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
		"active_iface": activeIface,
	})
	return nil
}

func (a *Agent) reconcileWireGuard(ctx context.Context) map[string]any {
	primaryPeer, secondaryPeer := a.peerIntents()
	localAddress := normalizeAddress(a.cfg.WGLocalAddress)
	primaryPublicKey := ""
	secondaryPublicKey := ""

	if err := a.ensureWireGuardInterface(
		ctx,
		a.cfg.PrimaryIface,
		a.cfg.PrimaryListenPort,
		localAddress,
		primaryPeer,
	); err != nil {
		a.log.Warn("agent.wireguard", "interface.primary_error", "Failed to reconcile primary WireGuard interface", map[string]any{
			"iface": a.cfg.PrimaryIface,
			"error": err.Error(),
		})
	}
	if err := a.ensureWireGuardInterface(
		ctx,
		a.cfg.SecondaryIface,
		a.cfg.SecondaryListenPort,
		localAddress,
		secondaryPeer,
	); err != nil {
		a.log.Warn("agent.wireguard", "interface.secondary_error", "Failed to reconcile secondary WireGuard interface", map[string]any{
			"iface": a.cfg.SecondaryIface,
			"error": err.Error(),
		})
	}

	primaryPublicKey = a.wireGuardPublicKey(ctx, a.cfg.PrimaryIface)
	secondaryPublicKey = a.wireGuardPublicKey(ctx, a.cfg.SecondaryIface)

	primaryUp := a.interfaceUp(ctx, a.cfg.PrimaryIface)
	secondaryUp := a.interfaceUp(ctx, a.cfg.SecondaryIface)

	primaryHealthy := primaryUp
	secondaryHealthy := secondaryUp

	if primaryHealthy && strings.TrimSpace(a.cfg.PrimaryRouterIP) != "" {
		primaryHealthy = a.pingRouter(ctx, a.cfg.PrimaryIface, a.cfg.PrimaryRouterIP)
	}
	if secondaryHealthy && strings.TrimSpace(a.cfg.SecondaryRouterIP) != "" {
		secondaryHealthy = a.pingRouter(ctx, a.cfg.SecondaryIface, a.cfg.SecondaryRouterIP)
	}

	a.mu.Lock()
	if primaryHealthy {
		a.state.PrimaryFailures = 0
		a.state.PrimarySuccesses++
	} else {
		a.state.PrimaryFailures++
		a.state.PrimarySuccesses = 0
	}
	if secondaryHealthy {
		a.state.SecondaryFailures = 0
		a.state.SecondarySuccesses++
	} else {
		a.state.SecondaryFailures++
		a.state.SecondarySuccesses = 0
	}

	activeBefore := a.state.ActiveIface
	activeAfter := activeBefore
	failoverEvent := ""
	eventFields := map[string]any{}

	switch activeBefore {
	case a.cfg.PrimaryIface:
		if !primaryHealthy && secondaryHealthy && a.state.PrimaryFailures >= a.cfg.FailoverThreshold {
			activeAfter = a.cfg.SecondaryIface
			failoverEvent = "failover.engage"
			eventFields = map[string]any{
				"from":             a.cfg.PrimaryIface,
				"to":               a.cfg.SecondaryIface,
				"primary_failures": a.state.PrimaryFailures,
			}
		}
	case a.cfg.SecondaryIface:
		if !secondaryHealthy && primaryHealthy {
			activeAfter = a.cfg.PrimaryIface
			failoverEvent = "failover.recover"
			eventFields = map[string]any{
				"from": a.cfg.SecondaryIface,
				"to":   a.cfg.PrimaryIface,
			}
		} else if a.cfg.FailbackEnabled && primaryHealthy && a.state.PrimarySuccesses >= a.cfg.FailbackStableCount {
			activeAfter = a.cfg.PrimaryIface
			failoverEvent = "failback.engage"
			eventFields = map[string]any{
				"stable_count": a.state.PrimarySuccesses,
			}
		}
	default:
		activeAfter = a.cfg.PrimaryIface
	}

	a.state.ActiveIface = activeAfter
	primaryFailures := a.state.PrimaryFailures
	primarySuccesses := a.state.PrimarySuccesses
	secondaryFailures := a.state.SecondaryFailures
	secondarySuccesses := a.state.SecondarySuccesses
	a.mu.Unlock()

	if activeAfter != activeBefore {
		a.applyRouteMetrics(ctx, activeAfter)
		switch failoverEvent {
		case "failover.engage":
			a.log.Warn("agent.wireguard", failoverEvent, "Switched active route to secondary", eventFields)
		case "failover.recover":
			a.log.Warn("agent.wireguard", failoverEvent, "Primary route restored (secondary unhealthy)", eventFields)
		case "failback.engage":
			a.log.Info("agent.wireguard", failoverEvent, "Switched back to primary route", eventFields)
		}
	}
	a.applyRouteMetrics(ctx, activeAfter)

	failoverState := "primary"
	if activeAfter == a.cfg.SecondaryIface {
		failoverState = "failover_secondary"
	}

	patch := map[string]any{
		"wg_primary_tunnel":            upDown(primaryUp),
		"wg_secondary_tunnel":          upDown(secondaryUp),
		"wg_primary_health":            primaryHealthy,
		"wg_secondary_health":          secondaryHealthy,
		"wg_primary_router_reachable":  primaryHealthy,
		"wg_secondary_router_reachable": secondaryHealthy,
		"wg_active_route":              activeAfter,
		"wg_failover_state":            failoverState,
		"wg_primary_public_key":        primaryPublicKey,
		"wg_secondary_public_key":      secondaryPublicKey,
		"wg_public_key":                firstNonEmpty(primaryPublicKey, secondaryPublicKey),
		"wg_primary_peer_endpoint":     primaryPeer.endpoint,
		"wg_secondary_peer_endpoint":   secondaryPeer.endpoint,
		"wg_primary_peer_configured":   strings.TrimSpace(primaryPeer.publicKey) != "",
		"wg_secondary_peer_configured": strings.TrimSpace(secondaryPeer.publicKey) != "",
	}
	a.log.Info("agent.wireguard", "reconcile.status", "Reconciled WireGuard status", map[string]any{
		"primary_up":         primaryUp,
		"secondary_up":       secondaryUp,
		"primary_healthy":    primaryHealthy,
		"secondary_healthy":  secondaryHealthy,
		"active_iface":       activeAfter,
		"failover_state":     failoverState,
		"primary_failures":   primaryFailures,
		"primary_successes":  primarySuccesses,
		"secondary_failures": secondaryFailures,
		"secondary_successes": secondarySuccesses,
	})
	return patch
}

func normalizeAddress(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "/") {
		return trimmed
	}
	return trimmed + "/32"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func (a *Agent) peerIntents() (wgPeerIntent, wgPeerIntent) {
	allowed := strings.TrimSpace(a.cfg.PeerAllowedIPs)
	if allowed == "" {
		allowed = strings.TrimSpace(a.cfg.MeshCIDR)
	}
	primary := wgPeerIntent{
		publicKey:          strings.TrimSpace(a.cfg.PrimaryPeerPublicKey),
		endpoint:           strings.TrimSpace(a.cfg.PrimaryPeerEndpoint),
		allowedIPs:         allowed,
		persistentKeepalive: a.cfg.PersistentKeepaliveSeconds,
	}
	secondary := wgPeerIntent{
		publicKey:          strings.TrimSpace(a.cfg.SecondaryPeerPublicKey),
		endpoint:           strings.TrimSpace(a.cfg.SecondaryPeerEndpoint),
		allowedIPs:         allowed,
		persistentKeepalive: a.cfg.PersistentKeepaliveSeconds,
	}
	if primary.endpoint == "" && strings.TrimSpace(a.cfg.PrimaryRouterIP) != "" {
		primary.endpoint = fmt.Sprintf("%s:%d", strings.TrimSpace(a.cfg.PrimaryRouterIP), a.cfg.PeerPort)
	}
	if secondary.endpoint == "" && strings.TrimSpace(a.cfg.SecondaryRouterIP) != "" {
		secondary.endpoint = fmt.Sprintf("%s:%d", strings.TrimSpace(a.cfg.SecondaryRouterIP), a.cfg.PeerPort)
	}
	return primary, secondary
}

func (a *Agent) wireGuardKeyPath(iface string) string {
	dir := strings.TrimSpace(a.cfg.WGKeyDir)
	if dir == "" {
		dir = "data/wireguard"
	}
	_ = os.MkdirAll(dir, 0o700)
	return filepath.Join(dir, iface+".key")
}

func (a *Agent) ensureWireGuardKey(ctx context.Context, iface string) (string, error) {
	keyPath := a.wireGuardKeyPath(iface)
	info, err := os.Stat(keyPath)
	if err == nil && info.Size() > 0 {
		return keyPath, nil
	}

	code, out, errText := a.runCommand(ctx, "wireguard.key.generate", "wg", "genkey")
	if code != 0 || strings.TrimSpace(out) == "" {
		return "", fmt.Errorf("wg genkey failed: %s", firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code)))
	}
	key := strings.TrimSpace(out) + "\n"
	if writeErr := os.WriteFile(keyPath, []byte(key), 0o600); writeErr != nil {
		return "", writeErr
	}
	if chmodErr := os.Chmod(keyPath, 0o600); chmodErr != nil {
		return "", chmodErr
	}
	a.log.Info("agent.wireguard", "key.create", "Generated WireGuard private key", map[string]any{
		"iface":    iface,
		"key_path": keyPath,
	})
	return keyPath, nil
}

func (a *Agent) ensureWireGuardInterface(
	ctx context.Context,
	iface string,
	listenPort int,
	localAddress string,
	peer wgPeerIntent,
) error {
	if strings.TrimSpace(iface) == "" {
		return nil
	}

	if !a.interfaceUp(ctx, iface) {
		code, out, errText := a.runCommand(ctx, "wireguard.iface.create", "ip", "link", "add", "dev", iface, "type", "wireguard")
		if code != 0 && !strings.Contains(strings.ToLower(errText), "file exists") {
			return fmt.Errorf("create iface failed: %s", firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code)))
		}
	}

	keyPath, err := a.ensureWireGuardKey(ctx, iface)
	if err != nil {
		return err
	}

	wgArgs := []string{"set", iface, "private-key", keyPath}
	if listenPort > 0 {
		wgArgs = append(wgArgs, "listen-port", strconv.Itoa(listenPort))
	}
	code, out, errText := a.runCommand(ctx, "wireguard.iface.configure", "wg", wgArgs...)
	if code != 0 {
		return fmt.Errorf("configure iface failed: %s", firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code)))
	}

	if strings.TrimSpace(localAddress) != "" {
		code, out, errText = a.runCommand(ctx, "wireguard.iface.address", "ip", "-4", "address", "replace", localAddress, "dev", iface)
		if code != 0 {
			a.log.Warn("agent.wireguard", "interface.address_error", "Failed to apply interface address", map[string]any{
				"iface":   iface,
				"address": localAddress,
				"error":   firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code)),
			})
		}
	}

	code, out, errText = a.runCommand(ctx, "wireguard.iface.up", "ip", "link", "set", "up", "dev", iface)
	if code != 0 {
		return fmt.Errorf("bring iface up failed: %s", firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code)))
	}

	if err := a.syncWireGuardPeer(ctx, iface, peer); err != nil {
		return err
	}
	return nil
}

func (a *Agent) wireGuardPeers(ctx context.Context, iface string) []string {
	code, out, _ := a.runCommand(ctx, "wireguard.peers.list", "wg", "show", iface, "peers")
	if code != 0 {
		return []string{}
	}
	peers := []string{}
	for _, raw := range strings.Split(out, "\n") {
		value := strings.TrimSpace(raw)
		if value != "" {
			peers = append(peers, value)
		}
	}
	return peers
}

func (a *Agent) syncWireGuardPeer(ctx context.Context, iface string, peer wgPeerIntent) error {
	desiredPeer := strings.TrimSpace(peer.publicKey)
	existingPeers := a.wireGuardPeers(ctx, iface)
	for _, stale := range existingPeers {
		if desiredPeer != "" && stale == desiredPeer {
			continue
		}
		code, out, errText := a.runCommand(ctx, "wireguard.peer.remove", "wg", "set", iface, "peer", stale, "remove")
		if code != 0 {
			a.log.Warn("agent.wireguard", "peer.remove_error", "Failed to remove stale peer", map[string]any{
				"iface": iface,
				"peer":  stale,
				"error": firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code)),
			})
		}
	}

	if desiredPeer == "" {
		return nil
	}

	args := []string{"set", iface, "peer", desiredPeer}
	if strings.TrimSpace(peer.endpoint) != "" {
		args = append(args, "endpoint", strings.TrimSpace(peer.endpoint))
	}
	if strings.TrimSpace(peer.allowedIPs) != "" {
		args = append(args, "allowed-ips", strings.TrimSpace(peer.allowedIPs))
	}
	if peer.persistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", strconv.Itoa(peer.persistentKeepalive))
	}
	code, out, errText := a.runCommand(ctx, "wireguard.peer.configure", "wg", args...)
	if code != 0 {
		return fmt.Errorf("configure peer failed: %s", firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code)))
	}
	return nil
}

func (a *Agent) wireGuardPublicKey(ctx context.Context, iface string) string {
	code, out, _ := a.runCommand(ctx, "wireguard.key.public", "wg", "show", iface, "public-key")
	if code != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

func (a *Agent) applyRouteMetrics(ctx context.Context, activeIface string) {
	if strings.TrimSpace(a.cfg.MeshCIDR) == "" {
		return
	}
	primaryMetric := a.cfg.PrimaryMetric
	secondaryMetric := a.cfg.SecondaryMetric
	if activeIface == a.cfg.SecondaryIface {
		primaryMetric, secondaryMetric = secondaryMetric, primaryMetric
	}

	a.runCommand(ctx, "wireguard.route.primary", "ip", "route", "replace", a.cfg.MeshCIDR, "dev", a.cfg.PrimaryIface, "metric", strconv.Itoa(primaryMetric))
	a.runCommand(ctx, "wireguard.route.secondary", "ip", "route", "replace", a.cfg.MeshCIDR, "dev", a.cfg.SecondaryIface, "metric", strconv.Itoa(secondaryMetric))
}

func (a *Agent) interfaceUp(ctx context.Context, iface string) bool {
	code, _, _ := a.runCommand(ctx, "wireguard.iface.check", "ip", "link", "show", iface)
	return code == 0
}

func (a *Agent) pingRouter(ctx context.Context, iface, ip string) bool {
	timeout := strconv.Itoa(max(1, a.cfg.PingTimeoutSeconds))
	code, _, _ := a.runCommand(ctx, "wireguard.router.ping", "ping", "-I", iface, "-c", "1", "-W", timeout, ip)
	return code == 0
}

func (a *Agent) runCommand(ctx context.Context, event string, name string, args ...string) (int, string, string) {
	cmdCtx, cancel := context.WithTimeout(ctx, time.Duration(a.cfg.CommandTimeoutSeconds)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errText := strings.TrimSpace(stderr.String())
	if err != nil {
		exitCode := 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		a.log.Debug("agent.command", event, "Command failed", map[string]any{
			"cmd":       strings.Join(append([]string{name}, args...), " "),
			"exit_code": exitCode,
			"stderr":    trimForLog(errText, 300),
			"stdout":    trimForLog(out, 300),
		})
		return exitCode, out, errText
	}
	a.log.Debug("agent.command", event, "Command succeeded", map[string]any{
		"cmd": strings.Join(append([]string{name}, args...), " "),
	})
	return 0, out, errText
}

func (a *Agent) sendHeartbeat(ctx context.Context, statusPatch map[string]any) error {
	keyPath := filepath.Join(a.cfg.IdentityDir, a.cfg.NodeID, "node.key")
	leasePath := filepath.Join(a.cfg.IdentityDir, a.cfg.NodeID, "lease.token")

	keyRaw, err := os.ReadFile(keyPath)
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return fmt.Errorf("read key: %w", err)
	}
	leaseTokenRaw, err := os.ReadFile(leasePath)
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return fmt.Errorf("read lease token: %w", err)
	}
	leaseToken := strings.TrimSpace(string(leaseTokenRaw))
	if leaseToken == "" {
		a.mu.Lock()
		a.lastHeartbeatError = "lease token is empty"
		a.mu.Unlock()
		return errors.New("lease token is empty")
	}

	privateKey, err := parsePrivateKey(keyRaw)
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return fmt.Errorf("parse key: %w", err)
	}

	signedAt := time.Now().Unix()
	message, err := heartbeatSigningMessage(a.cfg.NodeID, leaseToken, signedAt, a.cfg.HeartbeatTTLSeconds, statusPatch)
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return fmt.Errorf("build message: %w", err)
	}
	signature, err := signMessage(privateKey, message)
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return fmt.Errorf("sign message: %w", err)
	}

	bodyMap := map[string]any{
		"node_id":     a.cfg.NodeID,
		"lease_token": leaseToken,
		"ttl_seconds": a.cfg.HeartbeatTTLSeconds,
		"status_patch": statusPatch,
		"signed_at":   signedAt,
		"signature":   signature,
	}
	body, err := json.Marshal(bodyMap)
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return err
	}

	url := a.cfg.APIServerURL + "/cluster/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		a.mu.Lock()
		a.lastHeartbeatError = err.Error()
		a.mu.Unlock()
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	latencyMs := time.Since(start).Milliseconds()
	if resp.StatusCode >= 300 {
		a.mu.Lock()
		a.lastHeartbeatError = fmt.Sprintf("heartbeat http %d", resp.StatusCode)
		a.mu.Unlock()
		return fmt.Errorf("heartbeat http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	a.mu.Lock()
	a.lastHeartbeatAt = time.Now().UTC()
	a.lastHeartbeatError = ""
	a.mu.Unlock()

	a.log.Info("agent.heartbeat", "publish.ok", "Published signed heartbeat", map[string]any{
		"node_id":     a.cfg.NodeID,
		"status_code": resp.StatusCode,
		"latency_ms":  latencyMs,
		"active_route": statusPatch["wg_active_route"],
		"failover_state": statusPatch["wg_failover_state"],
	})
	return nil
}

func parsePrivateKey(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil {
			return parsed, nil
		}
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

func signMessage(privateKey crypto.PrivateKey, message []byte) (string, error) {
	sum := sha256.Sum256(message)
	switch key := privateKey.(type) {
	case *ecdsa.PrivateKey:
		sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	case *rsa.PrivateKey:
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(sig), nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

func heartbeatSigningMessage(nodeID, leaseToken string, signedAt int64, ttlSeconds int, statusPatch map[string]any) ([]byte, error) {
	statusJSON, err := json.Marshal(statusPatch)
	if err != nil {
		return nil, err
	}
	raw := fmt.Sprintf("%s\n%s\n%d\n%d\n%s", nodeID, leaseToken, signedAt, ttlSeconds, string(statusJSON))
	return []byte(raw), nil
}

func trimForLog(value string, max int) string {
	if len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}

func upDown(value bool) string {
	if value {
		return "up"
	}
	return "down"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
