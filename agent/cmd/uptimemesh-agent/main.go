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
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
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
	NodeName                  string
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
	SWIMEnabled               bool
	SWIMPort                  int
	SWIMProbeTimeoutMs        int
	SWIMSuspectThreshold      int
	SWIMDeadThreshold         int
	SWIMCooldownSeconds       int
	InternalCDNDir            string
	BackendListenPort         int
	ProxyListenPort           int
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
	swimIncarnation    int64
	swimState          string
	swimPeers          map[string]*SwimPeerState
	swimPending        map[string]chan swimMessage
	swimConn           *net.UDPConn
	internalCDNVersion string
	internalCDNHash    string
	assignedRoles      []string
	backendTargets     []string
	lastLoadSample     *loadSnapshot
	loadScores         map[string]float64
	loadScoresComputed time.Time
}

type wgPeerIntent struct {
	publicKey          string
	endpoint           string
	allowedIPs         string
	persistentKeepalive int
}

type swimMessage struct {
	Type        string                 `json:"type"`
	From        string                 `json:"from"`
	Incarnation int64                  `json:"incarnation"`
	State       string                 `json:"state"`
	Flags       map[string]any         `json:"flags,omitempty"`
	Nonce       string                 `json:"nonce,omitempty"`
	Peers       map[string]map[string]any `json:"peers,omitempty"`
}

type SwimPeerState struct {
	NodeID        string
	MeshIP        string
	State         string
	Incarnation   int64
	LastSeen      time.Time
	Failures      int
	Suspect       bool
	CooldownUntil time.Time
	Flags         map[string]any
}

type loadSnapshot struct {
	takenAt                 time.Time
	cpuIdle                 uint64
	cpuTotal                uint64
	runQPerCore             float64
	throttleUsageUS         uint64
	throttleThrottledUS     uint64
	memTotalKB              uint64
	memAvailableKB          uint64
	swapTotalKB             uint64
	swapFreeKB              uint64
	majorFaults             uint64
	diskUsedPct             float64
	diskBusyMS              uint64
	diskOps                 uint64
	networkIface            string
	networkRxBytes          uint64
	networkTxBytes          uint64
	networkRxPackets        uint64
	networkTxPackets        uint64
	networkRxDropErrPackets uint64
	networkTxDropErrPackets uint64
	networkCapacityBps      float64
	rttMs                   float64
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
		swimIncarnation: time.Now().UnixNano(),
		swimState:       "healthy",
		swimPeers:       map[string]*SwimPeerState{},
		swimPending:     map[string]chan swimMessage{},
		assignedRoles:   []string{},
		backendTargets:  []string{},
		loadScores:      map[string]float64{},
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
	if cfg.SWIMEnabled {
		if err := agent.startSWIM(ctx); err != nil {
			logger.Error("agent.swim", "socket.start", "Failed to start SWIM UDP socket", map[string]any{
				"port":  cfg.SWIMPort,
				"error": err.Error(),
			})
			os.Exit(1)
		}
	} else {
		logger.Info("agent.swim", "socket.skip", "SWIM gossip is disabled", map[string]any{
			"port": cfg.SWIMPort,
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
		NodeName:                 get("RUNTIME_NODE_NAME", ""),
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
		SWIMEnabled:              parseBool("RUNTIME_SWIM_ENABLE", true),
		SWIMPort:                 parseInt("RUNTIME_SWIM_PORT", 7946),
		SWIMProbeTimeoutMs:       parseInt("RUNTIME_SWIM_PROBE_TIMEOUT_MS", 500),
		SWIMSuspectThreshold:     parseInt("RUNTIME_SWIM_SUSPECT_THRESHOLD", 2),
		SWIMDeadThreshold:        parseInt("RUNTIME_SWIM_DEAD_THRESHOLD", 4),
		SWIMCooldownSeconds:      parseInt("RUNTIME_SWIM_COOLDOWN_SECONDS", 30),
		InternalCDNDir:           get("RUNTIME_INTERNAL_CDN_DIR", "data/internal-cdn"),
		BackendListenPort:        parseInt("RUNTIME_BACKEND_LISTEN_PORT", 8081),
		ProxyListenPort:          parseInt("RUNTIME_PROXY_LISTEN_PORT", 8080),
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
	if cfg.SWIMPort < 1 || cfg.SWIMPort > 65535 {
		cfg.SWIMPort = 7946
	}
	if cfg.SWIMProbeTimeoutMs < 50 {
		cfg.SWIMProbeTimeoutMs = 500
	}
	if cfg.SWIMSuspectThreshold < 1 {
		cfg.SWIMSuspectThreshold = 2
	}
	if cfg.SWIMDeadThreshold < cfg.SWIMSuspectThreshold+1 {
		cfg.SWIMDeadThreshold = cfg.SWIMSuspectThreshold + 1
	}
	if cfg.SWIMCooldownSeconds < 0 {
		cfg.SWIMCooldownSeconds = 30
	}
	if cfg.BackendListenPort < 1 || cfg.BackendListenPort > 65535 {
		cfg.BackendListenPort = 8081
	}
	if cfg.ProxyListenPort < 1 || cfg.ProxyListenPort > 65535 {
		cfg.ProxyListenPort = 8080
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
	swimPeerCount := len(a.swimPeers)
	roles := make([]string, len(a.assignedRoles))
	copy(roles, a.assignedRoles)
	backendTargets := make([]string, len(a.backendTargets))
	copy(backendTargets, a.backendTargets)
	loadScores := map[string]float64{}
	for key, value := range a.loadScores {
		loadScores[key] = value
	}

	return map[string]any{
		"node_id":                a.cfg.NodeID,
		"node_name":              a.cfg.NodeName,
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
		"swim_enabled":           a.cfg.SWIMEnabled,
		"swim_state":             a.swimState,
		"swim_incarnation":       a.swimIncarnation,
		"swim_peer_count":        swimPeerCount,
		"internal_cdn_version":   a.internalCDNVersion,
		"internal_cdn_hash":      a.internalCDNHash,
		"assigned_roles":         roles,
		"backend_targets":        backendTargets,
		"backend_listen_port":    a.cfg.BackendListenPort,
		"proxy_listen_port":      a.cfg.ProxyListenPort,
		"load_scores":            loadScores,
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

func (a *Agent) readLeaseToken() (string, error) {
	leasePath := filepath.Join(a.cfg.IdentityDir, a.cfg.NodeID, "lease.token")
	raw, err := os.ReadFile(leasePath)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("lease token is empty")
	}
	return token, nil
}

func (a *Agent) swimBindAddress() string {
	local := strings.TrimSpace(a.cfg.WGLocalAddress)
	if local == "" {
		return fmt.Sprintf("0.0.0.0:%d", a.cfg.SWIMPort)
	}
	ip := local
	if strings.Contains(ip, "/") {
		ip = strings.SplitN(ip, "/", 2)[0]
	}
	if strings.TrimSpace(ip) == "" {
		ip = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", ip, a.cfg.SWIMPort)
}

func (a *Agent) startSWIM(ctx context.Context) error {
	addr := a.swimBindAddress()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.swimConn = conn
	a.mu.Unlock()

	a.log.Info("agent.swim", "socket.start", "Started SWIM UDP listener", map[string]any{
		"bind": addr,
	})

	go func() {
		<-ctx.Done()
		_ = conn.Close()
		a.log.Info("agent.swim", "socket.stop", "Stopped SWIM UDP listener", map[string]any{
			"bind": addr,
		})
	}()

	go a.swimReadLoop(conn)
	return nil
}

func (a *Agent) swimReadLoop(conn *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				a.log.Warn("agent.swim", "socket.read_error", "Failed reading SWIM UDP packet", map[string]any{
					"error": err.Error(),
				})
			}
			return
		}
		var msg swimMessage
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			a.log.Debug("agent.swim", "packet.decode_error", "Ignored invalid SWIM packet", map[string]any{
				"remote": remote.String(),
				"error":  err.Error(),
			})
			continue
		}
		a.handleSWIMMessage(remote, msg)
	}
}

func (a *Agent) handleSWIMMessage(remote *net.UDPAddr, msg swimMessage) {
	if strings.TrimSpace(msg.From) != "" && msg.From != a.cfg.NodeID {
		a.mu.Lock()
		peer := a.swimPeers[msg.From]
		if peer == nil {
			peer = &SwimPeerState{
				NodeID: msg.From,
				State:  "healthy",
				Flags:  map[string]any{},
			}
			a.swimPeers[msg.From] = peer
		}
		peer.Incarnation = msg.Incarnation
		peer.LastSeen = time.Now().UTC()
		if remote != nil {
			peer.MeshIP = remote.IP.String()
		}
		if msg.State != "" {
			peer.State = strings.ToLower(strings.TrimSpace(msg.State))
		}
		if msg.Flags != nil {
			peer.Flags = msg.Flags
		}
		peer.Failures = 0
		peer.Suspect = false
		a.mu.Unlock()
	}

	switch msg.Type {
	case "ping":
		ack := swimMessage{
			Type:        "ack",
			From:        a.cfg.NodeID,
			Incarnation: a.swimIncarnation,
			State:       a.swimState,
			Nonce:       msg.Nonce,
			Flags:       a.swimLoadFlags(),
		}
		a.sendSWIMMessage(remote, ack)
	case "ack":
		if strings.TrimSpace(msg.Nonce) == "" {
			return
		}
		a.mu.Lock()
		ch := a.swimPending[msg.Nonce]
		delete(a.swimPending, msg.Nonce)
		a.mu.Unlock()
		if ch != nil {
			select {
			case ch <- msg:
			default:
			}
		}
	}
}

func (a *Agent) sendSWIMMessage(remote *net.UDPAddr, msg swimMessage) bool {
	if remote == nil {
		return false
	}
	a.mu.RLock()
	conn := a.swimConn
	a.mu.RUnlock()
	if conn == nil {
		return false
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return false
	}
	_, err = conn.WriteToUDP(raw, remote)
	return err == nil
}

func (a *Agent) pingPeerSWIM(peerNodeID string, peerIP string) bool {
	ip := strings.TrimSpace(peerIP)
	if ip == "" {
		return false
	}
	remote, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", ip, a.cfg.SWIMPort))
	if err != nil {
		return false
	}
	nonce := fmt.Sprintf("%s-%d", a.cfg.NodeID, time.Now().UnixNano())
	ch := make(chan swimMessage, 1)
	a.mu.Lock()
	a.swimPending[nonce] = ch
	a.mu.Unlock()
	ok := a.sendSWIMMessage(remote, swimMessage{
		Type:        "ping",
		From:        a.cfg.NodeID,
		Incarnation: a.swimIncarnation,
		State:       a.swimState,
		Nonce:       nonce,
		Flags:       a.swimLoadFlags(),
	})
	if !ok {
		a.mu.Lock()
		delete(a.swimPending, nonce)
		a.mu.Unlock()
		return false
	}
	timeout := time.Duration(a.cfg.SWIMProbeTimeoutMs) * time.Millisecond
	select {
	case <-time.After(timeout):
		a.mu.Lock()
		delete(a.swimPending, nonce)
		a.mu.Unlock()
		return false
	case ack := <-ch:
		return strings.TrimSpace(ack.From) == peerNodeID || strings.TrimSpace(ack.From) != ""
	}
}

func (a *Agent) fetchClusterPeers(ctx context.Context, leaseToken string) ([]map[string]any, error) {
	u := fmt.Sprintf(
		"%s/cluster/peers?node_id=%s&lease_token=%s",
		a.cfg.APIServerURL,
		url.QueryEscape(a.cfg.NodeID),
		url.QueryEscape(leaseToken),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("peers http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func (a *Agent) reconcileSWIM(ctx context.Context) map[string]any {
	patch := map[string]any{
		"swim_enabled": true,
	}
	leaseToken, err := a.readLeaseToken()
	if err != nil {
		a.log.Warn("agent.swim", "lease.read_error", "Failed to read lease token for SWIM", map[string]any{
			"error": err.Error(),
		})
		patch["swim_state"] = "degraded"
		return patch
	}

	peersRaw, err := a.fetchClusterPeers(ctx, leaseToken)
	if err != nil {
		a.log.Warn("agent.swim", "peer.fetch_error", "Failed to fetch peers for SWIM", map[string]any{
			"error": err.Error(),
		})
		patch["swim_state"] = "degraded"
		return patch
	}

	now := time.Now().UTC()
	candidates := make([]*SwimPeerState, 0, len(peersRaw))
	a.mu.Lock()
	for _, row := range peersRaw {
		nodeID := strings.TrimSpace(fmt.Sprintf("%v", row["node_id"]))
		if nodeID == "" || nodeID == a.cfg.NodeID {
			continue
		}
		meshIP := strings.TrimSpace(fmt.Sprintf("%v", row["mesh_ip"]))
		peer := a.swimPeers[nodeID]
		if peer == nil {
			peer = &SwimPeerState{
				NodeID: nodeID,
				State:  "degraded",
				Flags:  map[string]any{},
			}
			a.swimPeers[nodeID] = peer
		}
		if meshIP != "" {
			peer.MeshIP = meshIP
		}
		candidates = append(candidates, peer)
	}
	a.mu.Unlock()

	probed := ""
	if len(candidates) > 0 {
		index := int(now.UnixNano() % int64(len(candidates)))
		target := candidates[index]
		probed = target.NodeID
		ok := a.pingPeerSWIM(target.NodeID, target.MeshIP)
		a.mu.Lock()
		peer := a.swimPeers[target.NodeID]
		if peer != nil {
			if ok {
				peer.State = "healthy"
				peer.Failures = 0
				peer.Suspect = false
				peer.LastSeen = now
			} else {
				peer.Failures++
				if peer.Failures >= a.cfg.SWIMDeadThreshold {
					peer.State = "dead"
					peer.Suspect = false
					peer.CooldownUntil = now.Add(time.Duration(a.cfg.SWIMCooldownSeconds) * time.Second)
				} else if peer.Failures >= a.cfg.SWIMSuspectThreshold {
					peer.Suspect = true
					peer.State = "degraded"
				} else {
					peer.State = "degraded"
				}
			}
		}
		a.mu.Unlock()
	}

	peerStates := map[string]map[string]any{}
	healthy := 0
	degraded := 0
	dead := 0
	a.mu.Lock()
	for nodeID, peer := range a.swimPeers {
		state := strings.ToLower(strings.TrimSpace(peer.State))
		if state == "" {
			state = "unknown"
		}
		if state == "dead" && !peer.CooldownUntil.IsZero() && now.After(peer.CooldownUntil) {
			state = "degraded"
			peer.State = state
		}
		peerStates[nodeID] = map[string]any{
			"state":       state,
			"incarnation": peer.Incarnation,
			"failures":    peer.Failures,
			"last_seen":   peer.LastSeen.UTC().Format(time.RFC3339Nano),
		}
		switch state {
		case "healthy":
			healthy++
		case "dead":
			dead++
		default:
			degraded++
		}
	}
	a.swimIncarnation++
	localState := "healthy"
	totalLoad := a.loadScores["total"]
	lastRoleRuntimeState := strings.TrimSpace(fmt.Sprintf("%v", a.lastStatusPatch["role_runtime_state"]))
	lastCDNState := strings.TrimSpace(fmt.Sprintf("%v", a.lastStatusPatch["internal_cdn_state"]))
	criticalError := strings.TrimSpace(a.lastHeartbeatError) != "" ||
		strings.TrimSpace(a.lastTickError) != "" ||
		strings.EqualFold(lastRoleRuntimeState, "degraded") ||
		strings.EqualFold(lastCDNState, "degraded")
	if criticalError || totalLoad >= 75 {
		localState = "degraded"
	}
	a.swimState = localState
	localIncarnation := a.swimIncarnation
	a.mu.Unlock()

	patch["swim_state"] = localState
	patch["swim_incarnation"] = localIncarnation
	patch["swim_probe_target"] = probed
	patch["swim_peer_count"] = len(peerStates)
	patch["swim_healthy_peers"] = healthy
	patch["swim_degraded_peers"] = degraded
	patch["swim_dead_peers"] = dead
	patch["swim_peers"] = peerStates

	a.reportSWIM(ctx, leaseToken, localIncarnation, localState, peerStates)
	return patch
}

func (a *Agent) reportSWIM(
	ctx context.Context,
	leaseToken string,
	incarnation int64,
	state string,
	peers map[string]map[string]any,
) {
	flags := a.swimLoadFlags()
	payload := map[string]any{
		"node_id":     a.cfg.NodeID,
		"lease_token": leaseToken,
		"incarnation": incarnation,
		"state":       state,
		"flags":       flags,
		"peers":       peers,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	u := a.cfg.APIServerURL + "/cluster/swim/report"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		a.log.Warn("agent.swim", "report.error", "Failed to publish SWIM report", map[string]any{
			"error": err.Error(),
		})
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		bodyText, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		a.log.Warn("agent.swim", "report.error", "SWIM report rejected by API", map[string]any{
			"status_code": resp.StatusCode,
			"body":        strings.TrimSpace(string(bodyText)),
		})
		return
	}
}

func (a *Agent) syncInternalCDN(ctx context.Context) map[string]any {
	patch := map[string]any{}
	leaseToken, err := a.readLeaseToken()
	if err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = err.Error()
		return patch
	}
	u := fmt.Sprintf(
		"%s/cluster/content/active?node_id=%s&lease_token=%s",
		a.cfg.APIServerURL,
		url.QueryEscape(a.cfg.NodeID),
		url.QueryEscape(leaseToken),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = err.Error()
		return patch
	}
	resp, err := a.client.Do(req)
	if err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = err.Error()
		return patch
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = fmt.Sprintf("http_%d:%s", resp.StatusCode, strings.TrimSpace(string(body)))
		return patch
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = err.Error()
		return patch
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = err.Error()
		return patch
	}
	version := strings.TrimSpace(fmt.Sprintf("%v", payload["version"]))
	hashSHA := strings.TrimSpace(fmt.Sprintf("%v", payload["hash_sha256"]))
	bodyBase64 := strings.TrimSpace(fmt.Sprintf("%v", payload["body_base64"]))
	raw, err := base64.StdEncoding.DecodeString(bodyBase64)
	if err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = "invalid_base64_content"
		return patch
	}
	sum := sha256.Sum256(raw)
	computed := fmt.Sprintf("%x", sum[:])
	if hashSHA != "" && hashSHA != computed {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = "hash_mismatch"
		return patch
	}
	targetDir := filepath.Join(strings.TrimSpace(a.cfg.InternalCDNDir), "active")
	if targetDir == "" {
		targetDir = "data/internal-cdn/active"
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = err.Error()
		return patch
	}
	indexPath := filepath.Join(targetDir, "index.html")
	if err := os.WriteFile(indexPath, raw, 0o644); err != nil {
		patch["internal_cdn_state"] = "degraded"
		patch["internal_cdn_error"] = err.Error()
		return patch
	}

	a.mu.Lock()
	a.internalCDNVersion = version
	a.internalCDNHash = computed
	a.mu.Unlock()

	patch["internal_cdn_state"] = "healthy"
	patch["internal_cdn_version"] = version
	patch["internal_cdn_hash"] = computed
	patch["internal_cdn_size_bytes"] = len(raw)
	patch["internal_cdn_path"] = indexPath
	return patch
}

func clamp01(value float64) float64 {
	if value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func normalizeRange(value float64, good float64, bad float64) float64 {
	if bad <= good {
		return 0
	}
	return clamp01((value - good) / (bad - good))
}

func round1(value float64) float64 {
	if value < 0 {
		return 0
	}
	return float64(int(value*10+0.5)) / 10
}

func max4(a, b, c, d float64) float64 {
	maxValue := a
	for _, item := range []float64{b, c, d} {
		if item > maxValue {
			maxValue = item
		}
	}
	return maxValue
}

func readCPUCounters() (uint64, uint64, error) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	lines := strings.Split(string(raw), "\n")
	if len(lines) == 0 {
		return 0, 0, errors.New("missing /proc/stat cpu line")
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, errors.New("invalid /proc/stat cpu line")
	}
	values := make([]uint64, 0, len(fields)-1)
	for _, item := range fields[1:] {
		value, parseErr := strconv.ParseUint(item, 10, 64)
		if parseErr != nil {
			return 0, 0, parseErr
		}
		values = append(values, value)
	}
	var total uint64
	for _, item := range values {
		total += item
	}
	idle := values[3]
	if len(values) > 4 {
		// Treat iowait as idle time for utilization purposes.
		idle += values[4]
	}
	return idle, total, nil
}

func readRunQPerCore() float64 {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return 0
	}
	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	cores := runtime.NumCPU()
	if cores < 1 {
		cores = 1
	}
	return load1 / float64(cores)
}

func readCgroupCPUStats() (uint64, uint64) {
	usageUS := uint64(0)
	throttledUS := uint64(0)

	parseCPUStat := func(path string) {
		raw, err := os.ReadFile(path)
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) != 2 {
				continue
			}
			value, parseErr := strconv.ParseUint(fields[1], 10, 64)
			if parseErr != nil {
				continue
			}
			switch fields[0] {
			case "usage_usec":
				usageUS = value
			case "throttled_usec":
				throttledUS = value
			case "throttled_time":
				// cgroup v1 is usually nanoseconds.
				throttledUS = value / 1000
			}
		}
	}

	parseCPUStat("/sys/fs/cgroup/cpu.stat")
	if usageUS == 0 {
		raw, err := os.ReadFile("/sys/fs/cgroup/cpuacct.usage")
		if err == nil {
			if value, parseErr := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64); parseErr == nil {
				usageUS = value / 1000
			}
		}
	}
	if usageUS == 0 {
		parseCPUStat("/sys/fs/cgroup/cpu/cpu.stat")
	}
	return usageUS, throttledUS
}

func readMemInfo() map[string]uint64 {
	out := map[string]uint64{}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) == 0 {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[0], 10, 64)
		if parseErr != nil {
			continue
		}
		out[key] = value
	}
	return out
}

func readMajorFaults() uint64 {
	raw, err := os.ReadFile("/proc/vmstat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 {
			continue
		}
		if fields[0] != "pgmajfault" {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 10, 64)
		if parseErr != nil {
			return 0
		}
		return value
	}
	return 0
}

func readDiskUsedPercent() float64 {
	stat := syscall.Statfs_t{}
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0
	}
	if stat.Blocks == 0 {
		return 0
	}
	used := stat.Blocks - stat.Bavail
	return (float64(used) / float64(stat.Blocks)) * 100
}

func normalizeBlockDeviceName(source string) string {
	name := strings.TrimSpace(source)
	if !strings.HasPrefix(name, "/dev/") {
		return ""
	}
	name = strings.TrimPrefix(name, "/dev/")
	if strings.HasPrefix(name, "mapper/") {
		return ""
	}
	if strings.Contains(name, "nvme") && strings.Contains(name, "p") {
		if idx := strings.LastIndex(name, "p"); idx > 0 {
			trimmed := name[idx+1:]
			allDigits := trimmed != ""
			for _, r := range trimmed {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				return name[:idx]
			}
		}
	}
	for len(name) > 0 {
		last := name[len(name)-1]
		if last < '0' || last > '9' {
			break
		}
		name = name[:len(name)-1]
	}
	return name
}

func readRootBlockDevice() string {
	raw, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		if fields[1] != "/" {
			continue
		}
		return normalizeBlockDeviceName(fields[0])
	}
	return ""
}

func readDiskCounters(preferredDevice string) (uint64, uint64, string) {
	raw, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0, ""
	}
	type row struct {
		name   string
		ops    uint64
		busyMS uint64
	}
	candidates := []row{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 14 {
			continue
		}
		name := fields[2]
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") {
			continue
		}
		readOps, errA := strconv.ParseUint(fields[3], 10, 64)
		writeOps, errB := strconv.ParseUint(fields[7], 10, 64)
		busyMS, errC := strconv.ParseUint(fields[12], 10, 64)
		if errA != nil || errB != nil || errC != nil {
			continue
		}
		candidates = append(candidates, row{name: name, ops: readOps + writeOps, busyMS: busyMS})
	}
	if len(candidates) == 0 {
		return 0, 0, ""
	}
	if preferredDevice != "" {
		for _, item := range candidates {
			if item.name == preferredDevice {
				return item.busyMS, item.ops, item.name
			}
		}
	}
	return candidates[0].busyMS, candidates[0].ops, candidates[0].name
}

func defaultRouteInterface() string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0]
		}
	}
	return ""
}

func readNetworkCounters(iface string) (uint64, uint64, uint64, uint64, uint64, uint64, string) {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, 0, 0, 0, 0, ""
	}
	parseLine := func(line string) (uint64, uint64, uint64, uint64, uint64, uint64, string) {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return 0, 0, 0, 0, 0, 0, ""
		}
		name := strings.TrimSpace(parts[0])
		fields := strings.Fields(strings.TrimSpace(parts[1]))
		if len(fields) < 16 {
			return 0, 0, 0, 0, 0, 0, ""
		}
		rxBytes, errA := strconv.ParseUint(fields[0], 10, 64)
		rxPackets, errB := strconv.ParseUint(fields[1], 10, 64)
		rxErr, errC := strconv.ParseUint(fields[2], 10, 64)
		rxDrop, errD := strconv.ParseUint(fields[3], 10, 64)
		txBytes, errE := strconv.ParseUint(fields[8], 10, 64)
		txPackets, errF := strconv.ParseUint(fields[9], 10, 64)
		txErr, errG := strconv.ParseUint(fields[10], 10, 64)
		txDrop, errH := strconv.ParseUint(fields[11], 10, 64)
		if errA != nil || errB != nil || errC != nil || errD != nil || errE != nil || errF != nil || errG != nil || errH != nil {
			return 0, 0, 0, 0, 0, 0, ""
		}
		return rxBytes, txBytes, rxPackets, txPackets, rxErr + rxDrop, txErr + txDrop, name
	}

	fallback := ""
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		rxBytes, txBytes, rxPackets, txPackets, rxDropErr, txDropErr, name := parseLine(line)
		if name == "" || strings.HasPrefix(name, "lo") {
			continue
		}
		if iface != "" && name == iface {
			return rxBytes, txBytes, rxPackets, txPackets, rxDropErr, txDropErr, name
		}
		if fallback == "" {
			fallback = name
		}
	}
	if fallback == "" {
		return 0, 0, 0, 0, 0, 0, ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		rxBytes, txBytes, rxPackets, txPackets, rxDropErr, txDropErr, name := parseLine(line)
		if name == fallback {
			return rxBytes, txBytes, rxPackets, txPackets, rxDropErr, txDropErr, name
		}
	}
	return 0, 0, 0, 0, 0, 0, ""
}

func readInterfaceCapacityBps(iface string) float64 {
	if strings.TrimSpace(iface) == "" {
		return 1_000_000_000
	}
	path := filepath.Join("/sys/class/net", iface, "speed")
	raw, err := os.ReadFile(path)
	if err != nil {
		return 1_000_000_000
	}
	speedMbps, parseErr := strconv.ParseFloat(strings.TrimSpace(string(raw)), 64)
	if parseErr != nil || speedMbps <= 0 {
		return 1_000_000_000
	}
	return speedMbps * 1_000_000
}

func measureAPIConnectRTT(apiBaseURL string) float64 {
	parsed, err := url.Parse(strings.TrimSpace(apiBaseURL))
	if err != nil {
		return 0
	}
	host := parsed.Hostname()
	if host == "" {
		return 0
	}
	if host == "127.0.0.1" || host == "localhost" {
		return 0
	}
	port := parsed.Port()
	if port == "" {
		if strings.EqualFold(parsed.Scheme, "https") {
			port = "443"
		} else {
			port = "80"
		}
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 500*time.Millisecond)
	if err != nil {
		return 250
	}
	_ = conn.Close()
	return float64(time.Since(start).Milliseconds())
}

func (a *Agent) collectLoadSnapshot() *loadSnapshot {
	now := time.Now().UTC()
	idle, total, _ := readCPUCounters()
	runQPerCore := readRunQPerCore()
	throttleUsageUS, throttleThrottledUS := readCgroupCPUStats()
	mem := readMemInfo()
	majorFaults := readMajorFaults()
	diskUsedPct := readDiskUsedPercent()
	rootDevice := readRootBlockDevice()
	diskBusyMS, diskOps, _ := readDiskCounters(rootDevice)

	iface := defaultRouteInterface()
	rxBytes, txBytes, rxPackets, txPackets, rxDropErr, txDropErr, resolvedIface := readNetworkCounters(iface)
	if resolvedIface != "" {
		iface = resolvedIface
	}
	networkCapacityBps := readInterfaceCapacityBps(iface)
	rttMs := measureAPIConnectRTT(a.cfg.APIServerURL)

	return &loadSnapshot{
		takenAt:                 now,
		cpuIdle:                 idle,
		cpuTotal:                total,
		runQPerCore:             runQPerCore,
		throttleUsageUS:         throttleUsageUS,
		throttleThrottledUS:     throttleThrottledUS,
		memTotalKB:              mem["MemTotal"],
		memAvailableKB:          mem["MemAvailable"],
		swapTotalKB:             mem["SwapTotal"],
		swapFreeKB:              mem["SwapFree"],
		majorFaults:             majorFaults,
		diskUsedPct:             diskUsedPct,
		diskBusyMS:              diskBusyMS,
		diskOps:                 diskOps,
		networkIface:            iface,
		networkRxBytes:          rxBytes,
		networkTxBytes:          txBytes,
		networkRxPackets:        rxPackets,
		networkTxPackets:        txPackets,
		networkRxDropErrPackets: rxDropErr,
		networkTxDropErrPackets: txDropErr,
		networkCapacityBps:      networkCapacityBps,
		rttMs:                   rttMs,
	}
}

// computeLoadScores calculates normalized subsystem load scores (0..100) and total load.
//
// Design:
// 1. For each subsystem we normalize each component to [0,1] with explicit good/bad thresholds.
// 2. The subsystem score is:
//      score = 100 * max(peak_component, weighted_average_components)
//    This guarantees single-metric spikes elevate the subsystem score.
// 3. TOTAL score uses the agreed formula:
//      S = [cpu, ram, disk, net]
//      mx = max(S)
//      union = 100 * (1 - Π(1 - s/100))
//      total = max(mx, 0.70*mx + 0.30*union)
func computeLoadScores(prev *loadSnapshot, curr *loadSnapshot) map[string]float64 {
	if curr == nil {
		return map[string]float64{
			"cpu":   0,
			"ram":   0,
			"disk":  0,
			"net":   0,
			"total": 0,
		}
	}
	elapsedSeconds := 0.0
	if prev != nil {
		elapsedSeconds = curr.takenAt.Sub(prev.takenAt).Seconds()
	}
	if elapsedSeconds <= 0 {
		elapsedSeconds = 0
	}

	// CPU components: util %, run queue per core, cgroup throttle %.
	cpuUtilPct := 0.0
	if prev != nil && curr.cpuTotal > prev.cpuTotal && curr.cpuIdle >= prev.cpuIdle {
		totalDelta := float64(curr.cpuTotal - prev.cpuTotal)
		idleDelta := float64(curr.cpuIdle - prev.cpuIdle)
		if totalDelta > 0 {
			cpuUtilPct = clamp01(1-(idleDelta/totalDelta)) * 100
		}
	}
	runQPerCore := curr.runQPerCore
	throttlePct := 0.0
	if prev != nil && curr.throttleUsageUS > prev.throttleUsageUS && curr.throttleThrottledUS >= prev.throttleThrottledUS {
		usageDelta := float64(curr.throttleUsageUS - prev.throttleUsageUS)
		throttledDelta := float64(curr.throttleThrottledUS - prev.throttleThrottledUS)
		if usageDelta > 0 {
			throttlePct = (throttledDelta / usageDelta) * 100
		}
	}
	cpuU := normalizeRange(cpuUtilPct, 55, 95)
	cpuQ := normalizeRange(runQPerCore, 0.5, 2.0)
	cpuT := normalizeRange(throttlePct, 1, 20)
	cpuPeak := max4(cpuU, cpuQ, cpuT, 0)
	cpuWeighted := 0.55*cpuU + 0.30*cpuQ + 0.15*cpuT
	cpuScore := round1(100 * max4(cpuPeak, cpuWeighted, 0, 0))

	// RAM components: memory pressure, swap usage, major fault rate.
	memUsedPct := 0.0
	if curr.memTotalKB > 0 && curr.memAvailableKB <= curr.memTotalKB {
		memUsedPct = (1 - (float64(curr.memAvailableKB) / float64(curr.memTotalKB))) * 100
	}
	swapUsedPct := 0.0
	if curr.swapTotalKB > 0 && curr.swapFreeKB <= curr.swapTotalKB {
		swapUsedPct = (1 - (float64(curr.swapFreeKB) / float64(curr.swapTotalKB))) * 100
	}
	majorFaultRate := 0.0
	if prev != nil && elapsedSeconds > 0 && curr.majorFaults >= prev.majorFaults {
		majorFaultRate = float64(curr.majorFaults-prev.majorFaults) / elapsedSeconds
	}
	ramM := normalizeRange(memUsedPct, 65, 95)
	ramS := normalizeRange(swapUsedPct, 5, 40)
	ramF := normalizeRange(majorFaultRate, 50, 500)
	ramPeak := max4(ramM, ramS, ramF, 0)
	ramWeighted := 0.70*ramM + 0.20*ramS + 0.10*ramF
	ramScore := round1(100 * max4(ramPeak, ramWeighted, 0, 0))

	// Disk components: filesystem usage, device busy %, latency proxy.
	diskBusyPct := 0.0
	if prev != nil && elapsedSeconds > 0 && curr.diskBusyMS >= prev.diskBusyMS {
		busyDeltaMS := float64(curr.diskBusyMS - prev.diskBusyMS)
		windowMS := elapsedSeconds * 1000
		if windowMS > 0 {
			diskBusyPct = clamp01(busyDeltaMS/windowMS) * 100
		}
	}
	awaitMs := 0.0
	if prev != nil && curr.diskOps > prev.diskOps && curr.diskBusyMS >= prev.diskBusyMS {
		opsDelta := float64(curr.diskOps - prev.diskOps)
		busyDeltaMS := float64(curr.diskBusyMS - prev.diskBusyMS)
		if opsDelta > 0 {
			awaitMs = busyDeltaMS / opsDelta
		}
	}
	diskD := normalizeRange(curr.diskUsedPct, 70, 95)
	diskB := normalizeRange(diskBusyPct, 60, 95)
	diskA := normalizeRange(awaitMs, 10, 80)
	diskPeak := max4(diskD, diskB, diskA, 0)
	diskWeighted := 0.45*diskD + 0.35*diskB + 0.20*diskA
	diskScore := round1(100 * max4(diskPeak, diskWeighted, 0, 0))

	// Network components: bandwidth utilization, packet error/drop %, RTT.
	networkUtilPct := 0.0
	if prev != nil && elapsedSeconds > 0 && curr.networkCapacityBps > 0 &&
		curr.networkRxBytes >= prev.networkRxBytes && curr.networkTxBytes >= prev.networkTxBytes {
		rxDelta := float64(curr.networkRxBytes - prev.networkRxBytes)
		txDelta := float64(curr.networkTxBytes - prev.networkTxBytes)
		bps := ((rxDelta + txDelta) * 8) / elapsedSeconds
		networkUtilPct = (bps / curr.networkCapacityBps) * 100
	}
	networkLossErrPct := 0.0
	if prev != nil &&
		curr.networkRxPackets >= prev.networkRxPackets &&
		curr.networkTxPackets >= prev.networkTxPackets &&
		curr.networkRxDropErrPackets >= prev.networkRxDropErrPackets &&
		curr.networkTxDropErrPackets >= prev.networkTxDropErrPackets {
		packetDelta := float64((curr.networkRxPackets - prev.networkRxPackets) + (curr.networkTxPackets - prev.networkTxPackets))
		errorDelta := float64((curr.networkRxDropErrPackets - prev.networkRxDropErrPackets) + (curr.networkTxDropErrPackets - prev.networkTxDropErrPackets))
		if packetDelta > 0 {
			networkLossErrPct = (errorDelta / packetDelta) * 100
		}
	}
	rttMs := curr.rttMs
	netU := normalizeRange(networkUtilPct, 60, 95)
	netL := normalizeRange(networkLossErrPct, 0.1, 2.0)
	netR := normalizeRange(rttMs, 20, 150)
	netPeak := max4(netU, netL, netR, 0)
	netWeighted := 0.50*netU + 0.30*netL + 0.20*netR
	netScore := round1(100 * max4(netPeak, netWeighted, 0, 0))

	// TOTAL load aggregation per agreed formula.
	scoreList := []float64{cpuScore, ramScore, diskScore, netScore}
	mx := 0.0
	product := 1.0
	for _, score := range scoreList {
		if score > mx {
			mx = score
		}
		product *= (1 - clamp01(score/100))
	}
	union := 100 * (1 - product)
	totalScore := round1(max4(mx, 0.70*mx+0.30*union, 0, 0))

	return map[string]float64{
		"cpu":   cpuScore,
		"ram":   ramScore,
		"disk":  diskScore,
		"net":   netScore,
		"total": totalScore,
	}
}

func (a *Agent) swimLoadFlags() map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return map[string]any{
		"cpu_load":     round1(a.loadScores["cpu"]),
		"ram_load":     round1(a.loadScores["ram"]),
		"disk_load":    round1(a.loadScores["disk"]),
		"network_load": round1(a.loadScores["net"]),
		"total_load":   round1(a.loadScores["total"]),
	}
}

func (a *Agent) reconcileLoadScores() map[string]any {
	cacheTTL := time.Duration(max(1, a.cfg.HeartbeatIntervalSeconds)) * time.Second
	a.mu.RLock()
	cachedAt := a.loadScoresComputed
	cachedScores := map[string]float64{
		"cpu":   a.loadScores["cpu"],
		"ram":   a.loadScores["ram"],
		"disk":  a.loadScores["disk"],
		"net":   a.loadScores["net"],
		"total": a.loadScores["total"],
	}
	hasCache := a.lastLoadSample != nil && !cachedAt.IsZero()
	a.mu.RUnlock()
	if hasCache && time.Since(cachedAt) < cacheTTL {
		return map[string]any{
			"load_cpu_score":     cachedScores["cpu"],
			"load_ram_score":     cachedScores["ram"],
			"load_disk_score":    cachedScores["disk"],
			"load_network_score": cachedScores["net"],
			"load_total_score":   cachedScores["total"],
			"heartbeat_flags": map[string]any{
				"cpu_load":     cachedScores["cpu"],
				"ram_load":     cachedScores["ram"],
				"disk_load":    cachedScores["disk"],
				"network_load": cachedScores["net"],
				"total_load":   cachedScores["total"],
			},
		}
	}

	current := a.collectLoadSnapshot()
	a.mu.Lock()
	previous := a.lastLoadSample
	a.lastLoadSample = current
	a.mu.Unlock()

	scores := computeLoadScores(previous, current)
	a.mu.Lock()
	a.loadScores = map[string]float64{
		"cpu":   scores["cpu"],
		"ram":   scores["ram"],
		"disk":  scores["disk"],
		"net":   scores["net"],
		"total": scores["total"],
	}
	a.loadScoresComputed = time.Now().UTC()
	a.mu.Unlock()

	a.log.Debug("agent.load", "scores.compute", "Computed resource load scores", map[string]any{
		"cpu":            scores["cpu"],
		"ram":            scores["ram"],
		"disk":           scores["disk"],
		"net":            scores["net"],
		"total":          scores["total"],
		"network_iface":  current.networkIface,
		"network_rtt_ms": round1(current.rttMs),
	})
	return map[string]any{
		"load_cpu_score":     scores["cpu"],
		"load_ram_score":     scores["ram"],
		"load_disk_score":    scores["disk"],
		"load_network_score": scores["net"],
		"load_total_score":   scores["total"],
		"heartbeat_flags": map[string]any{
			"cpu_load":     scores["cpu"],
			"ram_load":     scores["ram"],
			"disk_load":    scores["disk"],
			"network_load": scores["net"],
			"total_load":   scores["total"],
		},
	}
}

func (a *Agent) syncRoleAssignment(ctx context.Context) map[string]any {
	patch := map[string]any{}
	leaseToken, err := a.readLeaseToken()
	if err != nil {
		patch["role_assignment_error"] = err.Error()
		return patch
	}
	u := fmt.Sprintf(
		"%s/roles/placement?node_id=%s&lease_token=%s",
		a.cfg.APIServerURL,
		url.QueryEscape(a.cfg.NodeID),
		url.QueryEscape(leaseToken),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		patch["role_assignment_error"] = err.Error()
		return patch
	}
	resp, err := a.client.Do(req)
	if err != nil {
		patch["role_assignment_error"] = err.Error()
		return patch
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		patch["role_assignment_error"] = fmt.Sprintf("http_%d:%s", resp.StatusCode, strings.TrimSpace(string(body)))
		return patch
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		patch["role_assignment_error"] = err.Error()
		return patch
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		patch["role_assignment_error"] = err.Error()
		return patch
	}
	assignments := []string{}
	nodeAssignments, ok := payload["node_assignments"].(map[string]any)
	if ok {
		if raw, ok := nodeAssignments[a.cfg.NodeID].([]any); ok {
			for _, item := range raw {
				value := strings.TrimSpace(fmt.Sprintf("%v", item))
				if value != "" {
					assignments = append(assignments, value)
				}
			}
		}
	}

	backendNodeIDs := []string{}
	placementMap, ok := payload["placement_map"].(map[string]any)
	if ok {
		if raw, ok := placementMap["backend_server"].([]any); ok {
			for _, item := range raw {
				value := strings.TrimSpace(fmt.Sprintf("%v", item))
				if value != "" {
					backendNodeIDs = append(backendNodeIDs, value)
				}
			}
		}
	}

	peerByNodeID := map[string]string{}
	if len(backendNodeIDs) > 0 {
		peersRaw, peersErr := a.fetchClusterPeers(ctx, leaseToken)
		if peersErr != nil {
			patch["backend_targets_error"] = peersErr.Error()
		} else {
			for _, row := range peersRaw {
				nodeID := strings.TrimSpace(fmt.Sprintf("%v", row["node_id"]))
				meshIP := strings.TrimSpace(fmt.Sprintf("%v", row["mesh_ip"]))
				if nodeID != "" && meshIP != "" {
					peerByNodeID[nodeID] = meshIP
				}
			}
		}
	}

	backendTargets := []string{}
	for _, nodeID := range backendNodeIDs {
		if nodeID == a.cfg.NodeID {
			backendTargets = append(backendTargets, fmt.Sprintf("127.0.0.1:%d", a.cfg.BackendListenPort))
			continue
		}
		if meshIP := peerByNodeID[nodeID]; meshIP != "" {
			backendTargets = append(backendTargets, fmt.Sprintf("%s:%d", meshIP, a.cfg.BackendListenPort))
		}
	}
	if hasRole(assignments, "backend_server") {
		backendTargets = append(backendTargets, fmt.Sprintf("127.0.0.1:%d", a.cfg.BackendListenPort))
	}

	assignments = dedupeStrings(assignments)
	backendTargets = dedupeStrings(backendTargets)

	a.mu.Lock()
	a.assignedRoles = assignments
	a.backendTargets = backendTargets
	a.mu.Unlock()
	patch["assigned_roles"] = assignments
	patch["assigned_role_count"] = len(assignments)
	patch["backend_targets"] = backendTargets
	patch["backend_target_count"] = len(backendTargets)
	return patch
}

func (a *Agent) reconcileRoleRuntimes(ctx context.Context) map[string]any {
	a.mu.RLock()
	roles := append([]string{}, a.assignedRoles...)
	backendTargets := append([]string{}, a.backendTargets...)
	a.mu.RUnlock()

	patch := map[string]any{
		"role_runtime_roles": roles,
	}
	backendEnabled := hasRole(roles, "backend_server")
	proxyEnabled := hasRole(roles, "reverse_proxy")

	backendPatch := a.reconcileBackendRuntime(ctx, backendEnabled)
	for key, value := range backendPatch {
		patch[key] = value
	}

	proxyPatch := a.reconcileProxyRuntime(ctx, proxyEnabled, backendTargets)
	for key, value := range proxyPatch {
		patch[key] = value
	}

	state := "healthy"
	if fmt.Sprintf("%v", patch["backend_runtime_state"]) == "degraded" || fmt.Sprintf("%v", patch["proxy_runtime_state"]) == "degraded" {
		state = "degraded"
	}
	patch["role_runtime_state"] = state
	patch["role_runtime_backend_enabled"] = backendEnabled
	patch["role_runtime_proxy_enabled"] = proxyEnabled
	return patch
}

func (a *Agent) reconcileBackendRuntime(ctx context.Context, enabled bool) map[string]any {
	patch := map[string]any{
		"backend_runtime_state": "not_assigned",
	}
	if !enabled {
		return patch
	}

	contentBase := strings.TrimSpace(a.cfg.InternalCDNDir)
	if contentBase == "" {
		contentBase = "data/internal-cdn"
	}
	contentRoot := filepath.Join(contentBase, "active")
	if err := os.MkdirAll(contentRoot, 0o755); err != nil {
		patch["backend_runtime_state"] = "degraded"
		patch["backend_runtime_error"] = err.Error()
		a.log.Warn("agent.roles", "backend.prepare_error", "Failed preparing backend content directory", map[string]any{
			"path":  contentRoot,
			"error": err.Error(),
		})
		return patch
	}

	configPath := "/etc/nginx/conf.d/uptimemesh-backend.conf"
	config := fmt.Sprintf(`# Managed by UptimeMesh. Manual edits are overwritten.
server {
    listen 127.0.0.1:%d;
    server_name _;
    root %q;
    index index.html;
    location / {
        try_files $uri $uri/ /index.html;
    }
}
`, a.cfg.BackendListenPort, contentRoot)
	if err := os.WriteFile(configPath, []byte(config), 0o644); err != nil {
		patch["backend_runtime_state"] = "degraded"
		patch["backend_runtime_error"] = err.Error()
		a.log.Warn("agent.roles", "backend.config_write_error", "Failed writing backend NGINX config", map[string]any{
			"path":  configPath,
			"error": err.Error(),
		})
		return patch
	}

	code, out, errText := a.runCommand(ctx, "backend.nginx_validate", "nginx", "-t")
	if code != 0 {
		patch["backend_runtime_state"] = "degraded"
		patch["backend_runtime_error"] = firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code))
		a.log.Warn("agent.roles", "backend.validate_error", "NGINX config validation failed", map[string]any{
			"config_path": configPath,
			"error":       patch["backend_runtime_error"],
		})
		return patch
	}

	code, out, errText = a.runCommand(ctx, "backend.nginx_enable", "systemctl", "enable", "--now", "nginx")
	if code != 0 {
		patch["backend_runtime_state"] = "degraded"
		patch["backend_runtime_error"] = firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code))
		a.log.Warn("agent.roles", "backend.enable_error", "Failed enabling backend nginx service", map[string]any{
			"error": patch["backend_runtime_error"],
		})
		return patch
	}

	code, out, errText = a.runCommand(ctx, "backend.nginx_reload", "systemctl", "reload", "nginx")
	if code != 0 {
		code, out, errText = a.runCommand(ctx, "backend.nginx_restart", "systemctl", "restart", "nginx")
		if code != 0 {
			patch["backend_runtime_state"] = "degraded"
			patch["backend_runtime_error"] = firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code))
			a.log.Warn("agent.roles", "backend.reload_error", "Failed reloading backend nginx service", map[string]any{
				"error": patch["backend_runtime_error"],
			})
			return patch
		}
	}

	a.log.Info("agent.roles", "backend.ready", "Backend runtime reconciled", map[string]any{
		"config_path":  configPath,
		"content_root": contentRoot,
		"listen_port":  a.cfg.BackendListenPort,
	})
	patch["backend_runtime_state"] = "healthy"
	patch["backend_runtime_config_path"] = configPath
	patch["backend_runtime_content_root"] = contentRoot
	patch["backend_runtime_port"] = a.cfg.BackendListenPort
	return patch
}

func (a *Agent) reconcileProxyRuntime(ctx context.Context, enabled bool, upstreams []string) map[string]any {
	patch := map[string]any{
		"proxy_runtime_state": "not_assigned",
	}
	if !enabled {
		return patch
	}
	upstreams = dedupeStrings(upstreams)
	if len(upstreams) == 0 {
		patch["proxy_runtime_state"] = "degraded"
		patch["proxy_runtime_error"] = "no_backend_targets"
		a.log.Warn("agent.roles", "proxy.targets_missing", "Reverse proxy has no backend targets", nil)
		return patch
	}

	configPath := "/etc/caddy/Caddyfile"
	var builder strings.Builder
	builder.WriteString("# Managed by UptimeMesh. Manual edits are overwritten.\n")
	builder.WriteString(fmt.Sprintf(":%d {\n", a.cfg.ProxyListenPort))
	builder.WriteString("    encode zstd gzip\n")
	builder.WriteString("    @health path /healthz\n")
	builder.WriteString("    respond @health \"ok\" 200\n")
	builder.WriteString("    reverse_proxy ")
	builder.WriteString(strings.Join(upstreams, " "))
	builder.WriteString("\n}\n")
	if err := os.WriteFile(configPath, []byte(builder.String()), 0o644); err != nil {
		patch["proxy_runtime_state"] = "degraded"
		patch["proxy_runtime_error"] = err.Error()
		a.log.Warn("agent.roles", "proxy.config_write_error", "Failed writing Caddy config", map[string]any{
			"path":  configPath,
			"error": err.Error(),
		})
		return patch
	}

	code, out, errText := a.runCommand(ctx, "proxy.caddy_validate", "caddy", "validate", "--config", configPath, "--adapter", "caddyfile")
	if code != 0 {
		patch["proxy_runtime_state"] = "degraded"
		patch["proxy_runtime_error"] = firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code))
		a.log.Warn("agent.roles", "proxy.validate_error", "Caddy config validation failed", map[string]any{
			"config_path": configPath,
			"error":       patch["proxy_runtime_error"],
		})
		return patch
	}

	code, out, errText = a.runCommand(ctx, "proxy.caddy_enable", "systemctl", "enable", "--now", "caddy")
	if code != 0 {
		patch["proxy_runtime_state"] = "degraded"
		patch["proxy_runtime_error"] = firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code))
		a.log.Warn("agent.roles", "proxy.enable_error", "Failed enabling caddy service", map[string]any{
			"error": patch["proxy_runtime_error"],
		})
		return patch
	}

	code, out, errText = a.runCommand(ctx, "proxy.caddy_reload", "systemctl", "reload", "caddy")
	if code != 0 {
		code, out, errText = a.runCommand(ctx, "proxy.caddy_restart", "systemctl", "restart", "caddy")
		if code != 0 {
			patch["proxy_runtime_state"] = "degraded"
			patch["proxy_runtime_error"] = firstNonEmpty(errText, out, fmt.Sprintf("exit_%d", code))
			a.log.Warn("agent.roles", "proxy.reload_error", "Failed reloading caddy service", map[string]any{
				"error": patch["proxy_runtime_error"],
			})
			return patch
		}
	}

	a.log.Info("agent.roles", "proxy.ready", "Reverse proxy runtime reconciled", map[string]any{
		"config_path": configPath,
		"listen_port": a.cfg.ProxyListenPort,
		"targets":     strings.Join(upstreams, ","),
	})
	patch["proxy_runtime_state"] = "healthy"
	patch["proxy_runtime_config_path"] = configPath
	patch["proxy_runtime_port"] = a.cfg.ProxyListenPort
	patch["proxy_runtime_targets"] = upstreams
	return patch
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

	loadPatch := a.reconcileLoadScores()
	for k, v := range loadPatch {
		statusPatch[k] = v
	}

	if a.cfg.EnableWireGuard {
		wgPatch := a.reconcileWireGuard(ctx)
		for k, v := range wgPatch {
			statusPatch[k] = v
		}
	} else {
		a.log.Info("agent.wireguard", "reconcile.skip", "WireGuard reconcile disabled", nil)
	}
	if a.cfg.SWIMEnabled {
		swimPatch := a.reconcileSWIM(ctx)
		for k, v := range swimPatch {
			statusPatch[k] = v
		}
	}
	rolePatch := a.syncRoleAssignment(ctx)
	for k, v := range rolePatch {
		statusPatch[k] = v
	}
	cdnPatch := a.syncInternalCDN(ctx)
	for k, v := range cdnPatch {
		statusPatch[k] = v
	}
	roleRuntimePatch := a.reconcileRoleRuntimes(ctx)
	for k, v := range roleRuntimePatch {
		statusPatch[k] = v
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
	primaryPeerConfigured := strings.TrimSpace(primaryPeer.publicKey) != ""
	secondaryPeerConfigured := strings.TrimSpace(secondaryPeer.publicKey) != ""
	primaryIfaceConfigured := primaryPeerConfigured || strings.TrimSpace(localAddress) != ""
	secondaryIfaceConfigured := secondaryPeerConfigured || strings.TrimSpace(localAddress) != ""
	primaryPublicKey := ""
	secondaryPublicKey := ""

	if !primaryIfaceConfigured && !secondaryIfaceConfigured {
		a.mu.Lock()
		if strings.TrimSpace(a.state.ActiveIface) == "" {
			a.state.ActiveIface = a.cfg.PrimaryIface
		}
		activeIface := a.state.ActiveIface
		a.state.PrimaryFailures = 0
		a.state.PrimarySuccesses = 0
		a.state.SecondaryFailures = 0
		a.state.SecondarySuccesses = 0
		a.mu.Unlock()

		a.log.Info("agent.wireguard", "reconcile.skip_unconfigured", "Skipped WireGuard reconcile (no peer public keys configured)", map[string]any{
			"primary_iface":          a.cfg.PrimaryIface,
			"secondary_iface":        a.cfg.SecondaryIface,
			"primary_peer_endpoint":  primaryPeer.endpoint,
			"secondary_peer_endpoint": secondaryPeer.endpoint,
		})
		return map[string]any{
			"wg_primary_tunnel":            "down",
			"wg_secondary_tunnel":          "down",
			"wg_primary_health":            false,
			"wg_secondary_health":          false,
			"wg_primary_router_reachable":  false,
			"wg_secondary_router_reachable": false,
			"wg_active_route":              activeIface,
			"wg_failover_state":            "unconfigured",
			"wg_primary_public_key":        "",
			"wg_secondary_public_key":      "",
			"wg_public_key":                "",
			"wg_primary_peer_endpoint":     primaryPeer.endpoint,
			"wg_secondary_peer_endpoint":   secondaryPeer.endpoint,
			"wg_primary_peer_configured":   false,
			"wg_secondary_peer_configured": false,
		}
	}

	if primaryIfaceConfigured {
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
	}
	if secondaryIfaceConfigured {
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
	}

	if primaryIfaceConfigured {
		primaryPublicKey = a.wireGuardPublicKey(ctx, a.cfg.PrimaryIface)
	}
	if secondaryIfaceConfigured {
		secondaryPublicKey = a.wireGuardPublicKey(ctx, a.cfg.SecondaryIface)
	}

	primaryUp := primaryIfaceConfigured && a.interfaceUp(ctx, a.cfg.PrimaryIface)
	secondaryUp := secondaryIfaceConfigured && a.interfaceUp(ctx, a.cfg.SecondaryIface)

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

	if activeAfter != activeBefore && (primaryIfaceConfigured || secondaryIfaceConfigured) {
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
	if primaryIfaceConfigured || secondaryIfaceConfigured {
		a.applyRouteMetrics(ctx, activeAfter)
	}

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
		"wg_primary_peer_configured":   primaryPeerConfigured,
		"wg_secondary_peer_configured": secondaryPeerConfigured,
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

func hasRole(roles []string, target string) bool {
	expected := strings.ToLower(strings.TrimSpace(target))
	if expected == "" {
		return false
	}
	for _, role := range roles {
		if strings.ToLower(strings.TrimSpace(role)) == expected {
			return true
		}
	}
	return false
}

func dedupeStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, raw := range values {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
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
