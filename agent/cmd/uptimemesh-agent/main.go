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
	a.log.Info("agent.loop", "tick.start", "Starting loop tick", map[string]any{
		"active_iface": a.state.ActiveIface,
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

	if err := a.sendHeartbeat(ctx, statusPatch); err != nil {
		a.log.Error("agent.heartbeat", "publish.fail", "Heartbeat publish failed", map[string]any{
			"error": err.Error(),
		})
		return err
	}

	a.log.Info("agent.loop", "tick.complete", "Completed loop tick", map[string]any{
		"duration_ms": time.Since(start).Milliseconds(),
		"active_iface": a.state.ActiveIface,
	})
	return nil
}

func (a *Agent) reconcileWireGuard(ctx context.Context) map[string]any {
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

	switch a.state.ActiveIface {
	case a.cfg.PrimaryIface:
		if !primaryHealthy && secondaryHealthy && a.state.PrimaryFailures >= a.cfg.FailoverThreshold {
			a.state.ActiveIface = a.cfg.SecondaryIface
			a.applyRouteMetrics(ctx, a.state.ActiveIface)
			a.log.Warn("agent.wireguard", "failover.engage", "Switched active route to secondary", map[string]any{
				"from":             a.cfg.PrimaryIface,
				"to":               a.cfg.SecondaryIface,
				"primary_failures": a.state.PrimaryFailures,
			})
		}
	case a.cfg.SecondaryIface:
		if !secondaryHealthy && primaryHealthy {
			a.state.ActiveIface = a.cfg.PrimaryIface
			a.applyRouteMetrics(ctx, a.state.ActiveIface)
			a.log.Warn("agent.wireguard", "failover.recover", "Primary route restored (secondary unhealthy)", map[string]any{
				"from": a.cfg.SecondaryIface,
				"to":   a.cfg.PrimaryIface,
			})
		} else if a.cfg.FailbackEnabled && primaryHealthy && a.state.PrimarySuccesses >= a.cfg.FailbackStableCount {
			a.state.ActiveIface = a.cfg.PrimaryIface
			a.applyRouteMetrics(ctx, a.state.ActiveIface)
			a.log.Info("agent.wireguard", "failback.engage", "Switched back to primary route", map[string]any{
				"stable_count": a.state.PrimarySuccesses,
			})
		}
	default:
		a.state.ActiveIface = a.cfg.PrimaryIface
	}

	failoverState := "primary"
	if a.state.ActiveIface == a.cfg.SecondaryIface {
		failoverState = "failover_secondary"
	}

	patch := map[string]any{
		"wg_primary_tunnel":   upDown(primaryUp),
		"wg_secondary_tunnel": upDown(secondaryUp),
		"wg_primary_health":   primaryHealthy,
		"wg_secondary_health": secondaryHealthy,
		"wg_active_route":     a.state.ActiveIface,
		"wg_failover_state":   failoverState,
	}
	a.log.Info("agent.wireguard", "reconcile.status", "Reconciled WireGuard status", map[string]any{
		"primary_up":       primaryUp,
		"secondary_up":     secondaryUp,
		"primary_healthy":  primaryHealthy,
		"secondary_healthy": secondaryHealthy,
		"active_iface":     a.state.ActiveIface,
		"failover_state":   failoverState,
	})
	return patch
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
		return fmt.Errorf("read key: %w", err)
	}
	leaseTokenRaw, err := os.ReadFile(leasePath)
	if err != nil {
		return fmt.Errorf("read lease token: %w", err)
	}
	leaseToken := strings.TrimSpace(string(leaseTokenRaw))
	if leaseToken == "" {
		return errors.New("lease token is empty")
	}

	privateKey, err := parsePrivateKey(keyRaw)
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}

	signedAt := time.Now().Unix()
	message, err := heartbeatSigningMessage(a.cfg.NodeID, leaseToken, signedAt, a.cfg.HeartbeatTTLSeconds, statusPatch)
	if err != nil {
		return fmt.Errorf("build message: %w", err)
	}
	signature, err := signMessage(privateKey, message)
	if err != nil {
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
		return err
	}

	url := a.cfg.APIServerURL + "/cluster/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	latencyMs := time.Since(start).Milliseconds()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat http %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

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
