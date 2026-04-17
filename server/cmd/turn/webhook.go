package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type WebhookEvent string

const (
	WebhookEventSessionCreated WebhookEvent = "session_created"
	WebhookEventSessionUpdated WebhookEvent = "session_updated"
	WebhookEventSessionIdle    WebhookEvent = "session_idle"
	WebhookEventSessionExpired WebhookEvent = "session_expired"
	WebhookEventSessionClosed  WebhookEvent = "session_closed"
)

const (
	webhookStatusActive  = "active"
	webhookStatusIdle    = "idle"
	webhookStatusExpired = "expired"
	webhookStatusClosed  = "closed"

	defaultWebhookTimeout    = 3 * time.Second
	defaultWebhookQueueSize  = 128
	maxWebhookBodyLogBytes   = 512
	defaultCommandTimeout    = 3 * time.Second
	defaultCommandQueueSize  = 128
	defaultCommandShell      = "/bin/sh"
	maxCommandOutputLogBytes = 512
)

var webhookEvents = []WebhookEvent{
	WebhookEventSessionCreated,
	WebhookEventSessionUpdated,
	WebhookEventSessionIdle,
	WebhookEventSessionExpired,
	WebhookEventSessionClosed,
}

var webhookTemplatePattern = regexp.MustCompile(`\$\{([a-z0-9_]+)\}`)

type WebhookSnapshot struct {
	Event               WebhookEvent
	Status              string
	SessionID           string
	PublicKey           string
	ClientPublicIP      string
	RelayIPs            []string
	ActiveStreams       int
	PersistentKeepalive int
	LastSeenUnix        int64
	LastChangeUnix      int64
	TsUnix              int64
}

type WebhookConfig struct {
	Event    WebhookEvent
	Method   string
	URL      string
	Template string
	Headers  map[string]string
}

type WebhookSink interface {
	Emit(WebhookEvent, WebhookSnapshot)
	Close()
}

type sinkGroup struct {
	sinks []WebhookSink
}

func (g *sinkGroup) Emit(event WebhookEvent, snapshot WebhookSnapshot) {
	if g == nil {
		return
	}
	for _, sink := range g.sinks {
		if sink != nil {
			sink.Emit(event, snapshot)
		}
	}
}

func (g *sinkGroup) Close() {
	if g == nil {
		return
	}
	for _, sink := range g.sinks {
		if sink != nil {
			sink.Close()
		}
	}
}

type webhookJob struct {
	config   WebhookConfig
	snapshot WebhookSnapshot
}

type WebhookDispatcher struct {
	client  *http.Client
	configs map[WebhookEvent]WebhookConfig
	queue   chan webhookJob
	wg      sync.WaitGroup
}

type CommandConfig struct {
	Event   WebhookEvent
	Command string
}

type commandJob struct {
	config   CommandConfig
	snapshot WebhookSnapshot
}

type CommandDispatcher struct {
	shell   string
	timeout time.Duration
	configs map[WebhookEvent]CommandConfig
	queue   chan commandJob
	wg      sync.WaitGroup
}

func LoadWebhookDispatcherFromEnv() (*WebhookDispatcher, error) {
	configs := make(map[WebhookEvent]WebhookConfig)
	for _, event := range webhookEvents {
		cfg, enabled, err := loadWebhookConfigFromEnv(event)
		if err != nil {
			return nil, err
		}
		if enabled {
			configs[event] = cfg
		}
	}
	if len(configs) == 0 {
		return nil, nil
	}

	timeout := defaultWebhookTimeout
	if raw := strings.TrimSpace(os.Getenv("VKTURN_WEBHOOK_TIMEOUT")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid VKTURN_WEBHOOK_TIMEOUT=%q: %w", raw, err)
		}
		if parsed <= 0 {
			return nil, fmt.Errorf("invalid VKTURN_WEBHOOK_TIMEOUT=%q: must be > 0", raw)
		}
		timeout = parsed
	}

	sslVerify := true
	if raw := strings.TrimSpace(os.Getenv("VKTURN_WEBHOOK_SSL_VERIFY")); raw != "" {
		parsed, err := parseBoolEnv(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid VKTURN_WEBHOOK_SSL_VERIFY=%q: %w", raw, err)
		}
		sslVerify = parsed
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: !sslVerify}

	dispatcher := &WebhookDispatcher{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		configs: configs,
		queue:   make(chan webhookJob, defaultWebhookQueueSize),
	}

	dispatcher.wg.Add(1)
	go dispatcher.worker()

	for _, event := range webhookEvents {
		if cfg, ok := configs[event]; ok {
			log.Printf("Webhook enabled for %s: %s %s", event, cfg.Method, redactWebhookURL(cfg.URL))
		}
	}

	return dispatcher, nil
}

func LoadCommandDispatcherFromEnv() (*CommandDispatcher, error) {
	configs := make(map[WebhookEvent]CommandConfig)
	for _, event := range webhookEvents {
		cfg, enabled, err := loadCommandConfigFromEnv(event)
		if err != nil {
			return nil, err
		}
		if enabled {
			configs[event] = cfg
		}
	}
	if len(configs) == 0 {
		return nil, nil
	}

	timeout := defaultCommandTimeout
	if raw := strings.TrimSpace(os.Getenv("VKTURN_EXEC_TIMEOUT")); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid VKTURN_EXEC_TIMEOUT=%q: %w", raw, err)
		}
		if parsed <= 0 {
			return nil, fmt.Errorf("invalid VKTURN_EXEC_TIMEOUT=%q: must be > 0", raw)
		}
		timeout = parsed
	}

	shell := strings.TrimSpace(os.Getenv("VKTURN_EXEC_SHELL"))
	if shell == "" {
		shell = defaultCommandShell
	}

	dispatcher := &CommandDispatcher{
		shell:   shell,
		timeout: timeout,
		configs: configs,
		queue:   make(chan commandJob, defaultCommandQueueSize),
	}

	dispatcher.wg.Add(1)
	go dispatcher.worker()

	for _, event := range webhookEvents {
		if _, ok := configs[event]; ok {
			log.Printf("Command enabled for %s: shell %s", event, shell)
		}
	}

	return dispatcher, nil
}

func loadWebhookConfigFromEnv(event WebhookEvent) (WebhookConfig, bool, error) {
	prefix := webhookEnvPrefix(event)
	rawURL := strings.TrimSpace(os.Getenv(prefix + "_URL"))
	rawMethod := strings.TrimSpace(os.Getenv(prefix + "_METHOD"))
	rawTemplate := os.Getenv(prefix + "_TEMPLATE")
	rawHeaders := strings.TrimSpace(os.Getenv(prefix + "_HEADERS"))

	if rawURL == "" && rawMethod == "" && rawTemplate == "" && rawHeaders == "" {
		return WebhookConfig{}, false, nil
	}

	if rawURL == "" {
		return WebhookConfig{}, false, fmt.Errorf("%s_URL is required when configuring %s", prefix, event)
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
		return WebhookConfig{}, false, fmt.Errorf("%s_URL must be a valid absolute URL", prefix)
	}

	if rawMethod == "" {
		return WebhookConfig{}, false, fmt.Errorf("%s_METHOD is required when configuring %s", prefix, event)
	}
	method := strings.ToUpper(rawMethod)
	if method != http.MethodPost && method != http.MethodGet {
		return WebhookConfig{}, false, fmt.Errorf("%s_METHOD=%q is unsupported; use GET or POST", prefix, rawMethod)
	}
	if method == http.MethodPost && strings.TrimSpace(rawTemplate) == "" {
		return WebhookConfig{}, false, fmt.Errorf("%s_TEMPLATE is required for POST hooks", prefix)
	}

	headers := make(map[string]string)
	if rawHeaders != "" {
		if err := json.Unmarshal([]byte(rawHeaders), &headers); err != nil {
			return WebhookConfig{}, false, fmt.Errorf("%s_HEADERS must be a JSON object: %w", prefix, err)
		}
	}

	return WebhookConfig{
		Event:    event,
		Method:   method,
		URL:      rawURL,
		Template: rawTemplate,
		Headers:  headers,
	}, true, nil
}

func loadCommandConfigFromEnv(event WebhookEvent) (CommandConfig, bool, error) {
	prefix := commandEnvPrefix(event)
	rawCommand := strings.TrimSpace(os.Getenv(prefix + "_COMMAND"))

	if rawCommand == "" {
		return CommandConfig{}, false, nil
	}

	return CommandConfig{
		Event:   event,
		Command: rawCommand,
	}, true, nil
}

func webhookEnvPrefix(event WebhookEvent) string {
	return "VKTURN_WEBHOOK_ON_" + strings.ToUpper(strings.ReplaceAll(string(event), "-", "_"))
}

func commandEnvPrefix(event WebhookEvent) string {
	return "VKTURN_EXEC_ON_" + strings.ToUpper(strings.ReplaceAll(string(event), "-", "_"))
}

func parseBoolEnv(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("expected boolean value")
	}
}

func (d *WebhookDispatcher) Emit(event WebhookEvent, snapshot WebhookSnapshot) {
	if d == nil {
		return
	}
	cfg, ok := d.configs[event]
	if !ok {
		return
	}

	select {
	case d.queue <- webhookJob{config: cfg, snapshot: snapshot}:
	default:
		log.Printf("Webhook queue full for %s, dropping event for session %s", event, snapshot.SessionID)
	}
}

func (d *CommandDispatcher) Emit(event WebhookEvent, snapshot WebhookSnapshot) {
	if d == nil {
		return
	}
	cfg, ok := d.configs[event]
	if !ok {
		return
	}

	select {
	case d.queue <- commandJob{config: cfg, snapshot: snapshot}:
	default:
		log.Printf("Command queue full for %s, dropping event for session %s", event, snapshot.SessionID)
	}
}

func (d *WebhookDispatcher) Close() {
	if d == nil {
		return
	}
	close(d.queue)
	d.wg.Wait()
}

func (d *CommandDispatcher) Close() {
	if d == nil {
		return
	}
	close(d.queue)
	d.wg.Wait()
}

func (d *WebhookDispatcher) worker() {
	defer d.wg.Done()
	for job := range d.queue {
		d.deliver(job)
	}
}

func (d *CommandDispatcher) worker() {
	defer d.wg.Done()
	for job := range d.queue {
		d.deliver(job)
	}
}

func (d *WebhookDispatcher) deliver(job webhookJob) {
	started := time.Now()
	req, err := buildWebhookRequest(job.config, job.snapshot)
	if err != nil {
		log.Printf("Webhook %s build failed for %s: %v", job.config.Event, job.snapshot.SessionID, err)
		return
	}

	resp, err := d.client.Do(req)
	if err != nil {
		log.Printf("Webhook %s %s %s failed in %s: %v", job.config.Event, job.config.Method, redactWebhookURL(job.config.URL), time.Since(started).Round(time.Millisecond), err)
		return
	}
	defer resp.Body.Close()

	bodySnippet := readWebhookBodySnippet(resp.Body)
	duration := time.Since(started).Round(time.Millisecond)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if bodySnippet != "" {
			log.Printf("Webhook %s %s %s -> %d in %s: %s", job.config.Event, job.config.Method, redactWebhookURL(job.config.URL), resp.StatusCode, duration, bodySnippet)
		} else {
			log.Printf("Webhook %s %s %s -> %d in %s", job.config.Event, job.config.Method, redactWebhookURL(job.config.URL), resp.StatusCode, duration)
		}
		return
	}

	log.Printf("Webhook %s %s %s -> %d in %s", job.config.Event, job.config.Method, redactWebhookURL(job.config.URL), resp.StatusCode, duration)
}

func (d *CommandDispatcher) deliver(job commandJob) {
	started := time.Now()
	rendered := renderWebhookTemplate(job.config.Command, job.snapshot)

	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, d.shell, "-c", rendered)
	cmd.Env = append(os.Environ(), snapshotEnvVars(job.snapshot)...)

	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined

	err := cmd.Run()
	duration := time.Since(started).Round(time.Millisecond)
	outputSnippet := readCommandOutputSnippet(&combined)
	if err != nil {
		if outputSnippet != "" {
			log.Printf("Command %s failed for %s in %s: %v: %s", job.config.Event, job.snapshot.SessionID, duration, err, outputSnippet)
		} else {
			log.Printf("Command %s failed for %s in %s: %v", job.config.Event, job.snapshot.SessionID, duration, err)
		}
		return
	}

	if outputSnippet != "" {
		log.Printf("Command %s completed for %s in %s: %s", job.config.Event, job.snapshot.SessionID, duration, outputSnippet)
		return
	}
	log.Printf("Command %s completed for %s in %s", job.config.Event, job.snapshot.SessionID, duration)
}

func buildWebhookRequest(cfg WebhookConfig, snapshot WebhookSnapshot) (*http.Request, error) {
	rendered := renderWebhookTemplate(cfg.Template, snapshot)
	var body io.Reader
	targetURL := cfg.URL

	if cfg.Method == http.MethodGet {
		targetURL += rendered
	} else {
		body = strings.NewReader(rendered)
	}

	req, err := http.NewRequest(cfg.Method, targetURL, body)
	if err != nil {
		return nil, err
	}
	for key, value := range cfg.Headers {
		req.Header.Set(key, value)
	}
	return req, nil
}

func renderWebhookTemplate(template string, snapshot WebhookSnapshot) string {
	vars := snapshot.templateVars()
	return webhookTemplatePattern.ReplaceAllStringFunc(template, func(match string) string {
		groups := webhookTemplatePattern.FindStringSubmatch(match)
		if len(groups) != 2 {
			return ""
		}
		return vars[groups[1]]
	})
}

func (s WebhookSnapshot) templateVars() map[string]string {
	relayIPsJSON, _ := json.Marshal(s.RelayIPs)
	return map[string]string{
		"event":                string(s.Event),
		"session_id":           s.SessionID,
		"public_key":           s.PublicKey,
		"client_public_ip":     s.ClientPublicIP,
		"relay_ips_json":       string(relayIPsJSON),
		"relay_ips_csv":        strings.Join(s.RelayIPs, ","),
		"active_streams":       fmt.Sprintf("%d", s.ActiveStreams),
		"persistent_keepalive": fmt.Sprintf("%d", s.PersistentKeepalive),
		"last_seen_unix":       fmt.Sprintf("%d", s.LastSeenUnix),
		"last_change_unix":     fmt.Sprintf("%d", s.LastChangeUnix),
		"ts_unix":              fmt.Sprintf("%d", s.TsUnix),
		"status":               s.Status,
	}
}

func snapshotEnvVars(s WebhookSnapshot) []string {
	vars := s.templateVars()
	keys := make([]string, 0, len(vars))
	for key := range vars {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	env := make([]string, 0, len(vars))
	for _, key := range keys {
		env = append(env, "VKTURN_"+strings.ToUpper(key)+"="+vars[key])
	}
	return env
}

func readWebhookBodySnippet(r io.Reader) string {
	limited, err := io.ReadAll(io.LimitReader(r, maxWebhookBodyLogBytes))
	if err != nil {
		return ""
	}
	snippet := strings.TrimSpace(string(bytes.TrimSpace(limited)))
	if len(snippet) > maxWebhookBodyLogBytes {
		return snippet[:maxWebhookBodyLogBytes]
	}
	return snippet
}

func readCommandOutputSnippet(buf *bytes.Buffer) string {
	output := strings.TrimSpace(buf.String())
	if len(output) > maxCommandOutputLogBytes {
		return output[:maxCommandOutputLogBytes]
	}
	return output
}

func redactWebhookURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "<invalid-url>"
	}
	return parsed.Scheme + "://" + parsed.Host
}
