package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingWebhookSink struct {
	mu        sync.Mutex
	snapshots map[WebhookEvent][]WebhookSnapshot
}

func newRecordingWebhookSink() *recordingWebhookSink {
	return &recordingWebhookSink{snapshots: make(map[WebhookEvent][]WebhookSnapshot)}
}

func (r *recordingWebhookSink) Emit(event WebhookEvent, snapshot WebhookSnapshot) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshots[event] = append(r.snapshots[event], snapshot)
}

func (r *recordingWebhookSink) Close() {}

func (r *recordingWebhookSink) count(event WebhookEvent) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.snapshots[event])
}

func (r *recordingWebhookSink) last(event WebhookEvent) WebhookSnapshot {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := r.snapshots[event]
	return items[len(items)-1]
}

func TestLoadWebhookConfigFromEnvValidation(t *testing.T) {
	t.Setenv("VKTURN_WEBHOOK_ON_SESSION_CREATED_METHOD", "POST")
	t.Setenv("VKTURN_WEBHOOK_ON_SESSION_CREATED_TEMPLATE", `{"event":"${event}"}`)
	if _, err := LoadWebhookDispatcherFromEnv(); err == nil || !strings.Contains(err.Error(), "URL") {
		t.Fatalf("expected URL validation error, got %v", err)
	}

	t.Setenv("VKTURN_WEBHOOK_ON_SESSION_CREATED_URL", "https://example.com/hook")
	t.Setenv("VKTURN_WEBHOOK_ON_SESSION_CREATED_METHOD", "PATCH")
	if _, err := LoadWebhookDispatcherFromEnv(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported method error, got %v", err)
	}

	t.Setenv("VKTURN_WEBHOOK_ON_SESSION_CREATED_METHOD", "GET")
	t.Setenv("VKTURN_WEBHOOK_ON_SESSION_CREATED_HEADERS", `["bad"]`)
	if _, err := LoadWebhookDispatcherFromEnv(); err == nil || !strings.Contains(err.Error(), "JSON object") {
		t.Fatalf("expected headers validation error, got %v", err)
	}
}

func TestLoadCommandConfigFromEnvValidation(t *testing.T) {
	t.Setenv("VKTURN_EXEC_ON_SESSION_CREATED_COMMAND", "echo ok")
	t.Setenv("VKTURN_EXEC_TIMEOUT", "nope")
	if _, err := LoadCommandDispatcherFromEnv(); err == nil || !strings.Contains(err.Error(), "VKTURN_EXEC_TIMEOUT") {
		t.Fatalf("expected timeout validation error, got %v", err)
	}
}

func TestRenderWebhookTemplate(t *testing.T) {
	snapshot := WebhookSnapshot{
		Event:               WebhookEventSessionUpdated,
		Status:              webhookStatusActive,
		SessionID:           "sess",
		PublicKey:           "pub",
		ClientPublicIP:      "1.2.3.4",
		RelayIPs:            []string{"10.0.0.1", "10.0.0.2"},
		ActiveStreams:       2,
		PersistentKeepalive: 25,
		LastSeenUnix:        10,
		LastChangeUnix:      11,
		TsUnix:              12,
	}
	rendered := renderWebhookTemplate(`{"event":"${event}","relay":"${relay_ips_csv}","pk":"${public_key}"}`, snapshot)
	want := `{"event":"session_updated","relay":"10.0.0.1,10.0.0.2","pk":"pub"}`
	if rendered != want {
		t.Fatalf("unexpected template render: %s", rendered)
	}
}

func TestBuildWebhookRequestValidation(t *testing.T) {
	snapshot := WebhookSnapshot{Event: WebhookEventSessionCreated, SessionID: "abc", Status: webhookStatusActive}
	req, err := buildWebhookRequest(WebhookConfig{
		Event:    WebhookEventSessionCreated,
		Method:   http.MethodPost,
		URL:      "https://example.com/hook",
		Template: `{"session":"${session_id}"}`,
	}, snapshot)
	if err != nil {
		t.Fatalf("build post request: %v", err)
	}
	body, _ := io.ReadAll(req.Body)
	if string(body) != `{"session":"abc"}` {
		t.Fatalf("unexpected post body: %s", body)
	}

	req, err = buildWebhookRequest(WebhookConfig{
		Event:    WebhookEventSessionCreated,
		Method:   http.MethodGet,
		URL:      "https://example.com/hook",
		Template: "?session=${session_id}",
	}, snapshot)
	if err != nil {
		t.Fatalf("build get request: %v", err)
	}
	if req.URL.String() != "https://example.com/hook?session=abc" {
		t.Fatalf("unexpected get url: %s", req.URL.String())
	}
}

func TestClassifyInitialClientPacket(t *testing.T) {
	now := time.Unix(123, 456)

	v2Packet := append(bytes.Repeat([]byte{0xab}, 16), 7)
	v2 := classifyInitialClientPacket(v2Packet, now)
	if v2.Protocol != protocolProxyV2 {
		t.Fatalf("expected %s, got %s", protocolProxyV2, v2.Protocol)
	}
	if v2.StreamID != 7 {
		t.Fatalf("unexpected stream id: %d", v2.StreamID)
	}
	if v2.SessionID != strings.Repeat("ab", 16) {
		t.Fatalf("unexpected session id: %s", v2.SessionID)
	}
	if len(v2.FirstData) != 0 {
		t.Fatalf("expected no first data for v2 packet")
	}

	v1Packet := []byte{1, 2, 3, 4, 5}
	v1 := classifyInitialClientPacket(v1Packet, now)
	if v1.Protocol != protocolProxyV1 {
		t.Fatalf("expected %s, got %s", protocolProxyV1, v1.Protocol)
	}
	if v1.SessionID != "v1-123000000456" {
		t.Fatalf("unexpected legacy session id: %s", v1.SessionID)
	}
	if !bytes.Equal(v1.FirstData, v1Packet) {
		t.Fatalf("unexpected first data clone: %v", v1.FirstData)
	}
}

func TestLifecycleEmissionDecisions(t *testing.T) {
	sink := newRecordingWebhookSink()
	manager := newTestSessionManager(sink)
	backendAddr, closeBackend := newUDPBackend(t)
	defer closeBackend()

	session, _, err := manager.GetOrCreate(context.Background(), "session-1", protocolProxyV2Meta, backendAddr)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	session.AddConn(1, left)
	manager.EmitLifecycleEvent(WebhookEventSessionCreated, session.ID, webhookStatusActive, -1)
	if sink.count(WebhookEventSessionCreated) != 1 {
		t.Fatalf("expected session_created event")
	}

	meta := ClientMeta{
		PublicKey:      "pub1",
		ClientPublicIP: "1.2.3.4",
		RelayIP:        "5.6.7.8",
		KeepaliveSec:   25,
	}
	manager.UpsertClientMeta(session.ID, meta)
	if sink.count(WebhookEventSessionUpdated) != 1 {
		t.Fatalf("expected first session_updated event")
	}

	manager.UpsertClientMeta(session.ID, meta)
	if sink.count(WebhookEventSessionUpdated) != 1 {
		t.Fatalf("expected no duplicate session_updated event")
	}

	meta.ClientPublicIP = "9.9.9.9"
	manager.UpsertClientMeta(session.ID, meta)
	if sink.count(WebhookEventSessionUpdated) != 2 {
		t.Fatalf("expected updated session_updated event")
	}

	session.RemoveConn(1, left)
	if sink.count(WebhookEventSessionIdle) != 1 {
		t.Fatalf("expected session_idle event")
	}

	manager.Lock.Lock()
	session.NoConnSince = time.Now().Add(-2 * time.Minute)
	manager.Lock.Unlock()
	manager.gcOnce()
	if sink.count(WebhookEventSessionExpired) != 1 {
		t.Fatalf("expected session_expired event")
	}

	session2, _, err := manager.GetOrCreate(context.Background(), "session-2", protocolProxyV2Meta, backendAddr)
	if err != nil {
		t.Fatalf("GetOrCreate session2: %v", err)
	}
	left2, right2 := net.Pipe()
	defer left2.Close()
	defer right2.Close()
	session2.AddConn(1, left2)
	manager.UpsertClientMeta(session2.ID, ClientMeta{
		PublicKey:      "pub2",
		ClientPublicIP: "4.3.2.1",
		RelayIP:        "8.8.8.8",
	})
	session2.Cleanup()
	if sink.count(WebhookEventSessionClosed) != 1 {
		t.Fatalf("expected session_closed event")
	}
}

func TestOnlyMetaSessionsEmitLifecycle(t *testing.T) {
	sink := newRecordingWebhookSink()
	manager := newTestSessionManager(sink)
	backendAddr, closeBackend := newUDPBackend(t)
	defer closeBackend()

	session, _, err := manager.GetOrCreate(context.Background(), "session-v2", protocolProxyV2, backendAddr)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	session.AddConn(1, left)
	manager.EmitLifecycleEvent(WebhookEventSessionCreated, session.ID, webhookStatusActive, -1)
	if sink.count(WebhookEventSessionCreated) != 0 {
		t.Fatalf("expected no lifecycle events for non-meta session")
	}

	manager.UpsertClientMeta(session.ID, ClientMeta{
		PublicKey:      "pubmeta",
		ClientPublicIP: "1.1.1.1",
		RelayIP:        "2.2.2.2",
		KeepaliveSec:   25,
	})
	if sink.count(WebhookEventSessionCreated) != 1 {
		t.Fatalf("expected session_created after meta promotion")
	}
	if sink.count(WebhookEventSessionUpdated) != 1 {
		t.Fatalf("expected session_updated after meta promotion")
	}
}

func TestWebhookDispatcherPostAndGet(t *testing.T) {
	var received struct {
		method string
		path   string
		body   string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received.method = r.Method
		received.path = r.URL.RequestURI()
		received.body = string(body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	dispatcher := &WebhookDispatcher{
		client: &http.Client{Timeout: time.Second},
		configs: map[WebhookEvent]WebhookConfig{
			WebhookEventSessionCreated: {
				Event:    WebhookEventSessionCreated,
				Method:   http.MethodPost,
				URL:      server.URL + "/post",
				Template: `{"session":"${session_id}"}`,
			},
			WebhookEventSessionIdle: {
				Event:    WebhookEventSessionIdle,
				Method:   http.MethodGet,
				URL:      server.URL + "/get",
				Template: "?status=${status}",
			},
		},
		queue: make(chan webhookJob, 4),
	}
	dispatcher.wg.Add(1)
	go dispatcher.worker()

	dispatcher.Emit(WebhookEventSessionCreated, WebhookSnapshot{Event: WebhookEventSessionCreated, SessionID: "abc", Status: webhookStatusActive})
	dispatcher.Emit(WebhookEventSessionIdle, WebhookSnapshot{Event: WebhookEventSessionIdle, SessionID: "abc", Status: webhookStatusIdle})
	dispatcher.Close()

	if received.method == "" {
		t.Fatalf("expected request to be received")
	}
}

func TestCommandDispatcherRunsCommand(t *testing.T) {
	outFile := t.TempDir() + "/command.out"
	t.Setenv("OUTFILE", outFile)

	dispatcher := &CommandDispatcher{
		shell:   "/bin/sh",
		timeout: time.Second,
		configs: map[WebhookEvent]CommandConfig{
			WebhookEventSessionCreated: {
				Event:   WebhookEventSessionCreated,
				Command: `printf '%s|%s' '${session_id}' "$VKTURN_STATUS" > "$OUTFILE"`,
			},
		},
		queue: make(chan commandJob, 1),
	}
	dispatcher.wg.Add(1)
	go dispatcher.worker()

	dispatcher.Emit(WebhookEventSessionCreated, WebhookSnapshot{
		Event:     WebhookEventSessionCreated,
		SessionID: "abc",
		Status:    webhookStatusActive,
	})
	dispatcher.Close()

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if string(data) != "abc|active" {
		t.Fatalf("unexpected command output: %q", string(data))
	}
}

func TestWebhookDispatcherTLSAndFailureLogging(t *testing.T) {
	snippetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failed badly", http.StatusBadGateway)
	}))
	defer snippetServer.Close()

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer tlsServer.Close()

	var logs bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)

	dispatcher := &WebhookDispatcher{
		client: &http.Client{Timeout: time.Second},
	}
	dispatcher.deliver(webhookJob{
		config:   WebhookConfig{Event: WebhookEventSessionUpdated, Method: http.MethodPost, URL: snippetServer.URL, Template: `{"ok":true}`},
		snapshot: WebhookSnapshot{Event: WebhookEventSessionUpdated, SessionID: "x", Status: webhookStatusActive},
	})
	if !strings.Contains(logs.String(), "502") || !strings.Contains(logs.String(), "upstream failed badly") {
		t.Fatalf("expected non-2xx log, got %s", logs.String())
	}

	logs.Reset()
	dispatcher.client = tlsServer.Client()
	dispatcher.client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	dispatcher.deliver(webhookJob{
		config:   WebhookConfig{Event: WebhookEventSessionUpdated, Method: http.MethodGet, URL: tlsServer.URL, Template: ""},
		snapshot: WebhookSnapshot{Event: WebhookEventSessionUpdated, SessionID: "x", Status: webhookStatusActive},
	})
	if logs.Len() == 0 {
		t.Fatalf("expected tls failure log")
	}

	logs.Reset()
	dispatcher.client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	dispatcher.deliver(webhookJob{
		config:   WebhookConfig{Event: WebhookEventSessionUpdated, Method: http.MethodGet, URL: tlsServer.URL, Template: ""},
		snapshot: WebhookSnapshot{Event: WebhookEventSessionUpdated, SessionID: "x", Status: webhookStatusActive},
	})
	if !strings.Contains(logs.String(), "200") && !strings.Contains(logs.String(), "204") {
		t.Fatalf("expected successful tls-disabled log, got %s", logs.String())
	}
}

func newTestSessionManager(sink WebhookSink) *SessionManager {
	return &SessionManager{
		Sessions:        make(map[string]*UserSession),
		SessionToPublic: make(map[string]string),
		ClientStates:    make(map[string]ClientState),
		InactiveGrace:   30 * time.Second,
		Webhooks:        sink,
	}
}

func newUDPBackend(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 256)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return
			}
			if _, _, err := conn.ReadFrom(buf); err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					select {
					case <-done:
						return
					default:
					}
					continue
				}
				return
			}
		}
	}()
	return conn.LocalAddr().String(), func() {
		_ = conn.Close()
	}
}

func TestMain(m *testing.M) {
	log.SetFlags(0)
	os.Exit(m.Run())
}
