package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

type streamEntry struct {
	id   byte
	conn net.Conn
}

type UserSession struct {
	ID          string
	Protocol    string
	Conns       []streamEntry
	BackendConn net.Conn
	Lock        sync.RWMutex
	Ctx         context.Context
	Cancel      context.CancelFunc
	Manager     *SessionManager
	LastSeen    time.Time
	NoConnSince time.Time
}

type SessionManager struct {
	Sessions          map[string]*UserSession
	SessionToPublic   map[string]string
	ClientStates      map[string]ClientState
	StateFilePath     string
	InactiveGrace     time.Duration
	Webhooks          WebhookSink
	lastWrittenDigest []byte
	Lock              sync.RWMutex
}

const (
	protocolProxyV1     = "proxy_v1"
	protocolProxyV2     = "proxy_v2"
	protocolProxyV2Meta = "proxy_v2_meta"
)

type initialClientPacket struct {
	Protocol  string
	SessionID string
	StreamID  byte
	FirstData []byte
}

func classifyInitialClientPacket(data []byte, now time.Time) initialClientPacket {
	if len(data) == 17 {
		return initialClientPacket{
			Protocol:  protocolProxyV2,
			SessionID: fmt.Sprintf("%x", data[:16]),
			StreamID:  data[16],
		}
	}

	return initialClientPacket{
		Protocol:  protocolProxyV1,
		SessionID: fmt.Sprintf("v1-%d", now.UnixNano()),
		StreamID:  0,
		FirstData: append([]byte(nil), data...),
	}
}

func (s *SessionManager) GetOrCreate(ctx context.Context, id string, protocol string, connectAddr string) (*UserSession, bool, error) {
	s.Lock.Lock()
	defer s.Lock.Unlock()

	if session, ok := s.Sessions[id]; ok {
		if session.Protocol == "" {
			session.Protocol = protocol
		}
		return session, false, nil
	}

	backendConn, err := net.Dial("udp", connectAddr)
	if err != nil {
		return nil, false, err
	}

	sessionCtx, cancel := context.WithCancel(ctx)
	session := &UserSession{
		ID:          id,
		Protocol:    protocol,
		Conns:       make([]streamEntry, 0),
		BackendConn: backendConn,
		Manager:     s,
		Ctx:         sessionCtx,
		Cancel:      cancel,
		LastSeen:    time.Now(),
	}
	s.Sessions[id] = session
	go session.backendReaderLoop()

	return session, true, nil
}

func (s *UserSession) backendReaderLoop() {
	defer s.Cleanup()
	buf := make([]byte, 1600)
	var lastUsed uint32 = 0
	for {
		select {
		case <-s.Ctx.Done():
			return
		default:
		}

		s.BackendConn.SetReadDeadline(time.Now().Add(time.Minute * 5))
		n, err := s.BackendConn.Read(buf)
		if err != nil {
			log.Printf("Session %s backend read error: %v", s.ID, err)
			return
		}

		s.Lock.RLock()
		nConns := uint32(len(s.Conns))
		if nConns == 0 {
			s.Lock.RUnlock()
			continue
		}

		// Fast Round-robin selection using local variable
		lastUsed = (lastUsed + 1) % nConns
		conn := s.Conns[lastUsed].conn
		s.Lock.RUnlock()

		conn.SetWriteDeadline(time.Now().Add(time.Second * 10))

		_, err = conn.Write(buf[:n])
		if err != nil {
			log.Printf("Session %s DTLS write error: %v", s.ID, err)
			conn.Close()
		}
	}
}

func (s *UserSession) AddConn(id byte, conn net.Conn) {
	s.Lock.Lock()
	defer s.Lock.Unlock()
	s.LastSeen = time.Now()
	s.NoConnSince = time.Time{}

	// Evict existing connection with same ID
	for i, entry := range s.Conns {
		if entry.id == id {
			//log.Printf("Session %s: Evicting old stream %d", s.ID, id)
			entry.conn.Close()
			s.Conns[i].conn = conn
			return
		}
	}

	s.Conns = append(s.Conns, streamEntry{id: id, conn: conn})
}

func (s *UserSession) RemoveConn(id byte, conn net.Conn) {
	becameIdle := false
	s.Lock.Lock()
	for i, entry := range s.Conns {
		if entry.id == id && entry.conn == conn {
			s.Conns = append(s.Conns[:i], s.Conns[i+1:]...)
			s.LastSeen = time.Now()
			if len(s.Conns) == 0 {
				s.NoConnSince = time.Now()
				becameIdle = true
			}
			break
		}
	}
	s.Lock.Unlock()

	if becameIdle {
		s.Manager.EmitLifecycleEvent(WebhookEventSessionIdle, s.ID, webhookStatusIdle, 0)
	}
}

func (s *UserSession) touch() {
	s.Lock.Lock()
	s.LastSeen = time.Now()
	s.Lock.Unlock()
}

func (s *UserSession) Cleanup() {
	s.Cancel()
	s.BackendConn.Close()

	s.Manager.Lock.Lock()
	closeSnapshot, closeEvent := s.Manager.snapshotForSessionLocked(s.ID, WebhookEventSessionClosed, webhookStatusClosed, 0)
	delete(s.Manager.Sessions, s.ID)
	stateChanged := s.Manager.removeClientStateBySessionLocked(s.ID)
	if stateChanged {
		s.Manager.persistClientStatesLocked()
	}
	s.Manager.Lock.Unlock()

	s.Lock.Lock()
	for _, entry := range s.Conns {
		entry.conn.Close()
	}
	s.Conns = nil
	s.Lock.Unlock()

	if closeEvent {
		s.Manager.Webhooks.Emit(WebhookEventSessionClosed, closeSnapshot)
	}
}
func main() {
	listen := flag.String("listen", "0.0.0.0:56000", "listen on ip:port")
	connect := flag.String("connect", "", "connect to ip:port")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-signalChan
		log.Printf("Terminating...\n")
		cancel()
		<-signalChan
		log.Fatalf("Exit...\n")
	}()

	addr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		panic(err)
	}
	if len(*connect) == 0 {
		log.Panicf("server address is required")
	}

	certificate, genErr := selfsign.GenerateSelfSigned()
	if genErr != nil {
		panic(genErr)
	}

	config := &dtls.Config{
		Certificates:          []tls.Certificate{certificate},
		ExtendedMasterSecret:  dtls.RequireExtendedMasterSecret,
		CipherSuites:          []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.RandomCIDGenerator(8),
	}

	listener, err := dtls.Listen("udp", addr, config)
	if err != nil {
		panic(err)
	}
	context.AfterFunc(ctx, func() {
		listener.Close()
	})

	manager := &SessionManager{
		Sessions:        make(map[string]*UserSession),
		SessionToPublic: make(map[string]string),
		ClientStates:    make(map[string]ClientState),
		StateFilePath:   strings.TrimSpace(os.Getenv("VKTURN_STATE_JSON")),
		InactiveGrace:   90 * time.Second,
	}
	if rawGrace := strings.TrimSpace(os.Getenv("VKTURN_STATE_INACTIVE_GRACE")); rawGrace != "" {
		parsedGrace, parseErr := time.ParseDuration(rawGrace)
		if parseErr != nil {
			log.Printf("Invalid VKTURN_STATE_INACTIVE_GRACE=%q: %v (using default %s)", rawGrace, parseErr, manager.InactiveGrace)
		} else {
			manager.InactiveGrace = parsedGrace
		}
	}
	webhooks, err := LoadWebhookDispatcherFromEnv()
	if err != nil {
		log.Fatalf("Webhook config error: %v", err)
	}
	commands, err := LoadCommandDispatcherFromEnv()
	if err != nil {
		log.Fatalf("Command config error: %v", err)
	}
	switch {
	case webhooks != nil && commands != nil:
		manager.Webhooks = &sinkGroup{sinks: []WebhookSink{webhooks, commands}}
	case webhooks != nil:
		manager.Webhooks = webhooks
	case commands != nil:
		manager.Webhooks = commands
	}
	if manager.Webhooks != nil {
		defer manager.Webhooks.Close()
	}
	if manager.StateFilePath != "" {
		log.Printf("Client state export enabled: %s (inactive grace %s)", manager.StateFilePath, manager.InactiveGrace)
		go manager.gcLoop(ctx)
	} else if manager.Webhooks != nil {
		log.Printf("Client state export disabled; lifecycle exports enabled")
		go manager.gcLoop(ctx)
	} else {
		log.Printf("Client state export disabled (set VKTURN_STATE_JSON to enable)")
	}

	log.Printf("Listening on %s, forwarding to %s", *listen, *connect)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Println("Accept error:", err)
				continue
			}
		}

		go func(conn net.Conn) {
			defer conn.Close()

			dtlsConn, ok := conn.(*dtls.Conn)
			if !ok {
				return
			}

			handshakeCtx, hCancel := context.WithTimeout(ctx, 30*time.Second)
			defer hCancel()

			if err := dtlsConn.HandshakeContext(handshakeCtx); err != nil {
				log.Println("Handshake failed:", err)
				return
			}

			firstPacket := make([]byte, 1600)
			conn.SetReadDeadline(time.Now().Add(time.Second * 5))
			n, err := conn.Read(firstPacket)
			if err != nil {
				log.Println("Failed to read initial client packet:", err)
				return
			}
			conn.SetReadDeadline(time.Time{})

			packet := classifyInitialClientPacket(firstPacket[:n], time.Now())
			if packet.Protocol == protocolProxyV2 {
				log.Printf("Accepted %s stream %d for session %s from %s", packet.Protocol, packet.StreamID, packet.SessionID, conn.RemoteAddr())
			} else {
				log.Printf("Accepted %s legacy stream from %s (%d initial bytes)", packet.Protocol, conn.RemoteAddr(), n)
			}

			session, _, err := manager.GetOrCreate(ctx, packet.SessionID, packet.Protocol, *connect)
			if err != nil {
				log.Println("Failed to get/create session:", err)
				return
			}

			session.AddConn(packet.StreamID, conn)
			defer session.RemoveConn(packet.StreamID, conn)

			firstData := packet.FirstData
			if packet.Protocol != protocolProxyV1 {
				meta, packetData, err := readOptionalClientMeta(conn)
				if err != nil {
					log.Printf("Session %s read optional metadata error: %v", packet.SessionID, err)
					return
				}
				firstData = packetData
				if meta != nil {
					manager.UpsertClientMeta(packet.SessionID, *meta)
				}
			}

			// Upstream Loop: DTLS -> Backend
			buf := make([]byte, 1600)
			if len(firstData) > 0 {
				session.touch()
				session.BackendConn.SetWriteDeadline(time.Now().Add(time.Second * 5))
				if _, err := session.BackendConn.Write(firstData); err != nil {
					log.Printf("Session %s backend write error on first packet: %v", packet.SessionID, err)
					return
				}
			}
			for {
				conn.SetReadDeadline(time.Now().Add(time.Minute * 5))
				n, err := conn.Read(buf)
				if err != nil {
					log.Printf("Stream %s closed: %v", packet.SessionID, err)
					return
				}
				session.touch()

				if meta, rest, ok := extractClientMetaFrame(buf[:n]); ok {
					manager.UpsertClientMeta(packet.SessionID, meta)
					if len(rest) == 0 {
						continue
					}
					copy(buf, rest)
					n = len(rest)
				}

				session.BackendConn.SetWriteDeadline(time.Now().Add(time.Second * 5))
				_, err = session.BackendConn.Write(buf[:n])
				if err != nil {
					log.Printf("Session %s backend write error: %v", packet.SessionID, err)
					return
				}
			}
		}(conn)
	}
}
