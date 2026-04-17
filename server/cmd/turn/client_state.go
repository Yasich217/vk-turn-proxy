package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"
)

var (
	metaMagic           = [4]byte{'W', 'G', 'T', 'M'}
	metaVersion    byte = 1
	metaTypeClient byte = 1
	metaReadWindow      = 300 * time.Millisecond
)

type ClientMeta struct {
	PublicKey      string `json:"public_key"`
	SessionID      string `json:"session_id"`
	ClientPublicIP string `json:"client_public_ip,omitempty"`
	RelayIP        string `json:"relay_ip"`
	StreamID       byte   `json:"stream_id"`
	KeepaliveSec   int    `json:"persistent_keepalive"`
	TsUnix         int64  `json:"ts_unix"`
}

type ClientState struct {
	PublicKey      string   `json:"public_key"`
	SessionID      string   `json:"session_id"`
	ClientPublicIP string   `json:"client_public_ip"`
	RelayIPs       []string `json:"relay_ips"`
	KeepaliveSec   int      `json:"persistent_keepalive"`
	LastSeenUnix   int64    `json:"last_seen_unix"`
	LastChangeUnix int64    `json:"last_change_unix"`
}

type clientStateFile struct {
	UpdatedAtUnix int64                  `json:"updated_at_unix"`
	Clients       map[string]ClientState `json:"clients"`
}

func (s *SessionManager) trackingEnabled() bool {
	return s.StateFilePath != "" || s.Webhooks != nil
}

func readOptionalClientMeta(conn net.Conn) (*ClientMeta, []byte, error) {
	buf := make([]byte, 1600)
	conn.SetReadDeadline(time.Now().Add(metaReadWindow))
	n, err := conn.Read(buf)
	if err != nil {
		if e, ok := err.(net.Error); ok && e.Timeout() {
			conn.SetReadDeadline(time.Time{})
			return nil, nil, nil
		}
		return nil, nil, err
	}
	conn.SetReadDeadline(time.Time{})

	if meta, rest, ok := extractClientMetaFrame(buf[:n]); ok {
		return &meta, rest, nil
	}
	return nil, slices.Clone(buf[:n]), nil
}

func extractClientMetaFrame(data []byte) (ClientMeta, []byte, bool) {
	var meta ClientMeta
	if len(data) < 8 {
		return meta, nil, false
	}
	if !bytes.Equal(data[:4], metaMagic[:]) {
		return meta, nil, false
	}
	if data[4] != metaVersion || data[5] != metaTypeClient {
		return meta, nil, false
	}
	payloadLen := int(binary.BigEndian.Uint16(data[6:8]))
	frameLen := 8 + payloadLen
	if payloadLen <= 0 || len(data) < frameLen {
		return meta, nil, false
	}
	if err := json.Unmarshal(data[8:frameLen], &meta); err != nil {
		return meta, nil, false
	}
	if meta.PublicKey == "" || meta.SessionID == "" {
		return meta, nil, false
	}
	rest := slices.Clone(data[frameLen:])
	return meta, rest, true
}

func (s *SessionManager) UpsertClientMeta(sessionID string, meta ClientMeta) {
	if !s.trackingEnabled() {
		return
	}
	now := time.Now().Unix()
	var createdSnapshot WebhookSnapshot
	var snapshot WebhookSnapshot
	var emitCreated bool
	var emitUpdated bool

	s.Lock.Lock()

	if session, ok := s.Sessions[sessionID]; ok && session.Protocol != protocolProxyV2Meta {
		log.Printf("Session %s protocol promoted: %s -> %s", sessionID, session.Protocol, protocolProxyV2Meta)
		session.Protocol = protocolProxyV2Meta
		createdSnapshot, emitCreated = s.snapshotForSessionLocked(sessionID, WebhookEventSessionCreated, webhookStatusActive, -1)
	}

	meta.SessionID = sessionID
	s.SessionToPublic[sessionID] = meta.PublicKey

	state, exists := s.ClientStates[meta.PublicKey]
	changed := false

	if !exists {
		state = ClientState{
			PublicKey:      meta.PublicKey,
			SessionID:      sessionID,
			ClientPublicIP: meta.ClientPublicIP,
			RelayIPs:       make([]string, 0, 1),
			KeepaliveSec:   meta.KeepaliveSec,
			LastSeenUnix:   now,
			LastChangeUnix: now,
		}
		changed = true
	}

	if state.SessionID != sessionID {
		state.SessionID = sessionID
		changed = true
		if meta.ClientPublicIP != "" {
			if state.ClientPublicIP != meta.ClientPublicIP {
				state.ClientPublicIP = meta.ClientPublicIP
				changed = true
			}
		} else if state.ClientPublicIP != "" {
			state.ClientPublicIP = ""
			changed = true
		}
	}
	if meta.ClientPublicIP != "" && state.ClientPublicIP != meta.ClientPublicIP {
		state.ClientPublicIP = meta.ClientPublicIP
		changed = true
	}
	if meta.RelayIP != "" && !slices.Contains(state.RelayIPs, meta.RelayIP) {
		state.RelayIPs = append(state.RelayIPs, meta.RelayIP)
		slices.Sort(state.RelayIPs)
		changed = true
	}
	if meta.KeepaliveSec > 0 && state.KeepaliveSec != meta.KeepaliveSec {
		state.KeepaliveSec = meta.KeepaliveSec
		changed = true
	}

	state.LastSeenUnix = now
	if changed {
		state.LastChangeUnix = now
		log.Printf("State update for public key %s (session=%s)", meta.PublicKey, sessionID)
	}
	s.ClientStates[meta.PublicKey] = state

	if changed {
		snapshot, emitUpdated = s.snapshotForSessionLocked(sessionID, WebhookEventSessionUpdated, webhookStatusActive, -1)
		s.persistClientStatesLocked()
	}
	s.Lock.Unlock()

	if emitCreated {
		s.Webhooks.Emit(WebhookEventSessionCreated, createdSnapshot)
	}
	if emitUpdated {
		s.Webhooks.Emit(WebhookEventSessionUpdated, snapshot)
	}
}

func (s *SessionManager) removeClientStateBySessionLocked(sessionID string) bool {
	if !s.trackingEnabled() {
		return false
	}
	publicKey, ok := s.SessionToPublic[sessionID]
	if !ok {
		return false
	}
	delete(s.SessionToPublic, sessionID)

	state, ok := s.ClientStates[publicKey]
	if !ok {
		return false
	}
	if state.SessionID != sessionID {
		return false
	}
	delete(s.ClientStates, publicKey)
	log.Printf("State removed for public key %s (session=%s)", publicKey, sessionID)
	return true
}

func (s *SessionManager) gcLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.gcOnce()
		}
	}
}

func (s *SessionManager) gcOnce() {
	if !s.trackingEnabled() {
		return
	}
	now := time.Now()
	var expiredSnapshots []WebhookSnapshot
	s.Lock.Lock()

	changed := false
	for sessionID := range s.SessionToPublic {
		session, exists := s.Sessions[sessionID]
		if !exists {
			if s.removeClientStateBySessionLocked(sessionID) {
				changed = true
			}
			continue
		}

		session.Lock.RLock()
		noConnSince := session.NoConnSince
		session.Lock.RUnlock()

		grace := s.InactiveGrace
		if publicKey, ok := s.SessionToPublic[sessionID]; ok {
			if st, ok := s.ClientStates[publicKey]; ok && st.KeepaliveSec > 0 {
				// If peer keepalive is configured, remove the state after a few missed intervals.
				// This makes json lifecycle track real connectivity tighter than a fixed grace.
				grace = time.Duration(st.KeepaliveSec*3) * time.Second
				if grace < 30*time.Second {
					grace = 30 * time.Second
				}
			}
		}

		if noConnSince.IsZero() || now.Sub(noConnSince) < grace {
			continue
		}
		if snapshot, ok := s.snapshotForSessionLocked(sessionID, WebhookEventSessionExpired, webhookStatusExpired, 0); ok {
			expiredSnapshots = append(expiredSnapshots, snapshot)
		}
		if s.removeClientStateBySessionLocked(sessionID) {
			changed = true
		}
	}

	if changed {
		s.persistClientStatesLocked()
	}
	s.Lock.Unlock()

	for _, snapshot := range expiredSnapshots {
		s.Webhooks.Emit(WebhookEventSessionExpired, snapshot)
	}
}

func (s *SessionManager) persistClientStatesLocked() {
	if s.StateFilePath == "" {
		return
	}
	state := clientStateFile{
		UpdatedAtUnix: time.Now().Unix(),
		Clients:       make(map[string]ClientState, len(s.ClientStates)),
	}
	for publicKey, clientState := range s.ClientStates {
		state.Clients[publicKey] = clientState
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		log.Printf("State marshal error: %v", err)
		return
	}
	sum := sha256.Sum256(data)
	if bytes.Equal(s.lastWrittenDigest, sum[:]) {
		return
	}

	if err := os.MkdirAll(filepath.Dir(s.StateFilePath), 0o755); err != nil {
		log.Printf("State mkdir error: %v", err)
		return
	}

	tmpPath := s.StateFilePath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
		log.Printf("State write temp error: %v", err)
		return
	}
	if err := os.Rename(tmpPath, s.StateFilePath); err != nil {
		log.Printf("State rename error: %v", err)
		return
	}
	s.lastWrittenDigest = slices.Clone(sum[:])
}

func (s *SessionManager) EmitLifecycleEvent(event WebhookEvent, sessionID string, status string, activeStreamsOverride int) {
	if s.Webhooks == nil {
		return
	}
	s.Lock.Lock()
	snapshot, ok := s.snapshotForSessionLocked(sessionID, event, status, activeStreamsOverride)
	s.Lock.Unlock()
	if ok {
		s.Webhooks.Emit(event, snapshot)
	}
}

func (s *SessionManager) snapshotForSessionLocked(sessionID string, event WebhookEvent, status string, activeStreamsOverride int) (WebhookSnapshot, bool) {
	if s.Webhooks == nil {
		return WebhookSnapshot{}, false
	}
	session, ok := s.Sessions[sessionID]
	if !ok || session.Protocol != protocolProxyV2Meta {
		return WebhookSnapshot{}, false
	}

	snapshot := WebhookSnapshot{
		Event:         event,
		Status:        status,
		SessionID:     sessionID,
		RelayIPs:      []string{},
		TsUnix:        time.Now().Unix(),
		ActiveStreams: 0,
	}

	if activeStreamsOverride >= 0 {
		snapshot.ActiveStreams = activeStreamsOverride
	} else {
		session.Lock.RLock()
		snapshot.ActiveStreams = len(session.Conns)
		session.Lock.RUnlock()
	}

	if publicKey, ok := s.SessionToPublic[sessionID]; ok {
		snapshot.PublicKey = publicKey
		if state, ok := s.ClientStates[publicKey]; ok {
			snapshot.ClientPublicIP = state.ClientPublicIP
			snapshot.RelayIPs = slices.Clone(state.RelayIPs)
			snapshot.PersistentKeepalive = state.KeepaliveSec
			snapshot.LastSeenUnix = state.LastSeenUnix
			snapshot.LastChangeUnix = state.LastChangeUnix
		}
	}

	return snapshot, true
}

func mustWriteControlFrame(w io.Writer, meta ClientMeta) error {
	payload, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	if len(payload) > 0xFFFF {
		return errors.New("control payload too large")
	}

	frame := make([]byte, 8+len(payload))
	copy(frame[:4], metaMagic[:])
	frame[4] = metaVersion
	frame[5] = metaTypeClient
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(payload)))
	copy(frame[8:], payload)

	_, err = w.Write(frame)
	return err
}
