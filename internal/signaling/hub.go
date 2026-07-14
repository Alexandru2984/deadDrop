package signaling

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"sync"
)

const (
	// Mesh group rooms: every pair of peers gets its own WebRTC channel and its
	// own end-to-end session, so bandwidth (and file fan-out) grows with N² —
	// keep rooms small. The server still only relays opaque signaling.
	MaxPeersPerRoom            = 6
	MaxRooms                   = 128
	MaxConnections             = 256
	MaxConnectionsPerPrincipal = 8
	RoomCodeHexLen             = 24 // 96-bit ephemeral rendezvous capability
	PeerIDHexLen               = 32 // 128-bit connection identifier
)

// Hub manages chat rooms and routes signaling messages between peers.
// Uses channels instead of mutexes for idiomatic Go concurrency.
type Hub struct {
	rooms          map[string]*Room
	register       chan *registerRequest
	unregister     chan *unregisterRequest
	relay          chan *relayRequest
	slots          chan struct{}
	slotMu         sync.Mutex
	principalSlots map[string]int
}

type Room struct {
	Code  string
	Peers map[string]*Peer
}

type registerRequest struct {
	code     string
	peer     *Peer
	response chan *Room
	err      chan error
}

type unregisterRequest struct {
	peer *Peer
	done chan struct{}
}

// relayRequest routes a message to a target peer within a room, safely.
type relayRequest struct {
	from     *Peer
	targetID string
	data     []byte
	response chan bool
}

func NewHub() *Hub {
	return &Hub{
		rooms:          make(map[string]*Room),
		register:       make(chan *registerRequest),
		unregister:     make(chan *unregisterRequest),
		relay:          make(chan *relayRequest),
		slots:          make(chan struct{}, MaxConnections),
		principalSlots: make(map[string]int),
	}
}

func (h *Hub) reserveConnection(principal string) bool {
	if principal != "" {
		h.slotMu.Lock()
		if h.principalSlots[principal] >= MaxConnectionsPerPrincipal {
			h.slotMu.Unlock()
			return false
		}
		h.principalSlots[principal]++
		h.slotMu.Unlock()
	}
	select {
	case h.slots <- struct{}{}:
		return true
	default:
		if principal != "" {
			h.releasePrincipal(principal)
		}
		return false
	}
}

func (h *Hub) releaseConnection(principal string) {
	select {
	case <-h.slots:
		if principal != "" {
			h.releasePrincipal(principal)
		}
	default:
		log.Printf("[hub] connection slot accounting underflow")
	}
}

func (h *Hub) releasePrincipal(principal string) {
	h.slotMu.Lock()
	if count := h.principalSlots[principal]; count <= 1 {
		delete(h.principalSlots, principal)
	} else {
		h.principalSlots[principal] = count - 1
	}
	h.slotMu.Unlock()
}

// Run is the Hub's main event loop — all room state mutations happen here,
// so no locks are needed.
func (h *Hub) Run() {
	for {
		select {
		case req := <-h.register:
			if req.peer == nil || !ValidateRoomCode(req.code) {
				req.response <- nil
				req.err <- fmt.Errorf("invalid room code")
				continue
			}

			oldRoom := req.peer.room
			if oldRoom != nil && oldRoom.Code == req.code && oldRoom.Peers[req.peer.ID] == req.peer {
				// Duplicate joins are idempotent; they must not generate a fake
				// peer-left/peer-joined cycle for every member of the room.
				req.response <- oldRoom
				req.err <- nil
				continue
			}

			room, exists := h.rooms[req.code]
			if exists {
				if existing := room.Peers[req.peer.ID]; existing != nil && existing != req.peer {
					req.response <- nil
					req.err <- fmt.Errorf("peer identifier collision")
					continue
				}
				if len(room.Peers) >= MaxPeersPerRoom {
					req.response <- nil
					req.err <- fmt.Errorf("room is full")
					continue
				}
			} else {
				effectiveRooms := len(h.rooms)
				if oldRoom != nil && len(oldRoom.Peers) == 1 && oldRoom.Peers[req.peer.ID] == req.peer {
					effectiveRooms-- // moving will remove the peer's empty old room
				}
				if effectiveRooms >= MaxRooms {
					req.response <- nil
					req.err <- fmt.Errorf("server room limit reached")
					continue
				}
			}

			// Destination validation succeeded, so moving is atomic from the
			// client's perspective: a failed join never ejects it from its old room.
			if oldRoom != nil {
				h.removeFromRoom(req.peer, true)
			}
			if !exists {
				room = &Room{
					Code:  req.code,
					Peers: make(map[string]*Peer),
				}
				h.rooms[req.code] = room
			}
			room.Peers[req.peer.ID] = req.peer
			req.peer.room = room

			// Notify existing peers about the newcomer, and vice versa
			// Done here in the Hub goroutine where room.Peers is safe to read.
			newPeerMsg, _ := json.Marshal(SignalMessage{Type: "peer-joined", PeerID: req.peer.ID})
			for _, other := range room.Peers {
				if other.ID == req.peer.ID {
					continue
				}
				if !safeSend(other.send, newPeerMsg) {
					other.terminate()
					continue
				}
				existingMsg, _ := json.Marshal(SignalMessage{Type: "peer-joined", PeerID: other.ID})
				if !safeSend(req.peer.send, existingMsg) {
					req.peer.terminate()
				}
			}

			req.response <- room
			req.err <- nil

		case req := <-h.unregister:
			h.removeFromRoom(req.peer, true)
			close(req.done)

		case req := <-h.relay:
			delivered := false
			if req.from != nil {
				room := req.from.room
				if room != nil && req.targetID != req.from.ID && room.Peers[req.from.ID] == req.from {
					if target, ok := room.Peers[req.targetID]; ok {
						delivered = safeSend(target.send, req.data)
						if !delivered {
							// A producer must not be able to disconnect a healthy
							// target merely by bursting enough relay messages to
							// fill its queue. Its later peer-left event restores
							// consistent room state for the target.
							req.from.terminate()
						}
					}
				}
			}
			req.response <- delivered
		}
	}
}

// removeFromRoom is called only from Run, which owns all room membership state.
func (h *Hub) removeFromRoom(peer *Peer, notify bool) {
	if peer == nil || peer.room == nil {
		return
	}
	room := peer.room
	peer.room = nil // invalidate first so queued relays cannot use a stale room
	if room.Peers[peer.ID] != peer {
		return
	}
	delete(room.Peers, peer.ID)
	if notify {
		leftMsg, _ := json.Marshal(SignalMessage{Type: "peer-left", PeerID: peer.ID})
		for _, other := range room.Peers {
			if !safeSend(other.send, leftMsg) {
				other.terminate()
			}
		}
	}
	if len(room.Peers) == 0 {
		delete(h.rooms, room.Code)
	}
}

// JoinRoom adds a peer to a room (creates if needed). Thread-safe via channel.
// Peer notifications are now sent from the Hub goroutine (no race).
// Returns an error if the room is full or the server hit its room limit.
func (h *Hub) JoinRoom(code string, peer *Peer) (*Room, error) {
	resp := make(chan *Room, 1)
	errCh := make(chan error, 1)
	h.register <- &registerRequest{code: code, peer: peer, response: resp, err: errCh}
	room := <-resp
	err := <-errCh
	return room, err
}

// RemovePeer removes a peer from their room and notifies others. Thread-safe via channel.
// Blocks until removal is complete to ensure send channel is closed after.
func (h *Hub) RemovePeer(peer *Peer) {
	done := make(chan struct{})
	h.unregister <- &unregisterRequest{peer: peer, done: done}
	<-done
}

// Relay routes a signaling message to a target peer within the sender's room.
// Thread-safe via channel — avoids reading room.Peers from the readPump goroutine.
func (h *Hub) Relay(from *Peer, targetID string, data []byte) bool {
	response := make(chan bool, 1)
	h.relay <- &relayRequest{from: from, targetID: targetID, data: data, response: response}
	return <-response
}

func GenerateRoomCode() (string, error) {
	b := make([]byte, RoomCodeHexLen/2)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateRoomCode accepts only server-generated 96-bit lowercase hex codes.
func ValidateRoomCode(code string) bool {
	if len(code) != RoomCodeHexLen {
		return false
	}
	return isLowerHex(code)
}

// ValidatePeerID checks server-generated peer identifiers.
func ValidatePeerID(id string) bool {
	if len(id) != PeerIDHexLen {
		return false
	}
	return isLowerHex(id)
}

func isLowerHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
