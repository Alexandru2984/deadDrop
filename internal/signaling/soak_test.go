package signaling

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A signaling server is a long-running process holding one goroutine pair and
// one map entry per live connection. Whether it survives a crowd matters far
// less than whether it lets go afterwards: a room, a principal reservation or a
// goroutine retained per session is invisible on a test that runs six peers, and
// fatal after a week of uptime. Nothing here had ever been measured.
//
// So this runs a realistic crowd through the hub and then asks the only question
// that predicts week-two: is everything back to where it started?

// waitFor polls until cond holds, so a slow machine reports a real leak rather
// than a scheduling delay.
func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return cond()
}

func TestHubReleasesEverythingAfterALoad(t *testing.T) {
	if testing.Short() {
		t.Skip("soak test: skipped under -short")
	}

	hub := NewHub()
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		HandleWebSocket(hub, w, r, alwaysValidAccess)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"

	// Let the hub's own goroutines settle before taking the baseline, or their
	// startup gets counted as a leak.
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()
	baseRooms := hub.Snapshot().Rooms

	const (
		rooms        = 100
		peersPerRoom = 2
	)

	// Sample while the crowd is connected. Without this the whole test could pass
	// on a hub that never accepted anyone: everything would be back to baseline
	// because nothing ever left it.
	peak := make(chan Stats, 1)
	stopSampling := make(chan struct{})
	go func() {
		best := Stats{}
		for {
			select {
			case <-stopSampling:
				peak <- best
				return
			default:
			}
			if now := hub.Snapshot(); now.Peers > best.Peers {
				best = now
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	failures := make(chan string, rooms*peersPerRoom)

	for i := 0; i < rooms; i++ {
		// Room codes are 24 hex characters; give each room its own.
		code := fmt.Sprintf("%024x", i)
		for p := 0; p < peersPerRoom; p++ {
			wg.Add(1)
			go func(code string) {
				defer wg.Done()
				conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
				if err != nil {
					failures <- "dial: " + err.Error()
					return
				}
				defer conn.Close()

				_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
				var welcome SignalMessage
				if err := conn.ReadJSON(&welcome); err != nil || welcome.Type != "welcome" {
					failures <- fmt.Sprintf("welcome: %v (%+v)", err, welcome)
					return
				}
				if err := conn.WriteJSON(SignalMessage{Type: "join", Room: code}); err != nil {
					failures <- "join: " + err.Error()
					return
				}
				// Stay long enough for both members to be in the room together,
				// so peer-joined traffic and per-room state actually get built.
				time.Sleep(300 * time.Millisecond)
			}(code)
		}
	}

	wg.Wait()
	close(stopSampling)
	close(failures)

	busiest := <-peak
	t.Logf("peak: %d rooms, %d peers; goroutines %d → %d",
		busiest.Rooms, busiest.Peers, baseGoroutines, runtime.NumGoroutine())
	// Peers overlap rather than arriving in lockstep, so the peak is a fraction
	// of the total; requiring most of it would only make the test flaky.
	if busiest.Rooms < rooms/4 {
		t.Errorf("the hub never got busy: peak was %d rooms of %d — this test proved nothing",
			busiest.Rooms, rooms)
	}

	var reported int
	for msg := range failures {
		if reported < 5 {
			t.Errorf("peer failed: %s", msg)
		}
		reported++
	}
	if reported > 5 {
		t.Errorf("... and %d more peer failures", reported-5)
	}

	// Every connection is closed now. The hub must have unwound with them.
	if !waitFor(func() bool { return hub.Snapshot().Rooms == baseRooms }, 15*time.Second) {
		t.Errorf("rooms leaked: %d before, %d after %d sessions",
			baseRooms, hub.Snapshot().Rooms, rooms*peersPerRoom)
	}

	// Goroutines drain slightly behind the sockets, and the test's own dialers
	// leave the pool warm, so allow a small margin — a per-session leak would be
	// hundreds, not a handful.
	const slack = 20
	leaked := func() bool {
		runtime.GC()
		return runtime.NumGoroutine() <= baseGoroutines+slack
	}
	if !waitFor(leaked, 20*time.Second) {
		t.Errorf("goroutines leaked: %d before, %d after %d sessions (allowing %d)",
			baseGoroutines, runtime.NumGoroutine(), rooms*peersPerRoom, slack)
	}

	// A hub that released its bookkeeping must still be usable, not merely empty.
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("hub refuses new connections after the load: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var welcome SignalMessage
	if err := conn.ReadJSON(&welcome); err != nil || welcome.Type != "welcome" {
		t.Fatalf("hub unhealthy after the load: %v (%+v)", err, welcome)
	}
}
