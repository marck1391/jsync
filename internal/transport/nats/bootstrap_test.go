package nats

import (
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
)

func bootstrapHub(t *testing.T) *Node {
	t.Helper()
	hub, err := Bootstrap(Config{
		Role:              RoleHub,
		Port:              0,
		LeafNodePort:      0,
		JetStreamStoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Bootstrap(RoleHub): %v", err)
	}
	t.Cleanup(hub.Close)
	return hub
}

func TestBootstrapHubClientConnectionWorks(t *testing.T) {
	hub := bootstrapHub(t)

	if !hub.Conn.IsConnected() {
		t.Fatal("hub.Conn: expected IsConnected() to be true")
	}

	received := make(chan []byte, 1)
	sub, err := hub.Conn.Subscribe("test.subject", func(msg *natsgo.Msg) {
		received <- msg.Data
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer sub.Unsubscribe()

	if err := hub.Conn.Publish("test.subject", []byte("hello")); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if err := hub.Conn.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	select {
	case data := <-received:
		if string(data) != "hello" {
			t.Errorf("received %q, want %q", data, "hello")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for local pub/sub round trip")
	}
}

func TestBootstrapPeerReachesHubOverLeafNode(t *testing.T) {
	hub := bootstrapHub(t)

	peer, err := Bootstrap(Config{
		Role:              RolePeer,
		Port:              0,
		HubLeafNodeURL:    hub.LeafNodeURL(),
		JetStreamStoreDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Bootstrap(RolePeer): %v", err)
	}
	defer peer.Close()

	// Subscribe on the Hub, publish from the Peer: this only succeeds if
	// the Peer's outbound Leaf Node link is actually federating subjects
	// to the Hub, not just running an isolated local server.
	received := make(chan []byte, 1)
	sub, err := hub.Conn.Subscribe("leaf.roundtrip", func(msg *natsgo.Msg) {
		received <- msg.Data
	})
	if err != nil {
		t.Fatalf("Subscribe on hub: %v", err)
	}
	defer sub.Unsubscribe()
	if err := hub.Conn.Flush(); err != nil {
		t.Fatalf("Flush hub subscription: %v", err)
	}

	// The leaf link takes a moment to establish after Bootstrap returns,
	// so retry the publish instead of relying on a single fixed sleep.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := peer.Conn.Publish("leaf.roundtrip", []byte("via-leaf")); err != nil {
			t.Fatalf("Publish from peer: %v", err)
		}
		peer.Conn.Flush()

		select {
		case data := <-received:
			if string(data) != "via-leaf" {
				t.Fatalf("received %q, want %q", data, "via-leaf")
			}
			return
		case <-time.After(100 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for a message to cross the leaf node link")
			}
		}
	}
}
