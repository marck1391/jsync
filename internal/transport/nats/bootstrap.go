package nats

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	natsgo "github.com/nats-io/nats.go"
)

// Role is a node's network role (Fase 1 §1).
type Role int

const (
	// RoleHub embeds and owns the broker: it enables a Leaf Node listener
	// so Peers can attach to it.
	RoleHub Role = iota
	// RolePeer embeds a server that reaches out to a Hub's Leaf Node
	// listener instead of accepting inbound connections — its traffic
	// only ever leaves outbound, so it works behind a firewall that
	// blocks inbound connections the way SSH/SCP would need.
	RolePeer
)

// Config configures Bootstrap.
type Config struct {
	Role Role

	// Host/Port are where this node's embedded server listens for plain
	// client connections (its own internal/progress, internal/handshake,
	// etc. all connect here). Port 0 picks a random free port.
	Host string
	Port int

	// LeafNodePort is where a Hub listens for incoming Leaf Node
	// connections. Ignored for RolePeer. 0 picks a random free port —
	// deterministic only if the caller can hand the resulting
	// Node.LeafNodeURL() to Peers some other way (out-of-band config,
	// service discovery); pin an explicit port for a stable deployment
	// URL instead.
	LeafNodePort int

	// HubLeafNodeURL is the Hub's leafnode listener a Peer connects out
	// to, e.g. "nats-leaf://hub-host:7422". Required for RolePeer.
	HubLeafNodeURL string

	// JetStreamStoreDir, if empty, uses the OS temp dir — fine for tests
	// and short-lived nodes, but a real long-running deployment should
	// set a stable path so streams survive a restart.
	JetStreamStoreDir string

	// Debug enables the embedded server's own stderr logging (connect/
	// disconnect, leafnode routing, errors). Off by default so tests stay
	// quiet; turn on when diagnosing connectivity issues between nodes.
	Debug bool
}

// Node is a running embedded NATS server plus a client connection to it —
// what Fase 1 §1 calls a Leaf Node (RolePeer) or the broker itself
// (RoleHub).
type Node struct {
	// Conn is this node's own client connection to its embedded server —
	// internal/handshake, internal/pipeline, and internal/syncfs all
	// publish/subscribe through it.
	Conn *natsgo.Conn

	server       *server.Server
	leafNodeHost string
	leafNodePort int
}

// ClientURL returns the URL this node's embedded server accepts plain
// client connections on.
func (n *Node) ClientURL() string {
	return n.server.ClientURL()
}

// LeafNodeURL returns the URL a Peer's Config.HubLeafNodeURL should point
// at. Only meaningful for a Node bootstrapped with RoleHub.
func (n *Node) LeafNodeURL() string {
	return fmt.Sprintf("nats-leaf://%s:%d", n.leafNodeHost, n.leafNodePort)
}

// Close immediately closes the client connection and shuts the embedded
// server down, with no regard for in-flight replies. Fine for tests and
// abrupt teardown; a running daemon reacting to SIGTERM/SIGINT should use
// Drain instead (Fase 4 "Apagado Ordenado").
func (n *Node) Close() {
	if n.Conn != nil {
		n.Conn.Close()
	}
	if n.server != nil {
		n.server.Shutdown()
		n.server.WaitForShutdown()
	}
}

// Drain lets in-flight NATS replies finish (Fase 4 "Apagado Ordenado") before
// tearing the node down: subscriptions stop accepting new work immediately,
// but a request already dispatched to a handler gets to call msg.Respond()
// and have it actually leave the socket before the connection closes. This
// is what a running daemon should call on SIGTERM/SIGINT — Close is for
// tests and abrupt teardown only.
//
// nc.Drain() itself is asynchronous (it self-enforces nats.Conn's own
// DrainTimeout internally and closes the connection when done), so this
// polls IsClosed() up to timeout and then shuts the embedded server down
// regardless — best-effort, not a hard guarantee draining finished.
func (n *Node) Drain(timeout time.Duration) error {
	if n.Conn != nil {
		if err := n.Conn.Drain(); err != nil {
			return fmt.Errorf("nats: drain client connection: %w", err)
		}
		deadline := time.Now().Add(timeout)
		for !n.Conn.IsClosed() && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if n.server != nil {
		n.server.Shutdown()
		n.server.WaitForShutdown()
	}
	return nil
}

// readyTimeout bounds how long Bootstrap waits for the embedded server to
// accept connections before giving up.
const readyTimeout = 10 * time.Second

// Bootstrap starts a node's embedded NATS server per Fase 1 §1 and returns
// a ready client connection to it. RoleHub enables a Leaf Node listener for
// Peers to attach to; RolePeer instead configures a Leaf Node remote
// pointing at Config.HubLeafNodeURL.
func Bootstrap(cfg Config) (*Node, error) {
	host := cfg.Host
	if host == "" {
		host = "127.0.0.1"
	}

	// server.Options.Port follows the NATS server's own convention, not
	// this package's: 0 means "the default port, 4222", not "pick a
	// random one" — that's -1. Config.Port documents 0 as "random", so it
	// has to be translated here or two embedded servers in the same
	// process (Hub + Peer, exactly what the tests do) both try to bind
	// :4222 and the second one fails.
	clientPort := cfg.Port
	if clientPort == 0 {
		clientPort = -1
	}

	opts := &server.Options{
		Host:      host,
		Port:      clientPort,
		JetStream: true,
		StoreDir:  cfg.JetStreamStoreDir,
		NoLog:     !cfg.Debug,
		Debug:     cfg.Debug,
		Trace:     cfg.Debug,
		NoSigs:    true,
	}

	node := &Node{}

	switch cfg.Role {
	case RoleHub:
		leafPort := cfg.LeafNodePort
		if leafPort == 0 {
			p, err := freeTCPPort()
			if err != nil {
				return nil, fmt.Errorf("nats: pick leafnode port: %w", err)
			}
			leafPort = p
		}
		opts.LeafNode = server.LeafNodeOpts{Host: host, Port: leafPort}
		node.leafNodeHost = host
		node.leafNodePort = leafPort

	case RolePeer:
		if cfg.HubLeafNodeURL == "" {
			return nil, fmt.Errorf("nats: RolePeer requires Config.HubLeafNodeURL")
		}
		remote, err := url.Parse(cfg.HubLeafNodeURL)
		if err != nil {
			return nil, fmt.Errorf("nats: parse HubLeafNodeURL %q: %w", cfg.HubLeafNodeURL, err)
		}
		opts.LeafNode = server.LeafNodeOpts{
			Remotes: []*server.RemoteLeafOpts{{URLs: []*url.URL{remote}}},
		}

	default:
		return nil, fmt.Errorf("nats: unknown role %d", cfg.Role)
	}

	srv, err := server.NewServer(opts)
	if err != nil {
		return nil, fmt.Errorf("nats: create embedded server: %w", err)
	}
	if cfg.Debug {
		srv.ConfigureLogger()
	}

	go srv.Start()
	if !srv.ReadyForConnections(readyTimeout) {
		return nil, fmt.Errorf("nats: embedded server did not become ready within %s", readyTimeout)
	}

	conn, err := natsgo.Connect(srv.ClientURL())
	if err != nil {
		srv.Shutdown()
		return nil, fmt.Errorf("nats: connect local client: %w", err)
	}

	node.Conn = conn
	node.server = srv
	return node, nil
}

// freeTCPPort asks the OS for a free TCP port by binding to port 0 and
// reading back what it picked. Race-prone in theory (the port could be
// taken between Close and reuse) but standard practice for test/ephemeral
// bootstrap and good enough here — server.NewServer will simply fail loudly
// if it loses the race, it won't corrupt anything.
func freeTCPPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
