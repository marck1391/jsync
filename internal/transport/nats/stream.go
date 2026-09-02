package nats

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// streamMaxAge is an outer safety net matching handshake.SessionTTL: even
// if a receiver crashes without ever consuming the backlog, the stream
// (and the RAM it holds) doesn't outlive the session it belongs to.
const streamMaxAge = 30 * time.Minute

// consumerName is fixed rather than generated: each session's stream has
// exactly one intended reader (Fase 2 is a single ordered pipe, not
// Fase 5's partitioned lanes), so there is nothing to disambiguate.
const consumerName = "receiver"

// EnsureStream creates (or reuses) the JetStream stream backing a Fase 2
// transfer for sessionID. WorkQueuePolicy means each chunk disappears once
// the single receiver acks it — matching Fase 2 §3: "NATS no almacena el
// archivo a largo plazo; funciona como un búfer circular de paso" —  and
// MemoryStorage means none of it is meant to survive a broker restart.
func EnsureStream(ctx context.Context, js jetstream.JetStream, sessionID string) (jetstream.Stream, error) {
	name := StreamName(sessionID)
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      name,
		Subjects:  []string{StreamSubject(sessionID)},
		Storage:   jetstream.MemoryStorage,
		Retention: jetstream.WorkQueuePolicy,
		MaxAge:    streamMaxAge,
	})
	if err != nil {
		return nil, fmt.Errorf("nats: create stream %s: %w", name, err)
	}
	return stream, nil
}

// EnsureStreamConsumer creates (or reuses) the single pull consumer a Fase
// 2 receiver reads from. MaxAckPending: 1 enforces the strict in-order,
// one-chunk-in-flight processing Fase 4 §Paso 3 describes for a single
// transfer — unlike Fase 5's partitioned lanes, there's only one file tree
// in flight here, so there's nothing to gain from more parallelism and
// real correctness to lose (a chunk must never be written before the one
// before it).
func EnsureStreamConsumer(ctx context.Context, js jetstream.JetStream, sessionID string) (jetstream.Consumer, error) {
	cons, err := js.CreateOrUpdateConsumer(ctx, StreamName(sessionID), jetstream.ConsumerConfig{
		Durable:       consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("nats: create consumer for session %s: %w", sessionID, err)
	}
	return cons, nil
}

// StreamName is the JetStream stream name for sessionID's Fase 2 transfer.
func StreamName(sessionID string) string {
	return "JSYNC_" + sessionID
}

// EnsureEventsStream creates (or reuses) the JetStream stream backing a
// Fase 5 Watcher session for sessionID. Unlike EnsureStream's Fase 2
// stream, this uses LimitsPolicy rather than WorkQueuePolicy: a Watcher
// session is bidirectional, with each side running its own independent
// durable consumer over the same stream (EnsureEventsConsumer) — a
// WorkQueue stream rejects a second consumer whose filter subject overlaps
// an existing one, since its whole purpose is guaranteeing only one
// logical reader ever exists, which is exactly wrong here.
func EnsureEventsStream(ctx context.Context, js jetstream.JetStream, sessionID string) (jetstream.Stream, error) {
	name := EventsStreamName(sessionID)
	stream, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      name,
		Subjects:  []string{EventsSubject(sessionID)},
		Storage:   jetstream.MemoryStorage,
		Retention: jetstream.LimitsPolicy,
		MaxAge:    streamMaxAge,
	})
	if err != nil {
		return nil, fmt.Errorf("nats: create events stream %s: %w", name, err)
	}
	return stream, nil
}

// EnsureEventsConsumer creates (or reuses) a durable consumer named for
// consumerName (typically the local node's machine_id, sanitized) on
// sessionID's events stream — each side of a bidirectional Watcher session
// needs its own independent read position over the shared stream.
// MaxAckPending: 1 keeps strict per-session order for now; Fase 5's
// hash(RelPath)-partitioned lanes (for throughput under heavy concurrent
// edits) are a documented follow-up, not implemented here.
func EnsureEventsConsumer(ctx context.Context, js jetstream.JetStream, sessionID, consumerName string) (jetstream.Consumer, error) {
	name := sanitizeConsumerName(consumerName)
	cons, err := js.CreateOrUpdateConsumer(ctx, EventsStreamName(sessionID), jetstream.ConsumerConfig{
		Durable:       name,
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxAckPending: 1,
	})
	if err != nil {
		return nil, fmt.Errorf("nats: create events consumer %s for session %s: %w", name, sessionID, err)
	}
	return cons, nil
}

// EventsStreamName is the JetStream stream name for sessionID's Fase 5
// Watcher session.
func EventsStreamName(sessionID string) string {
	return "JSYNC_EVENTS_" + sessionID
}

// sanitizeConsumerName replaces characters NATS durable consumer names
// disallow (whitespace, '.', '*', '>', path separators) with '_'. A
// machine_id built from os.Hostname() (identity.NewMachineID) could in
// principle contain any of these — Windows in particular allows spaces in
// computer names.
func sanitizeConsumerName(name string) string {
	return consumerNameReplacer.Replace(name)
}

var consumerNameReplacer = strings.NewReplacer(
	" ", "_", "\t", "_", "\n", "_",
	".", "_", "*", "_", ">", "_",
	"/", "_", "\\", "_",
)
