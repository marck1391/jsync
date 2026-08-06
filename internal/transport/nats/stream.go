package nats

import (
	"context"
	"fmt"
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
	return "FILESHARE_" + sessionID
}
