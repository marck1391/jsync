package syncfs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/marck1391/jsync/internal/crypto/ratchet"
)

// Encryption bundles what PublishChanges/ReceiveChanges need to run a Fase
// 5 Watcher session's events through two independent Double Ratchet chains
// (Fase 3) — a nil *Encryption means unencrypted, exactly like
// pipeline.Encryption's role for Fase 2. Unlike pipeline.Encryption, there
// are two chains, not one: a Watcher session is bidirectional (both nodes
// publish and consume the same events subject), so encrypting with a
// single shared chain would mean two nodes' concurrent local Encrypt calls
// could derive the identical message key and nonce for two unrelated
// messages — a catastrophic AES-GCM nonce reuse. SendChain and RecvChain
// are cryptographically independent (see cmd/jsync and
// internal/daemon's WatchSession for how they're derived — this package
// only ever consumes already-derived chains, the same split Fase 2's
// pipeline package keeps from x3dh.Store).
type Encryption struct {
	SendChain      *ratchet.Chain
	RecvChain      *ratchet.Chain
	AssociatedData []byte
}

// PublishBootstrap publishes the initiator's X3DH bootstrap message —
// must be the very first message this node publishes on subject, before
// its own Watcher starts producing real Events, so the responder can never
// observe an encrypted Event before it has a chain to decrypt with (same
// principle as Fase 2's chunk 0 carrying the Bootstrap-* headers).
func PublishBootstrap(ctx context.Context, js jetstream.JetStream, subject, machineID string, initiatorDHPub, ephemeralPub []byte, usedOTPID uint32) error {
	return publish(ctx, js, subject, Event{
		Origin:                  machineID,
		Op:                      OpBootstrap,
		BootstrapInitiatorDHPub: initiatorDHPub,
		BootstrapEphemeralPub:   ephemeralPub,
		BootstrapUsedOTPID:      usedOTPID,
	})
}

// PublishBootstrapAck publishes the responder's half of the bootstrap
// dance — its own fresh ephemeral public key, which the initiator needs to
// derive its receiving chain (see the package doc on Encryption for why
// this can't just reuse the X3DH-derived chain both directions). Like
// PublishBootstrap, must go out before this node's own Watcher starts.
func PublishBootstrapAck(ctx context.Context, js jetstream.JetStream, subject, machineID string, ephemeralPub []byte) error {
	return publish(ctx, js, subject, Event{
		Origin:                machineID,
		Op:                    OpBootstrapAck,
		BootstrapEphemeralPub: ephemeralPub,
	})
}

// ReceiveBootstrap blocks (until ctx is done) fetching from cons until it
// sees peerMachineID's OpBootstrap message, acks it, and returns its
// material. Must be called — and must return — before this node starts its
// own Watcher or the general ReceiveChanges loop; at this point in a
// session's life the only messages that can legitimately appear on the
// stream are this node's own not-yet-published nothing and the peer's
// OpBootstrap, so anything else is treated as a protocol error rather than
// silently skipped.
func ReceiveBootstrap(ctx context.Context, cons jetstream.Consumer, peerMachineID string) (initiatorDHPub, ephemeralPub []byte, usedOTPID uint32, err error) {
	ev, err := awaitControl(ctx, cons, peerMachineID, OpBootstrap)
	if err != nil {
		return nil, nil, 0, err
	}
	return ev.BootstrapInitiatorDHPub, ev.BootstrapEphemeralPub, ev.BootstrapUsedOTPID, nil
}

// ReceiveBootstrapAck is ReceiveBootstrap's mirror on the initiator side:
// blocks until peerMachineID's OpBootstrapAck arrives, skipping over this
// node's own OpBootstrap message being echoed back to its own consumer
// (same Origin-based skip ReceiveChanges' general loop uses).
func ReceiveBootstrapAck(ctx context.Context, cons jetstream.Consumer, peerMachineID string) (ephemeralPub []byte, err error) {
	ev, err := awaitControl(ctx, cons, peerMachineID, OpBootstrapAck)
	if err != nil {
		return nil, err
	}
	return ev.BootstrapEphemeralPub, nil
}

// awaitControl fetches from cons, acking and discarding this node's own
// echoed-back messages, until it finds one from peerMachineID. That
// message must carry wantOp — anything else from the peer this early in
// the session (before either side's Watcher has started) means the two
// sides have desynced on the bootstrap protocol, which is treated as fatal
// rather than silently skipped.
func awaitControl(ctx context.Context, cons jetstream.Consumer, peerMachineID string, wantOp Op) (Event, error) {
	for {
		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		default:
		}

		batch, err := cons.Fetch(1, jetstream.FetchMaxWait(eventFetchTimeout))
		if err != nil {
			return Event{}, fmt.Errorf("syncfs: fetch bootstrap message: %w", err)
		}

		for msg := range batch.Messages() {
			var ev Event
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				_ = msg.Nak()
				continue
			}

			if ev.Origin != peerMachineID {
				_ = msg.Ack() // our own echoed-back message — not what we're waiting for
				continue
			}
			if ev.Op != wantOp {
				_ = msg.Nak()
				return Event{}, fmt.Errorf("syncfs: expected %s from %s during bootstrap, got %s", wantOp, peerMachineID, ev.Op)
			}
			if err := msg.Ack(); err != nil {
				return Event{}, fmt.Errorf("syncfs: ack bootstrap message: %w", err)
			}
			return ev, nil
		}
		if batchErr := batch.Error(); batchErr != nil {
			return Event{}, fmt.Errorf("syncfs: fetch bootstrap message batch: %w", batchErr)
		}
	}
}
