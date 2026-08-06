package pipeline

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Chunk headers (Fase 2 §2 step 4).
const (
	HeaderChunkSequence = "Chunk-Sequence"
	HeaderIsFinalChunk  = "Is-Final-Chunk"
)

// DefaultChunkSize follows Fase 2 §2's "exactamente 512 KB o 1 MB", picking
// the smaller end: NATS' own default max_payload is 1 MiB, and a chunk's
// on-wire size includes headers on top of the payload, so a full 1 MiB
// payload would need a larger-than-default max_payload configured on the
// broker to always fit.
const DefaultChunkSize = 512 * 1024

// chunkFetchTimeout bounds how long the receiver waits for the next chunk
// before giving up — analogous to (but independent of) Fase 1's handshake
// timeout; a slow sender legitimately needs more room than a handshake
// round trip does.
const chunkFetchTimeout = 30 * time.Second

// PublishArchive reads r in chunkSize blocks (DefaultChunkSize if <= 0) and
// publishes each as a JetStream message on subject, tagged with
// Chunk-Sequence and Is-Final-Chunk (Fase 2 §2).
func PublishArchive(ctx context.Context, js jetstream.JetStream, subject string, r io.Reader, chunkSize int) error {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	buf := make([]byte, chunkSize)
	seq := 0
	for {
		n, readErr := io.ReadFull(r, buf)
		if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
			return fmt.Errorf("pipeline: read chunk %d: %w", seq, readErr)
		}
		isFinal := readErr == io.EOF || readErr == io.ErrUnexpectedEOF

		msg := &natsgo.Msg{
			Subject: subject,
			Data:    append([]byte(nil), buf[:n]...),
			Header:  natsgo.Header{},
		}
		msg.Header.Set(HeaderChunkSequence, strconv.Itoa(seq))
		msg.Header.Set(HeaderIsFinalChunk, strconv.FormatBool(isFinal))

		if _, err := js.PublishMsg(ctx, msg); err != nil {
			return fmt.Errorf("pipeline: publish chunk %d: %w", seq, err)
		}
		if isFinal {
			return nil
		}
		seq++
	}
}

// ReceiveArchive pulls chunks from cons in order and streams their payload
// out through the returned io.ReadCloser, one chunk at a time, until the
// Is-Final-Chunk message. The done channel receives exactly one value (nil
// on a clean finish) once the background goroutine driving this exits.
//
// A chunk is Ack'd right after its bytes are handed to the pipe, not after
// whatever's downstream (gzip/tar extraction, Fase 2 §4) has durably
// written the corresponding file bytes to disk — those are different
// granularities (a chunk boundary rarely lines up with a tar entry
// boundary) and reconciling them exactly is deferred; see Fase 4
// "Manejo de Errores" for the coarser, session-level recovery this backs
// onto today (sandbox kept intact for a grace period, full re-send on
// reconnect) rather than sub-session chunk replay.
func ReceiveArchive(ctx context.Context, cons jetstream.Consumer) (io.ReadCloser, <-chan error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)

	go func() {
		err := receiveLoop(ctx, cons, pw)
		pw.CloseWithError(err)
		done <- err
	}()

	return pr, done
}

func receiveLoop(ctx context.Context, cons jetstream.Consumer, pw *io.PipeWriter) error {
	wantSeq := 0
	for {
		batch, err := cons.Fetch(1, jetstream.FetchMaxWait(chunkFetchTimeout))
		if err != nil {
			return fmt.Errorf("pipeline: fetch chunk %d: %w", wantSeq, err)
		}

		gotAny := false
		for msg := range batch.Messages() {
			gotAny = true

			seq, err := strconv.Atoi(msg.Headers().Get(HeaderChunkSequence))
			if err != nil {
				_ = msg.Nak()
				return fmt.Errorf("pipeline: chunk missing/invalid %s header: %w", HeaderChunkSequence, err)
			}
			if seq != wantSeq {
				_ = msg.Nak()
				return fmt.Errorf("pipeline: chunk out of order: got %d, want %d", seq, wantSeq)
			}
			isFinal := msg.Headers().Get(HeaderIsFinalChunk) == "true"

			if _, err := pw.Write(msg.Data()); err != nil {
				_ = msg.Nak()
				return fmt.Errorf("pipeline: write chunk %d to pipe: %w", seq, err)
			}
			if err := msg.Ack(); err != nil {
				return fmt.Errorf("pipeline: ack chunk %d: %w", seq, err)
			}
			wantSeq++
			if isFinal {
				return nil
			}
		}
		if batchErr := batch.Error(); batchErr != nil {
			return fmt.Errorf("pipeline: fetch chunk %d batch: %w", wantSeq, batchErr)
		}
		if !gotAny {
			return fmt.Errorf("pipeline: no chunk arrived within %s (wanted sequence %d)", chunkFetchTimeout, wantSeq)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
	}
}
