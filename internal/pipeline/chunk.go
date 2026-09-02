package pipeline

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/marck1391/jsync/internal/crypto/ratchet"
)

// Chunk headers (Fase 2 §2 step 4). The four Bootstrap* headers only ever
// ride chunk 0, carrying Fase 3's X3DH bootstrap material so the receiver
// can derive a matching ratchet.Chain without an extra round trip.
const (
	HeaderChunkSequence = "Chunk-Sequence"
	HeaderIsFinalChunk  = "Is-Final-Chunk"

	HeaderEncrypted          = "Encrypted"
	HeaderBootstrapDHPub     = "Bootstrap-Initiator-Dh-Pub"
	HeaderBootstrapEphemeral = "Bootstrap-Ephemeral-Pub"
	HeaderBootstrapOTPID     = "Bootstrap-Used-Otp-Id"

	// HeaderTotalBytes only ever rides chunk 0, carrying EstimateSendSize's
	// upfront (uncompressed, approximate) total — Fase 2 progress
	// reporting. Absent or "0" means unknown, not zero-length.
	HeaderTotalBytes = "Total-Bytes"
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

// EncryptionBootstrap is what the initiator attaches to chunk 0 so the
// responder can derive a matching ratchet.Chain (Fase 3).
type EncryptionBootstrap struct {
	InitiatorDHPub *ecdh.PublicKey
	EphemeralPub   *ecdh.PublicKey
	UsedOTPID      uint32
}

// Encryption bundles what PublishArchive needs to run a transfer through a
// Fase 3 Double Ratchet chain. A nil *Encryption means unencrypted — chunks
// travel as plaintext exactly as before Fase 3 existed.
type Encryption struct {
	Chain          *ratchet.Chain
	AssociatedData []byte
	Bootstrap      EncryptionBootstrap
}

// PublishArchive reads r in chunkSize blocks (DefaultChunkSize if <= 0) and
// publishes each as a JetStream message on subject, tagged with
// Chunk-Sequence and Is-Final-Chunk (Fase 2 §2). If enc is non-nil, each
// chunk is encrypted with enc.Chain before publishing (Fase 3), and chunk 0
// additionally carries enc.Bootstrap as headers. totalBytes, if > 0, rides
// chunk 0 as HeaderTotalBytes for the receiver's progress reporting — pass
// 0 if unknown (EstimateSendSize failed, or the caller doesn't care).
func PublishArchive(ctx context.Context, js jetstream.JetStream, subject string, r io.Reader, chunkSize int, enc *Encryption, totalBytes int64) error {
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

		payload := buf[:n]
		msg := &natsgo.Msg{Subject: subject, Header: natsgo.Header{}}

		if enc != nil {
			ciphertext, chainSeq, err := enc.Chain.Encrypt(payload, enc.AssociatedData)
			if err != nil {
				return fmt.Errorf("pipeline: encrypt chunk %d: %w", seq, err)
			}
			if int(chainSeq) != seq {
				return fmt.Errorf("pipeline: internal error: ratchet sequence %d diverged from chunk sequence %d", chainSeq, seq)
			}
			msg.Data = ciphertext
			msg.Header.Set(HeaderEncrypted, "true")
			if seq == 0 {
				setBootstrapHeaders(msg.Header, enc.Bootstrap)
			}
		} else {
			msg.Data = append([]byte(nil), payload...)
		}

		msg.Header.Set(HeaderChunkSequence, strconv.Itoa(seq))
		msg.Header.Set(HeaderIsFinalChunk, strconv.FormatBool(isFinal))
		if seq == 0 && totalBytes > 0 {
			msg.Header.Set(HeaderTotalBytes, strconv.FormatInt(totalBytes, 10))
		}

		if _, err := js.PublishMsg(ctx, msg); err != nil {
			return fmt.Errorf("pipeline: publish chunk %d: %w", seq, err)
		}
		if isFinal {
			return nil
		}
		seq++
	}
}

func setBootstrapHeaders(h natsgo.Header, b EncryptionBootstrap) {
	h.Set(HeaderBootstrapDHPub, base64.StdEncoding.EncodeToString(b.InitiatorDHPub.Bytes()))
	h.Set(HeaderBootstrapEphemeral, base64.StdEncoding.EncodeToString(b.EphemeralPub.Bytes()))
	h.Set(HeaderBootstrapOTPID, strconv.FormatUint(uint64(b.UsedOTPID), 10))
}

// DeriveChainFunc derives the receiving side's ratchet.Chain from chunk 0's
// bootstrap headers (Fase 3) — a callback rather than a direct dependency
// on x3dh.Store so this package doesn't need to import x3dh; the usual
// implementation is a thin wrapper around Store.DeriveResponderChain.
type DeriveChainFunc func(initiatorDHPub, ephemeralPub *ecdh.PublicKey, usedOTPID uint32) (*ratchet.Chain, error)

// ReceiveArchive pulls chunks from cons in order and streams their
// (decrypted, if encrypted) payload out through the returned
// io.ReadCloser, one chunk at a time, until the Is-Final-Chunk message.
// The done channel receives exactly one value (nil on a clean finish) once
// the background goroutine driving this exits.
//
// deriveChain may be nil (the session is never encrypted — Fase 2 as it
// existed before Fase 3). If non-nil, it's consulted only if chunk 0
// actually carries an Encrypted: true header, so the same call works for
// both encrypted and plaintext transfers without the caller needing to
// know in advance which one is arriving. associatedData is ignored when
// the transfer turns out to be unencrypted.
//
// A chunk is Ack'd right after its bytes are handed to the pipe, not after
// whatever's downstream (gzip/tar extraction, Fase 2 §4) has durably
// written the corresponding file bytes to disk — those are different
// granularities (a chunk boundary rarely lines up with a tar entry
// boundary) and reconciling them exactly is deferred; see Fase 4
// "Manejo de Errores" for the coarser, session-level recovery this backs
// onto today (sandbox kept intact for a grace period, full re-send on
// reconnect) rather than sub-session chunk replay.
//
// onTotalBytes, if non-nil, is called at most once, when chunk 0 arrives,
// with whatever HeaderTotalBytes carried (0 if the header was absent —
// the sender's PublishArchive didn't have an estimate). Fase 2 progress
// reporting; nil is fine for a caller that doesn't report progress.
func ReceiveArchive(ctx context.Context, cons jetstream.Consumer, associatedData []byte, deriveChain DeriveChainFunc, onTotalBytes func(int64)) (io.ReadCloser, <-chan error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)

	go func() {
		err := receiveLoop(ctx, cons, pw, associatedData, deriveChain, onTotalBytes)
		pw.CloseWithError(err)
		done <- err
	}()

	return pr, done
}

func receiveLoop(ctx context.Context, cons jetstream.Consumer, pw *io.PipeWriter, associatedData []byte, deriveChain DeriveChainFunc, onTotalBytes func(int64)) error {
	wantSeq := 0
	var chain *ratchet.Chain

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

			if seq == 0 && onTotalBytes != nil {
				total, _ := strconv.ParseInt(msg.Headers().Get(HeaderTotalBytes), 10, 64)
				onTotalBytes(total)
			}

			payload := msg.Data()
			if msg.Headers().Get(HeaderEncrypted) == "true" {
				if seq == 0 {
					if deriveChain == nil {
						_ = msg.Nak()
						return fmt.Errorf("pipeline: chunk 0 is encrypted but this receiver has no way to derive a chain")
					}
					chain, err = chainFromBootstrapHeaders(msg.Headers(), deriveChain)
					if err != nil {
						_ = msg.Nak()
						return fmt.Errorf("pipeline: bootstrap chain from chunk 0: %w", err)
					}
				}
				if chain == nil {
					_ = msg.Nak()
					return fmt.Errorf("pipeline: chunk %d is encrypted but no chain has been established", seq)
				}
				payload, err = chain.Decrypt(payload, associatedData, uint32(seq))
				if err != nil {
					_ = msg.Nak()
					return fmt.Errorf("pipeline: decrypt chunk %d: %w", seq, err)
				}
			}

			if _, err := pw.Write(payload); err != nil {
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

func chainFromBootstrapHeaders(h natsgo.Header, deriveChain DeriveChainFunc) (*ratchet.Chain, error) {
	dhPubBytes, err := base64.StdEncoding.DecodeString(h.Get(HeaderBootstrapDHPub))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", HeaderBootstrapDHPub, err)
	}
	dhPub, err := ecdh.X25519().NewPublicKey(dhPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", HeaderBootstrapDHPub, err)
	}

	ephemeralBytes, err := base64.StdEncoding.DecodeString(h.Get(HeaderBootstrapEphemeral))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", HeaderBootstrapEphemeral, err)
	}
	ephemeralPub, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", HeaderBootstrapEphemeral, err)
	}

	otpID, err := strconv.ParseUint(h.Get(HeaderBootstrapOTPID), 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", HeaderBootstrapOTPID, err)
	}

	return deriveChain(dhPub, ephemeralPub, uint32(otpID))
}
