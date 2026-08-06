package ratchet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	rootKeySize   = 32
	chainKeySize  = 32
	cipherKeySize = 32
	nonceSize     = 12 // AES-GCM standard nonce size

	infoRootKey  = "DoubleRatchet-RootKey"
	infoChainKey = "DoubleRatchet-ChainKey"
)

// Chain is one direction (sending or receiving) of a Double Ratchet
// session, seeded by a single DH ratchet step and then advanced by
// KDF_CK once per chunk (Fase 3: "cada chunk... deriva la siguiente
// Message Key"). Not safe for concurrent use — Fase 2 already drives each
// direction from a single goroutine (the sender's chunk loop, the
// receiver's chunk loop).
type Chain struct {
	key []byte // current chain key
	n   uint32 // next sequence number
}

// InitSending derives the initiator's ("Alice's") first sending chain from
// the X3DH shared secret sk and a DH ratchet step against the responder's
// Signed PreKey. dhPriv is Alice's own ephemeral key — the same keypair
// x3dh.DeriveInitiator returned, reused here rather than generating a
// second ephemeral (see that function's doc comment) — and dhPub is the
// responder's Signed PreKey public half, taken straight from the Bundle.
func InitSending(sk []byte, dhPriv *ecdh.PrivateKey, dhPub *ecdh.PublicKey) (*Chain, error) {
	return initChain(sk, dhPriv, dhPub)
}

// InitReceiving derives the responder's ("Bob's") first receiving chain,
// mirroring InitSending. dhPriv is Bob's own Signed PreKey private half
// (the same keypair whose public half rode the Bundle); dhPub is Alice's
// ephemeral public key, taken off Fase 2's first chunk headers. ECDH is
// symmetric, so this produces the identical chain key InitSending did.
func InitReceiving(sk []byte, dhPriv *ecdh.PrivateKey, dhPub *ecdh.PublicKey) (*Chain, error) {
	return initChain(sk, dhPriv, dhPub)
}

func initChain(sk []byte, dhPriv *ecdh.PrivateKey, dhPub *ecdh.PublicKey) (*Chain, error) {
	dhOut, err := dhPriv.ECDH(dhPub)
	if err != nil {
		return nil, fmt.Errorf("ratchet: dh: %w", err)
	}
	_, ck, err := kdfRK(sk, dhOut)
	if err != nil {
		return nil, err
	}
	return &Chain{key: ck}, nil
}

// Encrypt derives the next message key (advancing the chain), encrypts
// plaintext with AES-256-GCM under it, and returns the ciphertext along
// with the sequence number the receiver must present back to Decrypt.
// associatedData is authenticated but not encrypted (Fase 3's AD =
// IKA_pub || IKB_pub is the intended use, binding the ciphertext to both
// parties' identities without needing to re-transmit them per chunk).
func (c *Chain) Encrypt(plaintext, associatedData []byte) (ciphertext []byte, seq uint32, err error) {
	nextCK, cipherKey, nonce, err := kdfCK(c.key)
	if err != nil {
		return nil, 0, err
	}
	gcm, err := newGCM(cipherKey)
	if err != nil {
		return nil, 0, err
	}

	seq = c.n
	c.key = nextCK
	c.n++
	return gcm.Seal(nil, nonce, plaintext, associatedData), seq, nil
}

// Decrypt requires seq to be exactly the next sequence number this chain
// expects — see the package doc comment for why that's a deliberate
// simplification rather than a general Double Ratchet's skipped-key
// buffering — derives the matching message key, and authenticates +
// decrypts ciphertext.
func (c *Chain) Decrypt(ciphertext, associatedData []byte, seq uint32) ([]byte, error) {
	if seq != c.n {
		return nil, fmt.Errorf("ratchet: out-of-order chunk: got sequence %d, want %d (this Chain requires strict in-order delivery)", seq, c.n)
	}

	nextCK, cipherKey, nonce, err := kdfCK(c.key)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(cipherKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, fmt.Errorf("ratchet: decrypt chunk %d: %w", seq, err)
	}

	c.key = nextCK
	c.n++
	return plaintext, nil
}

func newGCM(cipherKey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, fmt.Errorf("ratchet: aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("ratchet: gcm: %w", err)
	}
	return gcm, nil
}

// kdfRK is the Double Ratchet's root key derivation function: derives a
// new root key and an initial chain key from the current root key and a DH
// output, using the DH output as HKDF salt (matching the ftaw reference).
func kdfRK(rootKey, dhOutput []byte) (nextRootKey, chainKey []byte, err error) {
	h := hkdf.New(sha256.New, rootKey, dhOutput, []byte(infoRootKey))
	out := make([]byte, rootKeySize+chainKeySize)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, nil, fmt.Errorf("ratchet: KDF_RK: %w", err)
	}
	return out[:rootKeySize], out[rootKeySize:], nil
}

// kdfCK is the Double Ratchet's chain key derivation function: derives the
// next chain key plus a one-shot AES key and nonce from the current chain
// key. Deriving a nonce alongside the key (rather than using a fixed
// all-zero nonce and relying solely on "the key itself is single-use") is
// the more conservative, standard choice and costs nothing extra here.
func kdfCK(chainKey []byte) (nextChainKey, cipherKey, nonce []byte, err error) {
	h := hkdf.New(sha256.New, chainKey, nil, []byte(infoChainKey))
	out := make([]byte, chainKeySize+cipherKeySize+nonceSize)
	if _, err := io.ReadFull(h, out); err != nil {
		return nil, nil, nil, fmt.Errorf("ratchet: KDF_CK: %w", err)
	}
	return out[:chainKeySize], out[chainKeySize : chainKeySize+cipherKeySize], out[chainKeySize+cipherKeySize:], nil
}
