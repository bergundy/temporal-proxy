package credentials

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// KeyIDSize is the length of a key ID, which every header carries so the
// receiver can pick its private key without routing.
const KeyIDSize = 5

var (
	// ErrNoKey is returned by [Keyset.SealingKey] when nothing selects a key: no
	// key was named, no endpoint override matched, and the keyset is strict or
	// has no default.
	ErrNoKey = errors.New("credentials: no key selected")

	// ErrUnknownKeyName is returned when a call names a key the keyset doesn't
	// have.
	ErrUnknownKeyName = errors.New("credentials: unknown key name")
)

type (
	// KeyID identifies an HPKE key pair.
	KeyID [KeyIDSize]byte

	// Key is an X25519 key pair, or only its public half for a sender.
	Key struct {
		ID      KeyID
		Public  hpke.PublicKey
		private hpke.PrivateKey
	}

	// Keyset is everything a proxy needs to seal and open headers: the keys it
	// holds, by ID, and how senders choose among them.
	Keyset struct {
		keys           map[KeyID]*Key
		names          map[string]*Key
		nexusEndpoints map[string]*Key
		def            *Key
		strict         bool
	}

	// keysetFile is the JSON form of a [Keyset]. Keys are referred to by name;
	// the key ID is what is carried on the wire.
	keysetFile struct {
		Keys []struct {
			Name    string `json:"name"`
			ID      string `json:"id"`
			Public  string `json:"public"`
			Private string `json:"private,omitempty"`
		} `json:"keys"`
		Default        string            `json:"default,omitempty"`
		NexusEndpoints map[string]string `json:"nexusEndpoints,omitempty"`
	}
)

// LoadKeyset reads a JSON keyset file. See [ParseKeyset].
func LoadKeyset(path string, strict bool) (*Keyset, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return ParseKeyset(data, strict)
}

// ParseKeyset parses a JSON keyset:
//
//	{
//	  "keys": [{"name": "agents", "id": "<10 hex>", "public": "<b64url>", "private": "<b64url>"}],
//	  "default": "agents",
//	  "nexusEndpoints": {"payments": "payments"}
//	}
//
// A key without "private" can seal but not open. With strict, the default is
// ignored, so a call that names no key and matches no endpoint override fails
// instead of being sealed to a key the receiver may not hold.
func ParseKeyset(data []byte, strict bool) (*Keyset, error) {
	var f keysetFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("credentials: invalid keyset: %w", err)
	}

	ks := &Keyset{
		keys:           make(map[KeyID]*Key, len(f.Keys)),
		names:          make(map[string]*Key, len(f.Keys)),
		nexusEndpoints: make(map[string]*Key, len(f.NexusEndpoints)),
		strict:         strict,
	}

	for i, k := range f.Keys {
		key, err := parseKey(k.ID, k.Public, k.Private)
		if err != nil {
			return nil, fmt.Errorf("credentials: keys[%d]: %w", i, err)
		}

		if k.Name == "" {
			return nil, fmt.Errorf("credentials: keys[%d]: a name is required", i)
		}

		if _, dup := ks.keys[key.ID]; dup {
			return nil, fmt.Errorf("credentials: keys[%d]: duplicate key ID %x", i, key.ID)
		}

		if _, dup := ks.names[k.Name]; dup {
			return nil, fmt.Errorf("credentials: keys[%d]: duplicate key name %q", i, k.Name)
		}

		ks.keys[key.ID] = key
		ks.names[k.Name] = key
	}

	if f.Default != "" {
		ks.def = ks.names[f.Default]
		if ks.def == nil {
			return nil, fmt.Errorf("credentials: default: %w %q", ErrUnknownKeyName, f.Default)
		}
	}

	for ep, name := range f.NexusEndpoints {
		k := ks.names[name]
		if k == nil {
			return nil, fmt.Errorf("credentials: nexusEndpoints[%s]: %w %q", ep, ErrUnknownKeyName, name)
		}

		ks.nexusEndpoints[ep] = k
	}

	return ks, nil
}

func parseKey(id, pub, priv string) (*Key, error) {
	idBytes, err := hex.DecodeString(id)
	if err != nil || len(idBytes) != KeyIDSize {
		return nil, fmt.Errorf("id must be %d hex-encoded bytes", KeyIDSize)
	}

	key := &Key{ID: KeyID(idBytes)}

	pubBytes, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		return nil, fmt.Errorf("public: %w", err)
	}

	pk, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("public: %w", err)
	}

	if key.Public, err = hpke.NewDHKEMPublicKey(pk); err != nil {
		return nil, fmt.Errorf("public: %w", err)
	}

	if priv == "" {
		return key, nil
	}

	privBytes, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil {
		return nil, fmt.Errorf("private: %w", err)
	}

	sk, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("private: %w", err)
	}

	if !sk.PublicKey().Equal(pk) {
		return nil, errors.New("private key does not match public key")
	}

	if key.private, err = hpke.NewDHKEMPrivateKey(sk); err != nil {
		return nil, fmt.Errorf("private: %w", err)
	}

	return key, nil
}

// SealingKey picks the key a header is sealed to, first match wins: the key
// named at the call site, the Nexus endpoint's override (when endpoint is set),
// then the default unless the keyset is strict.
func (ks *Keyset) SealingKey(name, nexusEndpoint string) (*Key, error) {
	if name != "" {
		if k := ks.names[name]; k != nil {
			return k, nil
		}

		return nil, fmt.Errorf("%w %q", ErrUnknownKeyName, name)
	}

	if nexusEndpoint != "" {
		if k := ks.nexusEndpoints[nexusEndpoint]; k != nil {
			return k, nil
		}
	}

	if ks.def == nil || ks.strict {
		return nil, ErrNoKey
	}

	return ks.def, nil
}
