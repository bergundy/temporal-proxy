package credentials

import (
	"bytes"
	"crypto/hpke"
	"encoding/base64"
	"errors"
	"maps"
	"slices"
	"strings"
)

// HeaderPrefix starts every sealed header.
const HeaderPrefix = "v1.start."

// encSize is the length of an X25519 encapsulated key.
const encSize = 32

var (
	// ErrMalformed is returned for a header that isn't one this package wrote.
	ErrMalformed = errors.New("credentials: malformed header")

	// ErrKeyNotHeld is returned when a header is sealed to a key whose private
	// half this keyset doesn't hold.
	ErrKeyNotHeld = errors.New("credentials: header sealed to a key not held")

	// ErrOpen is returned when a header fails to open: it was edited, sealed
	// under a different context, or sealed to a different key with the same ID.
	// The cause is deliberately not distinguished.
	ErrOpen = errors.New("credentials: header does not open under this context")

	plaintextLabel = [][]byte{[]byte("credentials"), []byte("v1")}
)

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.AES256GCM() }

// Seal seals creds to key, bound to info, and returns the header value.
func Seal(key *Key, info []byte, creds map[string]string) (string, error) {
	fields := slices.Clone(plaintextLabel)
	for _, name := range slices.Sorted(maps.Keys(creds)) {
		fields = append(fields, []byte(name), []byte(creds[name]))
	}

	kdf, aead := suite()
	ct, err := hpke.Seal(key.Public, kdf, aead, info, Frame(fields...))
	if err != nil {
		return "", err
	}

	return HeaderPrefix + base64.RawURLEncoding.EncodeToString(append(key.ID[:], ct...)), nil
}

// Open opens header with the private key it names, under info, and returns
// the credentials it carries.
func (ks *Keyset) Open(info []byte, header string) (map[string]string, error) {
	rest, ok := strings.CutPrefix(header, HeaderPrefix)
	if !ok {
		return nil, ErrMalformed
	}

	raw, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(raw) < KeyIDSize+encSize+16 {
		return nil, ErrMalformed
	}

	key := ks.keys[KeyID(raw[:KeyIDSize])]
	if key == nil || key.private == nil {
		return nil, ErrKeyNotHeld
	}

	kdf, aead := suite()
	pt, err := hpke.Open(key.private, kdf, aead, info, raw[KeyIDSize:])
	if err != nil {
		return nil, ErrOpen
	}

	fields, err := unframe(pt)
	if err != nil || len(fields) < 2 || len(fields)%2 != 0 ||
		!bytes.Equal(fields[0], plaintextLabel[0]) || !bytes.Equal(fields[1], plaintextLabel[1]) {
		return nil, ErrMalformed
	}

	creds := make(map[string]string, len(fields)/2-1)
	for i := 2; i < len(fields); i += 2 {
		creds[string(fields[i])] = string(fields[i+1])
	}

	return creds, nil
}
