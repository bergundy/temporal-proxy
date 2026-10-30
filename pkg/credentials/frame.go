package credentials

import (
	"crypto/sha256"
	"encoding/binary"
	"maps"
	"slices"
	"strconv"

	"go.temporal.io/api/common/v1"
)

// Frame encodes fields unambiguously: a big-endian uint32 field count followed
// by each field as a big-endian uint32 length and its bytes. No two distinct
// field lists encode to the same bytes.
func Frame(fields ...[]byte) []byte {
	n := 4
	for _, f := range fields {
		n += 4 + len(f)
	}

	out := make([]byte, 0, n)
	out = binary.BigEndian.AppendUint32(out, uint32(len(fields)))
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}

	return out
}

// unframe reverses [Frame], failing on any trailing or missing bytes.
func unframe(b []byte) ([][]byte, error) {
	if len(b) < 4 {
		return nil, ErrMalformed
	}

	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if uint64(n)*4 > uint64(len(b)) {
		return nil, ErrMalformed
	}

	fields := make([][]byte, 0, n)
	for range n {
		if len(b) < 4 {
			return nil, ErrMalformed
		}

		l := binary.BigEndian.Uint32(b)
		b = b[4:]
		if uint64(l) > uint64(len(b)) {
			return nil, ErrMalformed
		}

		fields = append(fields, b[:l])
		b = b[l:]
	}

	if len(b) != 0 {
		return nil, ErrMalformed
	}

	return fields, nil
}

// Digest is D(list): SHA-256 over the framed payloads, covering their bytes,
// their order and their count. Each payload is framed as its metadata, sorted
// by key, followed by its data, so the digest does not depend on how a map was
// serialized on the way through the Temporal Service. A nil payload frames as
// an empty field list, distinct from an empty payload.
func Digest(payloads []*common.Payload) []byte {
	fields := make([][]byte, 0, 3+len(payloads))
	fields = append(fields, []byte("args-digest"), []byte("v1"), []byte(strconv.Itoa(len(payloads))))
	for _, p := range payloads {
		fields = append(fields, framePayload(p))
	}

	sum := sha256.Sum256(Frame(fields...))

	return sum[:]
}

func framePayload(p *common.Payload) []byte {
	if p == nil {
		return Frame()
	}

	md := p.GetMetadata()
	fields := make([][]byte, 0, 2*len(md)+1)
	for _, k := range slices.Sorted(maps.Keys(md)) {
		fields = append(fields, []byte(k), md[k])
	}

	fields = append(fields, p.GetData())

	return Frame(fields...)
}
