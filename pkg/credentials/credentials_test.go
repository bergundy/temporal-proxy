package credentials_test

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/api/common/v1"

	"go.temporal.io/proxy/pkg/credentials"
)

type testKey struct{ id, pub, priv string }

func newTestKey(t *testing.T) testKey {
	t.Helper()

	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	id := make([]byte, credentials.KeyIDSize)
	_, _ = rand.Read(id)

	return testKey{
		id:   hex.EncodeToString(id),
		pub:  base64.RawURLEncoding.EncodeToString(sk.PublicKey().Bytes()),
		priv: base64.RawURLEncoding.EncodeToString(sk.Bytes()),
	}
}

func keysetJSON(def, endpoints string, keys map[string]testKey, withPrivate bool) []byte {
	var entries []string
	for name, k := range keys {
		priv := ""
		if withPrivate {
			priv = fmt.Sprintf(`,"private":%q`, k.priv)
		}
		entries = append(entries, fmt.Sprintf(`{"name":%q,"id":%q,"public":%q%s}`, name, k.id, k.pub, priv))
	}

	return fmt.Appendf(nil, `{"keys":[%s],"default":%q,"nexusEndpoints":{%s}}`,
		strings.Join(entries, ","), def, endpoints)
}

func payload(data string) *common.Payload {
	return &common.Payload{Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: []byte(data)}
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	keys := map[string]testKey{"agents": newTestKey(t)}
	ks, err := credentials.ParseKeyset(keysetJSON("agents", "", keys, true), false)
	require.NoError(t, err)

	key, err := ks.SealingKey("", "")
	require.NoError(t, err)

	info := credentials.WorkflowContext("default", "Agent", "wf-1", []*common.Payload{payload(`"hi"`)})
	creds := map[string]string{"user_token": "eyJ...", "approver_token": "eyK..."}

	header, err := credentials.Seal(key, info, creds)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(header, credentials.HeaderPrefix))
	require.NotContains(t, header, "eyJ")

	opened, err := ks.Open(info, header)
	require.NoError(t, err)
	require.Equal(t, creds, opened)
}

func TestOpenFailsOnAnyContextChange(t *testing.T) {
	t.Parallel()

	keys := map[string]testKey{"agents": newTestKey(t)}
	ks, err := credentials.ParseKeyset(keysetJSON("agents", "", keys, true), false)
	require.NoError(t, err)

	key, err := ks.SealingKey("", "")
	require.NoError(t, err)

	args := []*common.Payload{payload(`"a"`), payload(`"b"`)}
	header, err := credentials.Seal(key, credentials.WorkflowContext("ns", "Agent", "wf-1", args), map[string]string{"t": "v"})
	require.NoError(t, err)

	for name, info := range map[string][]byte{
		"namespace":     credentials.WorkflowContext("other", "Agent", "wf-1", args),
		"type":          credentials.WorkflowContext("ns", "Other", "wf-1", args),
		"id":            credentials.WorkflowContext("ns", "Agent", "wf-2", args),
		"payload bytes": credentials.WorkflowContext("ns", "Agent", "wf-1", []*common.Payload{payload(`"a"`), payload(`"c"`)}),
		"order":         credentials.WorkflowContext("ns", "Agent", "wf-1", []*common.Payload{args[1], args[0]}),
		"count":         credentials.WorkflowContext("ns", "Agent", "wf-1", args[:1]),
		"metadata": credentials.WorkflowContext("ns", "Agent", "wf-1", []*common.Payload{
			{Metadata: map[string][]byte{"encoding": []byte("binary/plain")}, Data: []byte(`"a"`)}, args[1],
		}),
		"hop": credentials.ActivityContext("ns", "wf-1", "Agent", "", args),
	} {
		_, err := ks.Open(info, header)
		require.ErrorIs(t, err, credentials.ErrOpen, name)
	}
}

func TestOpenFailsOnEditedHeader(t *testing.T) {
	t.Parallel()

	keys := map[string]testKey{"agents": newTestKey(t)}
	ks, err := credentials.ParseKeyset(keysetJSON("agents", "", keys, true), false)
	require.NoError(t, err)

	key, _ := ks.SealingKey("", "")
	info := credentials.NexusContext("ep", "svc", "op", payload("x"))
	header, err := credentials.Seal(key, info, map[string]string{"t": "v"})
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(header, credentials.HeaderPrefix))
	require.NoError(t, err)
	raw[len(raw)-20] ^= 1
	_, err = ks.Open(info, credentials.HeaderPrefix+base64.RawURLEncoding.EncodeToString(raw))
	require.ErrorIs(t, err, credentials.ErrOpen)

	_, err = ks.Open(info, "eyJhbGciOi.plaintext.jwt")
	require.ErrorIs(t, err, credentials.ErrMalformed)
}

func TestPublicOnlyKeysetCannotOpen(t *testing.T) {
	t.Parallel()

	keys := map[string]testKey{"agents": newTestKey(t)}
	sender, err := credentials.ParseKeyset(keysetJSON("agents", "", keys, false), false)
	require.NoError(t, err)

	key, _ := sender.SealingKey("", "")
	info := credentials.NexusContext("ep", "svc", "op", payload("x"))
	header, err := credentials.Seal(key, info, map[string]string{"t": "v"})
	require.NoError(t, err)

	_, err = sender.Open(info, header)
	require.ErrorIs(t, err, credentials.ErrKeyNotHeld)

	receiver, err := credentials.ParseKeyset(keysetJSON("agents", "", keys, true), false)
	require.NoError(t, err)
	_, err = receiver.Open(info, header)
	require.NoError(t, err)
}

func TestSealingKeySelection(t *testing.T) {
	t.Parallel()

	keys := map[string]testKey{"agents": newTestKey(t), "payments": newTestKey(t)}
	data := keysetJSON("agents", `"payments-ep":"payments"`, keys, false)

	ks, err := credentials.ParseKeyset(data, false)
	require.NoError(t, err)

	id := func(name, ep string) string {
		k, err := ks.SealingKey(name, ep)
		require.NoError(t, err)
		return hex.EncodeToString(k.ID[:])
	}

	require.Equal(t, keys["agents"].id, id("", ""))
	require.Equal(t, keys["payments"].id, id("", "payments-ep"))
	require.Equal(t, keys["agents"].id, id("", "tools-ep"))
	require.Equal(t, keys["agents"].id, id("agents", "payments-ep"))

	_, err = ks.SealingKey("nope", "")
	require.ErrorIs(t, err, credentials.ErrUnknownKeyName)

	strict, err := credentials.ParseKeyset(data, true)
	require.NoError(t, err)
	_, err = strict.SealingKey("", "tools-ep")
	require.ErrorIs(t, err, credentials.ErrNoKey)
	_, err = strict.SealingKey("", "payments-ep")
	require.NoError(t, err)
}

func TestFrameIsUnambiguous(t *testing.T) {
	t.Parallel()

	require.NotEqual(t,
		credentials.Frame([]byte("ab"), []byte("c")),
		credentials.Frame([]byte("a"), []byte("bc")),
	)
	require.NotEqual(t, credentials.Frame([]byte("")), credentials.Frame())
}
