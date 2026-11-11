package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.temporal.io/sdk/contrib/credentials/binding"
)

// runCredentials runs `proxy credentials <args>` and returns what it wrote to
// stdout.
func runCredentials(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out, errOut bytes.Buffer

	cmd := credentials()
	cmd.Writer = &out
	cmd.ErrWriter = &errOut

	err := cmd.Run(t.Context(), append([]string{"credentials"}, args...))

	return out.String(), err
}

func parseKeysetJSON(t *testing.T, data []byte) binding.KeysetJSON {
	t.Helper()

	var ks binding.KeysetJSON
	require.NoError(t, json.Unmarshal(data, &ks))

	_, err := binding.NewKeyset(ks)
	require.NoError(t, err)

	return ks
}

func keyNames(ks binding.KeysetJSON) []string {
	names := make([]string, 0, len(ks.Keys))
	for _, k := range ks.Keys {
		names = append(names, k.Name)
	}

	return names
}

func TestGenerateKeyset(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		keys      []string
		def       string
		endpoints map[string]string
	}{
		{
			name: "default is the first key",
			args: []string{"--key", "agents", "--key", "payments"},
			keys: []string{"agents", "payments"},
			def:  "agents",
		},
		{
			name: "explicit default",
			args: []string{"--key", "agents", "--key", "payments", "--default", "payments"},
			keys: []string{"agents", "payments"},
			def:  "payments",
		},
		{
			name: "no default",
			args: []string{"--key", "agents", "--no-default"},
			keys: []string{"agents"},
		},
		{
			name: "nexus endpoints",
			args: []string{
				"--key", "agents", "--key", "payments",
				"--nexus-endpoint", "payments-endpoint=payments",
				"--nexus-endpoint", "billing-endpoint=payments",
			},
			keys:      []string{"agents", "payments"},
			def:       "agents",
			endpoints: map[string]string{"payments-endpoint": "payments", "billing-endpoint": "payments"},
		},
		{
			name: "commas are not separators",
			args: []string{"--key", "a,b"},
			keys: []string{"a,b"},
			def:  "a,b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := runCredentials(t, append([]string{"generate-keyset"}, tt.args...)...)
			require.NoError(t, err)

			ks := parseKeysetJSON(t, []byte(out))
			require.Equal(t, tt.keys, keyNames(ks))
			require.Equal(t, tt.def, ks.Default)
			require.Equal(t, tt.endpoints, ks.NexusEndpoints)

			ids := map[string]bool{}
			for _, k := range ks.Keys {
				require.NotEmpty(t, k.Private, "key %q has no private half", k.Name)
				require.False(t, ids[k.ID], "key ID %s repeats", k.ID)
				ids[k.ID] = true
			}
		})
	}
}

func TestGenerateKeysetErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "no keys",
			want: "at least one --key is required, such as --key agents",
		},
		{
			name: "empty key name",
			args: []string{"--key", ""},
			want: "--key needs a non-empty name",
		},
		{
			name: "duplicate key name",
			args: []string{"--key", "agents", "--key", "agents"},
			want: `--key "agents" is given more than once`,
		},
		{
			name: "unknown default",
			args: []string{"--key", "agents", "--default", "payments"},
			want: `--default "payments" is not one of the --key names (agents)`,
		},
		{
			name: "default and no default",
			args: []string{"--key", "agents", "--default", "agents", "--no-default"},
			want: "--default and --no-default contradict each other",
		},
		{
			name: "nexus endpoint without a key",
			args: []string{"--key", "agents", "--nexus-endpoint", "payments-endpoint"},
			want: `--nexus-endpoint "payments-endpoint" must be ENDPOINT=KEY`,
		},
		{
			name: "nexus endpoint with an empty name",
			args: []string{"--key", "agents", "--nexus-endpoint", "=agents"},
			want: `--nexus-endpoint "=agents" must be ENDPOINT=KEY`,
		},
		{
			name: "nexus endpoint naming an unknown key",
			args: []string{"--key", "agents", "--nexus-endpoint", "payments-endpoint=payments"},
			want: `names key "payments", which is not one of the --key names (agents)`,
		},
		{
			name: "nexus endpoint mapped twice",
			args: []string{
				"--key", "agents", "--key", "payments",
				"--nexus-endpoint", "payments-endpoint=payments",
				"--nexus-endpoint", "payments-endpoint=agents",
			},
			want: `--nexus-endpoint maps Nexus endpoint "payments-endpoint" more than once`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := runCredentials(t, append([]string{"generate-keyset"}, tt.args...)...)
			require.ErrorContains(t, err, tt.want)
			require.Empty(t, out)
		})
	}
}

func TestGenerateKeysetOut(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keyset.json")

	out, err := runCredentials(t, "generate-keyset", "--key", "agents", "--out", path)
	require.NoError(t, err)
	require.Empty(t, out, "the keyset belongs in the file, not on stdout")

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	ks := parseKeysetJSON(t, data)
	require.Equal(t, []string{"agents"}, keyNames(ks))

	_, err = runCredentials(t, "generate-keyset", "--key", "other", "-o", path)
	require.ErrorContains(t, err, "refusing to overwrite "+path)
	require.ErrorContains(t, err, "choose another --out")

	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, data, after, "an existing keyset must be left as it was")
}

func TestGenerateKeysetOutMissingDir(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "missing", "keyset.json")

	_, err := runCredentials(t, "generate-keyset", "--key", "agents", "--out", path)
	require.ErrorContains(t, err, "failed to create keyset file")
	require.ErrorContains(t, err, path)
}

func TestPublicKeyset(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "keyset.json")

	_, err := runCredentials(t, "generate-keyset",
		"--key", "agents", "--key", "payments",
		"--nexus-endpoint", "payments-endpoint=payments",
		"--out", path,
	)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	private := parseKeysetJSON(t, data)

	out, err := runCredentials(t, "public-keyset", path)
	require.NoError(t, err)
	require.NotContains(t, out, `"private"`)

	public := parseKeysetJSON(t, []byte(out))
	require.Len(t, public.Keys, len(private.Keys))

	for i, k := range public.Keys {
		require.Equal(t, private.Keys[i].PublicOnly(), k)
	}

	require.Equal(t, private.Default, public.Default)
	require.Equal(t, private.NexusEndpoints, public.NexusEndpoints)

	ks, err := binding.NewKeyset(public)
	require.NoError(t, err)
	require.False(t, ks.CanOpen(), "a public keyset must not open")

	// A public keyset is its own public form.
	again, err := runCredentials(t, "public-keyset", writeFile(t, out))
	require.NoError(t, err)
	require.Equal(t, out, again)
}

func TestPublicKeysetErrors(t *testing.T) {
	t.Parallel()

	missing := filepath.Join(t.TempDir(), "missing.json")

	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "no file",
			want: "public-keyset takes one argument, the keyset file, but got 0",
		},
		{
			name: "two files",
			args: []string{"a.json", "b.json"},
			want: "public-keyset takes one argument, the keyset file, but got 2",
		},
		{
			name: "missing file",
			args: []string{missing},
			want: "failed to read keyset: open " + missing,
		},
		{
			name: "not JSON",
			args: []string{writeFile(t, "{")},
			want: "is not valid JSON",
		},
		{
			name: "invalid keyset",
			args: []string{writeFile(t, `{"keys": [{"name": "agents", "id": "zz", "public": "x"}]}`)},
			want: `is invalid: credentials: keyset keys[0] ("agents"): id must be 5 hex-encoded bytes`,
		},
		{
			name: "unknown default",
			args: []string{writeFile(t, `{"keys": [], "default": "agents"}`)},
			want: `is invalid: credentials: keyset default: unknown key name "agents"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := runCredentials(t, append([]string{"public-keyset"}, tt.args...)...)
			require.ErrorContains(t, err, tt.want)
			require.Empty(t, out)
		})
	}
}

func writeFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "keyset.json")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}
