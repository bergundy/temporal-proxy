package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
	"go.temporal.io/sdk/contrib/credentials/binding"
)

func credentials() *cli.Command {
	return &cli.Command{
		Name:  "credentials",
		Usage: "Manage the keysets used for credential propagation",
		Commands: []*cli.Command{
			generateKeyset(),
			publicKeyset(),
		},
	}
}

func generateKeyset() *cli.Command {
	return &cli.Command{
		Name:  "generate-keyset",
		Usage: "Generate a keyset with a new X25519 key pair for each --key",
		// Each value is one name or mapping, so a comma is never a separator.
		DisableSliceFlagSeparator: true,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{
				Name:  "key",
				Usage: "Generate a key pair named `NAME`; repeat for more keys (at least one is required)",
			},
			&cli.StringFlag{
				Name:  "default",
				Usage: "Make `NAME` the key that seals calls that name no key (default: the first --key)",
			},
			&cli.BoolFlag{
				Name:  "no-default",
				Usage: "Leave the keyset without a default key, for deployments that set credentials.strict",
			},
			&cli.StringSliceFlag{
				Name:  "nexus-endpoint",
				Usage: "Seal Nexus operations on an endpoint to a key, as `ENDPOINT=KEY`; repeatable",
			},
			&cli.StringFlag{
				Name:      "out",
				Aliases:   []string{"o"},
				Usage:     "Write the keyset to `FILE`, a new file created with mode 0600, instead of stdout",
				TakesFile: true,
			},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			ks, err := keysetFromFlags(cmd)
			if err != nil {
				return err
			}

			out := cmd.String("out")
			if out == "" {
				return writeKeyset(cmd.Writer, ks)
			}

			return createKeysetFile(out, ks)
		},
	}
}

func publicKeyset() *cli.Command {
	return &cli.Command{
		Name:      "public-keyset",
		Usage:     "Print a keyset without its private keys, for senders that only seal",
		ArgsUsage: "FILE",
		Action: func(_ context.Context, cmd *cli.Command) error {
			if cmd.NArg() != 1 {
				return fmt.Errorf("public-keyset takes one argument, the keyset file, but got %d; usage: %s FILE",
					cmd.NArg(), cmd.FullName())
			}

			path := cmd.Args().First()

			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read keyset: %w", err)
			}

			var ks binding.KeysetJSON
			if err := json.Unmarshal(data, &ks); err != nil {
				return fmt.Errorf("keyset %s is not valid JSON: %w", path, err)
			}

			if _, err := binding.NewKeyset(ks); err != nil {
				return fmt.Errorf("keyset %s is invalid: %w", path, err)
			}

			for i, k := range ks.Keys {
				ks.Keys[i] = k.PublicOnly()
			}

			return writeKeyset(cmd.Writer, ks)
		},
	}
}

// keysetFromFlags generates a key pair for each --key and validates the keyset
// they form. The checks ahead of binding.NewKeyset exist to name the flag at
// fault.
func keysetFromFlags(cmd *cli.Command) (binding.KeysetJSON, error) {
	names := cmd.StringSlice("key")
	if len(names) == 0 {
		return binding.KeysetJSON{}, errors.New("at least one --key is required, such as --key agents")
	}

	for i, name := range names {
		if name == "" {
			return binding.KeysetJSON{}, errors.New("--key needs a non-empty name, such as --key agents")
		}

		if slices.Contains(names[:i], name) {
			return binding.KeysetJSON{}, fmt.Errorf("--key %q is given more than once; key names must be unique", name)
		}
	}

	known := func(name string) bool { return slices.Contains(names, name) }
	list := strings.Join(names, ", ")

	ks := binding.KeysetJSON{Keys: make([]binding.KeyJSON, 0, len(names))}

	switch def := cmd.String("default"); {
	case cmd.IsSet("default") && cmd.Bool("no-default"):
		return binding.KeysetJSON{}, errors.New("--default and --no-default contradict each other; pass one or neither")
	case cmd.Bool("no-default"):
	case cmd.IsSet("default"):
		if !known(def) {
			return binding.KeysetJSON{}, fmt.Errorf("--default %q is not one of the --key names (%s)", def, list)
		}

		ks.Default = def
	default:
		ks.Default = names[0]
	}

	endpoints := cmd.StringSlice("nexus-endpoint")
	for _, ep := range endpoints {
		endpoint, key, ok := strings.Cut(ep, "=")
		if !ok || endpoint == "" || key == "" {
			return binding.KeysetJSON{}, fmt.Errorf(
				"--nexus-endpoint %q must be ENDPOINT=KEY, such as --nexus-endpoint payments-endpoint=payments", ep)
		}

		if !known(key) {
			return binding.KeysetJSON{}, fmt.Errorf(
				"--nexus-endpoint %q names key %q, which is not one of the --key names (%s)", ep, key, list)
		}

		if ks.NexusEndpoints == nil {
			ks.NexusEndpoints = make(map[string]string, len(endpoints))
		}

		if _, dup := ks.NexusEndpoints[endpoint]; dup {
			return binding.KeysetJSON{}, fmt.Errorf("--nexus-endpoint maps Nexus endpoint %q more than once", endpoint)
		}

		ks.NexusEndpoints[endpoint] = key
	}

	for _, name := range names {
		k, err := binding.GenerateKey(name)
		if err != nil {
			return binding.KeysetJSON{}, fmt.Errorf("failed to generate key %q: %w", name, err)
		}

		ks.Keys = append(ks.Keys, k)
	}

	if _, err := binding.NewKeyset(ks); err != nil {
		return binding.KeysetJSON{}, fmt.Errorf("generated keyset is invalid: %w", err)
	}

	return ks, nil
}

// createKeysetFile writes ks to a new file only its owner can read. It refuses
// to replace an existing file, which may hold the only copy of private keys
// that running Workflows still need.
func createKeysetFile(path string, ks binding.KeysetJSON) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("refusing to overwrite %s, which may hold private keys that running Workflows still need; "+
			"remove it or choose another --out", path)
	}

	if err != nil {
		return fmt.Errorf("failed to create keyset file: %w", err)
	}

	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("failed to write keyset file: %w", cerr)
		}

		if err != nil {
			_ = os.Remove(path)
		}
	}()

	if err := writeKeyset(f, ks); err != nil {
		return fmt.Errorf("failed to write keyset file: %w", err)
	}

	return nil
}

func writeKeyset(w io.Writer, ks binding.KeysetJSON) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")

	return enc.Encode(ks)
}
