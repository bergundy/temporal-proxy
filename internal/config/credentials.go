package config

import "errors"

type (
	// Credentials configures secure credential propagation: the keyset the proxy
	// seals and opens credentials headers with. Applications attach plaintext
	// credentials to their calls; the proxy seals them before they reach the
	// Temporal Service and opens them on the tasks Workers receive.
	Credentials struct {
		// Keyset is the path of a JSON keyset file (see binding.ParseKeyset).
		Keyset string `yaml:"keyset"`

		// Strict disables the keyset's default key, so a call that names no key
		// and matches no Nexus endpoint override fails at the sender.
		Strict bool `yaml:"strict"`
	}
)

// Validate requires a keyset.
func (c *Credentials) Validate() error {
	if c.Keyset == "" {
		return errors.New("credentials.keyset is required")
	}

	return nil
}
