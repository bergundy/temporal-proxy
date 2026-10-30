package config

import (
	"errors"
	"fmt"
	"time"
)

type (
	// Credentials configures secure credential propagation: the keyset the proxy
	// seals and opens credentials headers with, and the validators each opened
	// credential must pass before it reaches the application.
	Credentials struct {
		// Keyset is the path of a JSON keyset file (see credentials.ParseKeyset).
		Keyset string `yaml:"keyset"`

		// Strict disables the keyset's default key, so a call that names no key
		// and matches no Nexus endpoint override fails at the sender.
		Strict bool `yaml:"strict"`

		// Validators maps credential names to the validator each must pass.
		// Opened credentials with no validator are dropped.
		Validators map[string]CredentialValidator `yaml:"validators"`
	}

	// CredentialValidator selects how one credential name is validated.
	CredentialValidator struct {
		JWT *JWTValidator `yaml:"jwt"`
	}

	// JWTValidator verifies a JWT's signature against a JWKS, and its expiry,
	// audience and issuer.
	JWTValidator struct {
		// JWKSURL is fetched and refreshed in the background. Exactly one of
		// JWKSURL and JWKSFile is required.
		JWKSURL string `yaml:"jwksUrl"`

		// JWKSFile is read once at startup.
		JWKSFile string `yaml:"jwksFile"`

		// Audience lists accepted audiences; the token must name at least one.
		Audience []string `yaml:"audience"`

		// Issuer, when set, must match the token's iss claim.
		Issuer string `yaml:"issuer"`

		// Leeway allows for clock skew when checking exp and nbf.
		Leeway time.Duration `yaml:"leeway"`
	}
)

// Validate requires a keyset and a well-formed validator for every name.
func (c *Credentials) Validate() error {
	if c.Keyset == "" {
		return errors.New("credentials.keyset is required")
	}

	for name, v := range c.Validators {
		if v.JWT == nil {
			return fmt.Errorf("credentials.validators[%s]: a validator (jwt) is required", name)
		}

		if (v.JWT.JWKSURL == "") == (v.JWT.JWKSFile == "") {
			return fmt.Errorf("credentials.validators[%s].jwt: exactly one of jwksUrl and jwksFile is required", name)
		}

		if len(v.JWT.Audience) == 0 {
			return fmt.Errorf("credentials.validators[%s].jwt: audience is required", name)
		}

		if v.JWT.Leeway < 0 {
			return fmt.Errorf("credentials.validators[%s].jwt: leeway must not be negative", name)
		}
	}

	return nil
}
