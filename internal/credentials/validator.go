package credentials

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"go.temporal.io/proxy/internal/config"
)

// validSigningMethods restricts accepted JWT algorithms to asymmetric ones, so a
// token can't pick "none" or an HMAC keyed with a public key.
var validSigningMethods = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}

type (
	// Validator checks one credential at a given time and returns claims
	// describing it.
	Validator interface {
		Validate(ctx context.Context, value string, at time.Time) (map[string]any, error)
	}

	// JWTValidator verifies a JWT's signature against a JWKS and checks its
	// expiry, audience and issuer against the time it is given.
	JWTValidator struct {
		keyfn    jwt.Keyfunc
		audience []string
		issuer   string
		leeway   time.Duration
	}
)

// NewValidators builds a validator for every configured credential name.
func NewValidators(ctx context.Context, cfg map[string]config.CredentialValidator) (map[string]Validator, error) {
	vs := make(map[string]Validator, len(cfg))
	for name, c := range cfg {
		v, err := NewJWTValidator(ctx, c.JWT)
		if err != nil {
			return nil, fmt.Errorf("credentials.validators[%s]: %w", name, err)
		}

		vs[name] = v
	}

	return vs, nil
}

// NewJWTValidator builds a [JWTValidator]. A JWKS URL is fetched in the
// background and refreshed; until it loads, validation fails closed.
func NewJWTValidator(ctx context.Context, c *config.JWTValidator) (*JWTValidator, error) {
	var (
		kf  keyfunc.Keyfunc
		err error
	)

	if c.JWKSFile != "" {
		raw, rerr := os.ReadFile(c.JWKSFile)
		if rerr != nil {
			return nil, rerr
		}

		kf, err = keyfunc.NewJWKSetJSON(raw)
	} else {
		kf, err = keyfunc.NewDefaultOverrideCtx(ctx, []string{c.JWKSURL}, keyfunc.Override{
			HTTPTimeout:      10 * time.Second,
			RefreshInterval:  15 * time.Minute,
			RateLimitWaitMax: 5 * time.Second,
		})
	}

	if err != nil {
		return nil, err
	}

	return &JWTValidator{keyfn: kf.Keyfunc, audience: c.Audience, issuer: c.Issuer, leeway: c.Leeway}, nil
}

// Validate verifies value's signature and checks it was valid at at: exp is
// required, and nbf and iat are honored when present.
func (v *JWTValidator) Validate(_ context.Context, value string, at time.Time) (map[string]any, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods(validSigningMethods),
		jwt.WithExpirationRequired(),
		jwt.WithAudience(v.audience...),
		jwt.WithLeeway(v.leeway),
		jwt.WithTimeFunc(func() time.Time { return at }),
	}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.NewParser(opts...).ParseWithClaims(value, claims, v.keyfn)
	if err != nil {
		return nil, err
	}

	if !tok.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
