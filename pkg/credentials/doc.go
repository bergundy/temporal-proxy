// Package credentials implements the binding layer of secure credential
// propagation: it seals named credentials into a header that only the receiving
// party can open, and binds that header to the exact call it travels with.
//
// A header is sealed with HPKE (RFC 9180, base mode) using DHKEM(X25519,
// HKDF-SHA256), HKDF-SHA256 and AES-256-GCM, to the receiver's public key. The
// call's context, such as the namespace, Workflow ID and a digest of the exact
// payload bytes, is passed as the HPKE info. It is never transmitted: the
// receiver rebuilds it from what it received, so a header moved to another
// call, or paired with different inputs, fails to open.
//
// The wire format of a header is
//
//	"v1.start." + base64url(keyID (5) | enc (32) | AES-GCM ciphertext | tag (16))
//
// and the sealed plaintext is [Frame]("credentials", "v1", name₁, value₁, ...).
package credentials
