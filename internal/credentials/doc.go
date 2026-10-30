// Package credentials runs the binding and validation layers of secure
// credential propagation inside the proxy.
//
// On the way to the Temporal Service, it replaces the plaintext credentials
// header an application attaches to a call with one sealed to the receiver's
// public key and bound to that call (see [go.temporal.io/proxy/pkg/credentials]).
// On the way back, it opens the headers on the tasks a Worker receives,
// rebuilding each binding from the task itself, validates every credential, and
// hands the application either the validated credentials or a failure marker.
// Any credentials header it did not produce or open itself is stripped, so
// neither side can inject one.
//
// The link between the application and the proxy carries credentials in
// plaintext and must be trusted.
package credentials
