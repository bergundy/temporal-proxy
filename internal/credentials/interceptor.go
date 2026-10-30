package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go.temporal.io/api/command/v1"
	"go.temporal.io/api/common/v1"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/history/v1"
	"go.temporal.io/api/nexus/v1"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"go.temporal.io/proxy/pkg/credentials"
	"go.temporal.io/proxy/pkg/logger"
	"go.temporal.io/proxy/pkg/logger/tag"
)

const (
	// HeaderKey is the header that carries credentials: plaintext JSON between
	// the application and the proxy, sealed between the proxy and the Temporal
	// Service.
	HeaderKey = "credentials"

	// KeyHeaderKey is the reserved header an application names a sealing key in.
	// It never leaves the proxy.
	KeyHeaderKey = "credentials-key"

	// sealedEncoding marks a header payload as sealed by this package.
	sealedEncoding = "binary/credentials-sealed"
)

type (
	// Interceptor seals, opens and validates credentials headers.
	Interceptor struct {
		keys       *credentials.Keyset
		validators map[string]Validator
		log        logger.Logger
		now        func() time.Time
	}

	// Result is what the application receives in place of a header the proxy
	// opened: the validated credentials, or a failure marker. Reason is for the
	// Worker's own logs; the application must not echo it to the caller.
	Result struct {
		OK          bool                  `json:"ok"`
		Reason      string                `json:"reason,omitempty"`
		Credentials map[string]Credential `json:"credentials,omitempty"`
	}

	// Credential is one validated credential and the claims its validator
	// returned.
	Credential struct {
		Value  string         `json:"value"`
		Claims map[string]any `json:"claims,omitempty"`
	}

	// handled is the set of headers this request or response sealed or opened.
	// Every other credentials header is stripped.
	handled map[*common.Header]struct{}
)

// NewInterceptor returns an Interceptor sealing and opening with keys and
// validating with validators.
func NewInterceptor(keys *credentials.Keyset, validators map[string]Validator, log logger.Logger) *Interceptor {
	return &Interceptor{keys: keys, validators: validators, log: log, now: time.Now}
}

// Unary returns the interceptor as a unary client interceptor on the
// connection to the Temporal Service. It must run between the application and
// any payload codec, so the payloads it digests are the ones the application
// sent and receives.
func (i *Interceptor) Unary() grpc.UnaryClientInterceptor {
	return func(
		ctx context.Context,
		method string,
		req, reply any,
		cc *grpc.ClientConn,
		invoker grpc.UnaryInvoker,
		opts ...grpc.CallOption,
	) error {
		if m, ok := req.(proto.Message); ok {
			if err := i.outbound(m); err != nil {
				i.log.Warn("Refusing to forward credentials", tag.String("method", method), tag.Error(err))
				return status.Error(codes.InvalidArgument, "credentials: "+err.Error())
			}
		}

		if err := invoker(ctx, method, req, reply, cc, opts...); err != nil {
			return err
		}

		if m, ok := reply.(proto.Message); ok {
			i.inbound(ctx, req, m)
		}

		return nil
	}
}

// outbound seals every credentials header on a call it knows the context of,
// and strips the rest.
func (i *Interceptor) outbound(req proto.Message) error {
	done := handled{}

	var err error
	switch r := req.(type) {
	case *workflowservice.StartWorkflowExecutionRequest:
		err = i.sealHeader(done, r.GetHeader(), func() []byte {
			return credentials.WorkflowContext(r.GetNamespace(), r.GetWorkflowType().GetName(), r.GetWorkflowId(), r.GetInput().GetPayloads())
		})
	case *workflowservice.SignalWorkflowExecutionRequest:
		err = i.sealHeader(done, r.GetHeader(), func() []byte {
			return credentials.SignalContext(r.GetNamespace(), r.GetWorkflowExecution().GetWorkflowId(), r.GetSignalName(), r.GetInput().GetPayloads())
		})
	// SignalWithStart carries one header for both the start and the Signal, so it
	// can't be bound to either; like every call without a context, it is stripped.
	case *workflowservice.RespondWorkflowTaskCompletedRequest:
		err = i.sealCommands(done, r)
	}

	if err != nil {
		return err
	}

	stripHeaders(req, done)

	return nil
}

// sealCommands seals the headers of the commands a Workflow task completes
// with. The Workflow ID they are bound to comes from the task token.
func (i *Interceptor) sealCommands(done handled, r *workflowservice.RespondWorkflowTaskCompletedRequest) error {
	ns := r.GetNamespace()

	var (
		wfID    string
		wfIDErr error
		parsed  bool
	)
	workflowID := func() (string, error) {
		if !parsed {
			wfID, wfIDErr = workflowIDFromTaskToken(r.GetTaskToken())
			parsed = true
		}

		return wfID, wfIDErr
	}

	for _, cmd := range r.GetCommands() {
		switch cmd.GetCommandType() {
		case enums.COMMAND_TYPE_SCHEDULE_ACTIVITY_TASK:
			a := cmd.GetScheduleActivityTaskCommandAttributes()
			if !hasCredentials(a.GetHeader()) {
				continue
			}

			id, err := workflowID()
			if err != nil {
				return err
			}

			if err := i.sealHeader(done, a.GetHeader(), func() []byte {
				return credentials.ActivityContext(ns, id, a.GetActivityId(), a.GetActivityType().GetName(), a.GetInput().GetPayloads())
			}); err != nil {
				return fmt.Errorf("activity %q: %w", a.GetActivityId(), err)
			}
		case enums.COMMAND_TYPE_CONTINUE_AS_NEW_WORKFLOW_EXECUTION:
			a := cmd.GetContinueAsNewWorkflowExecutionCommandAttributes()
			if !hasCredentials(a.GetHeader()) {
				continue
			}

			id, err := workflowID()
			if err != nil {
				return err
			}

			if err := i.sealHeader(done, a.GetHeader(), func() []byte {
				return credentials.WorkflowContext(ns, a.GetWorkflowType().GetName(), id, a.GetInput().GetPayloads())
			}); err != nil {
				return fmt.Errorf("continue-as-new: %w", err)
			}
		case enums.COMMAND_TYPE_SCHEDULE_NEXUS_OPERATION:
			if err := i.sealNexus(cmd.GetScheduleNexusOperationCommandAttributes()); err != nil {
				return err
			}
		}
	}

	return nil
}

// sealNexus seals a Nexus operation's string header. Nexus headers aren't
// payloads, so the sealed value is the header string itself.
func (i *Interceptor) sealNexus(a *command.ScheduleNexusOperationCommandAttributes) error {
	h := a.GetNexusHeader()
	plain, ok := h[HeaderKey]
	keyName := h[KeyHeaderKey]
	delete(h, KeyHeaderKey)
	if !ok {
		return nil
	}

	creds, err := parsePlaintext([]byte(plain))
	if err != nil {
		return err
	}

	name, err := parseKeyName([]byte(keyName))
	if err != nil {
		return err
	}

	key, err := i.keys.SealingKey(name, a.GetEndpoint())
	if err != nil {
		return fmt.Errorf("nexus %s/%s/%s: %w", a.GetEndpoint(), a.GetService(), a.GetOperation(), err)
	}

	sealed, err := credentials.Seal(key, credentials.NexusContext(a.GetEndpoint(), a.GetService(), a.GetOperation(), a.GetInput()), creds)
	if err != nil {
		return err
	}

	h[HeaderKey] = sealed

	return nil
}

// sealHeader replaces h's plaintext credentials with a header sealed under the
// context info returns, to the key named in h or else the default. It does
// nothing when h carries no credentials.
func (i *Interceptor) sealHeader(done handled, h *common.Header, info func() []byte) error {
	fields := h.GetFields()
	keyPayload := fields[KeyHeaderKey]
	delete(fields, KeyHeaderKey)

	plain := fields[HeaderKey]
	if plain == nil {
		return nil
	}

	creds, err := parsePlaintext(plain.GetData())
	if err != nil {
		return err
	}

	name, err := parseKeyName(keyPayload.GetData())
	if err != nil {
		return err
	}

	key, err := i.keys.SealingKey(name, "")
	if err != nil {
		return err
	}

	sealed, err := credentials.Seal(key, info(), creds)
	if err != nil {
		return err
	}

	fields[HeaderKey] = &common.Payload{
		Metadata: map[string][]byte{"encoding": []byte(sealedEncoding)},
		Data:     []byte(sealed),
	}
	done[h] = struct{}{}

	return nil
}

func parsePlaintext(data []byte) (map[string]string, error) {
	var creds map[string]string
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("credentials header must be a JSON object of strings: %w", err)
	}

	return creds, nil
}

// parseKeyName reads the JSON string an application names a key with. An
// absent header names no key.
func parseKeyName(data []byte) (string, error) {
	if len(data) == 0 {
		return "", nil
	}

	var name string
	if err := json.Unmarshal(data, &name); err != nil {
		return "", fmt.Errorf("invalid %s header: %w", KeyHeaderKey, err)
	}

	return name, nil
}

// inbound opens the credentials headers on the tasks a Worker receives, and
// strips every other one.
func (i *Interceptor) inbound(ctx context.Context, req any, reply proto.Message) {
	done := handled{}
	ns := namespaceOf(req)

	switch r := reply.(type) {
	case *workflowservice.PollWorkflowTaskQueueResponse:
		i.openWorkflowTask(ctx, done, ns, r)
	case *workflowservice.RespondWorkflowTaskCompletedResponse:
		i.openWorkflowTask(ctx, done, ns, r.GetWorkflowTask())
		for _, t := range r.GetActivityTasks() {
			i.openActivityTask(ctx, done, ns, t)
		}
	case *workflowservice.StartWorkflowExecutionResponse:
		i.openWorkflowTask(ctx, done, ns, r.GetEagerWorkflowTask())
	case *workflowservice.GetWorkflowExecutionHistoryResponse:
		if hr, ok := req.(*workflowservice.GetWorkflowExecutionHistoryRequest); ok {
			i.openHistory(ctx, done, ns, hr.GetExecution().GetWorkflowId(), r.GetHistory())
		}
	case *workflowservice.PollActivityTaskQueueResponse:
		i.openActivityTask(ctx, done, ns, r)
	case *workflowservice.PollNexusTaskQueueResponse:
		i.openNexusRequest(ctx, r.GetRequest())
	}

	stripHeaders(reply, done)
}

func (i *Interceptor) openWorkflowTask(ctx context.Context, done handled, ns string, t *workflowservice.PollWorkflowTaskQueueResponse) {
	if t == nil {
		return
	}

	i.openHistory(ctx, done, ns, t.GetWorkflowExecution().GetWorkflowId(), t.GetHistory())
}

// openHistory opens the headers of the events a Workflow handles: its start
// and its Signals. They are validated against the time of the event rather
// than the current time, so a replay weeks later reaches the same decision.
func (i *Interceptor) openHistory(ctx context.Context, done handled, ns, wfID string, h *history.History) {
	for _, e := range h.GetEvents() {
		at := e.GetEventTime().AsTime()

		switch e.GetEventType() {
		case enums.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED:
			a := e.GetWorkflowExecutionStartedEventAttributes()
			i.openHeader(ctx, done, a.GetHeader(), at, func() []byte {
				return credentials.WorkflowContext(ns, a.GetWorkflowType().GetName(), wfID, a.GetInput().GetPayloads())
			})
		case enums.EVENT_TYPE_WORKFLOW_EXECUTION_SIGNALED:
			a := e.GetWorkflowExecutionSignaledEventAttributes()
			i.openHeader(ctx, done, a.GetHeader(), at, func() []byte {
				return credentials.SignalContext(ns, wfID, a.GetSignalName(), a.GetInput().GetPayloads())
			})
		}
	}
}

// openActivityTask opens an Activity task's header. Activities never replay,
// so they are validated against the current time.
func (i *Interceptor) openActivityTask(ctx context.Context, done handled, ns string, t *workflowservice.PollActivityTaskQueueResponse) {
	if t == nil {
		return
	}

	i.openHeader(ctx, done, t.GetHeader(), i.now(), func() []byte {
		return credentials.ActivityContext(
			ns, t.GetWorkflowExecution().GetWorkflowId(), t.GetActivityId(), t.GetActivityType().GetName(), t.GetInput().GetPayloads(),
		)
	})
}

// openNexusRequest opens a Nexus start request's header, bound to the
// endpoint the Temporal Service reports. A request without an endpoint (from a
// server too old to send one) fails closed.
func (i *Interceptor) openNexusRequest(ctx context.Context, r *nexus.Request) {
	h := r.GetHeader()
	if h == nil {
		return
	}

	delete(h, KeyHeaderKey)

	sealed, ok := h[HeaderKey]
	if !ok {
		return
	}

	start := r.GetStartOperation()
	if start == nil {
		delete(h, HeaderKey)
		return
	}

	var res Result
	if r.GetEndpoint() == "" {
		i.log.Warn("Nexus request carries credentials but no endpoint; the Temporal Service is too old")
		res = Result{Reason: "no endpoint context"}
	} else {
		info := credentials.NexusContext(r.GetEndpoint(), start.GetService(), start.GetOperation(), start.GetPayload())
		res = i.open(ctx, info, sealed, i.now())
	}

	h[HeaderKey] = string(mustJSON(res))
}

// openHeader replaces h's sealed credentials with the [Result] of opening and
// validating them.
func (i *Interceptor) openHeader(ctx context.Context, done handled, h *common.Header, at time.Time, info func() []byte) {
	fields := h.GetFields()
	delete(fields, KeyHeaderKey)

	p := fields[HeaderKey]
	if p == nil {
		return
	}

	res := i.open(ctx, info(), string(p.GetData()), at)
	fields[HeaderKey] = &common.Payload{
		Metadata: map[string][]byte{"encoding": []byte("json/plain")},
		Data:     mustJSON(res),
	}
	done[h] = struct{}{}
}

// open opens a sealed header under info and validates each credential at at.
// A credential with no validator is dropped. A credential that fails
// validation fails the whole header, required or not: a broken credential is
// suspicious.
func (i *Interceptor) open(ctx context.Context, info []byte, sealed string, at time.Time) Result {
	creds, err := i.keys.Open(info, sealed)
	if err != nil {
		i.log.Warn("Credentials header failed to open", tag.Error(err))
		return Result{Reason: "binding"}
	}

	out := make(map[string]Credential, len(creds))
	for name, value := range creds {
		v := i.validators[name]
		if v == nil {
			i.log.Warn("Dropping credential with no validator", tag.String("credential", name))
			continue
		}

		claims, err := v.Validate(ctx, value, at)
		if err != nil {
			i.log.Warn("Credential failed validation", tag.String("credential", name), tag.Error(err))
			return Result{Reason: "validation: " + name}
		}

		out[name] = Credential{Value: value, Claims: claims}
	}

	return Result{OK: true, Credentials: out}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		// Only claims a validator returned can fail to marshal, and they came from JSON.
		b, _ = json.Marshal(Result{Reason: "unencodable claims"})
	}

	return b
}

func hasCredentials(h *common.Header) bool {
	_, ok := h.GetFields()[HeaderKey]
	return ok
}

func namespaceOf(req any) string {
	if r, ok := req.(interface{ GetNamespace() string }); ok {
		return r.GetNamespace()
	}

	return ""
}

// workflowIDFromTaskToken reads the Workflow ID from a Workflow task token:
// field 2 of the Temporal Service's token.v1.Task message. The token is opaque
// to clients, but the proxy has no other source for the ID on a task
// completion, and failing to find it fails closed.
func workflowIDFromTaskToken(token []byte) (string, error) {
	b := token
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}

		b = b[n:]
		if num == 2 && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				break
			}

			return string(v), nil
		}

		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			break
		}

		b = b[n:]
	}

	return "", errors.New("cannot read the workflow ID from the task token")
}

var headerName = (&common.Header{}).ProtoReflect().Descriptor().FullName()

// stripHeaders removes the credentials headers from every Header in m that
// isn't in done, so a credential is never forwarded in plaintext and a
// plaintext one is never injected into the application.
func stripHeaders(m proto.Message, done handled) {
	walk(m.ProtoReflect(), func(h *common.Header) {
		if _, ok := done[h]; ok {
			return
		}

		delete(h.GetFields(), HeaderKey)
		delete(h.GetFields(), KeyHeaderKey)
	})
}

func walk(m protoreflect.Message, fn func(*common.Header)) {
	if m.Descriptor().FullName() == headerName {
		if h, ok := m.Interface().(*common.Header); ok {
			fn(h)
		}

		return
	}

	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsMap():
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				v.Map().Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					walk(mv.Message(), fn)
					return true
				})
			}
		case fd.IsList():
			if fd.Kind() == protoreflect.MessageKind {
				l := v.List()
				for j := range l.Len() {
					walk(l.Get(j).Message(), fn)
				}
			}
		case fd.Kind() == protoreflect.MessageKind:
			walk(v.Message(), fn)
		}

		return true
	})
}
