package credentials_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"go.temporal.io/api/command/v1"
	"go.temporal.io/api/common/v1"
	"go.temporal.io/api/enums/v1"
	"go.temporal.io/api/history/v1"
	"go.temporal.io/api/nexus/v1"
	"go.temporal.io/api/taskqueue/v1"
	"go.temporal.io/api/update/v1"
	"go.temporal.io/api/workflowservice/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"go.temporal.io/proxy/internal/config"
	"go.temporal.io/proxy/internal/credentials"
	pkgcredentials "go.temporal.io/proxy/pkg/credentials"
	"go.temporal.io/proxy/pkg/logger"
)

type fixture struct {
	t      *testing.T
	signer *ecdsa.PrivateKey
	unary  grpc.UnaryClientInterceptor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	signer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pub, err := signer.PublicKey.Bytes() // uncompressed point: 0x04 | X | Y
	require.NoError(t, err)

	jwks := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","alg":"ES256","use":"sig","x":%q,"y":%q}]}`,
		b64(pub[1:33]), b64(pub[33:]))
	jwksPath := filepath.Join(t.TempDir(), "jwks.json")
	require.NoError(t, os.WriteFile(jwksPath, []byte(jwks), 0o600))

	keyset := fmt.Sprintf(`{"keys":[%s,%s],"default":"agents","nexusEndpoints":{"payments-ep":"payments"}}`,
		hpkeKey(t, "agents", "0000000001"), hpkeKey(t, "payments", "0000000002"))
	keys, err := pkgcredentials.ParseKeyset([]byte(keyset), false)
	require.NoError(t, err)

	validators, err := credentials.NewValidators(context.Background(), map[string]config.CredentialValidator{
		"user_token": {JWT: &config.JWTValidator{JWKSFile: jwksPath, Audience: []string{"agents"}, Issuer: "https://issuer.test"}},
	})
	require.NoError(t, err)

	return &fixture{t: t, signer: signer, unary: credentials.NewInterceptor(keys, validators, logger.NewNoopLogger()).Unary()}
}

func hpkeKey(t *testing.T, name, id string) string {
	t.Helper()

	sk, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	return fmt.Sprintf(`{"name":%q,"id":%q,"public":%q,"private":%q}`, name, id, b64(sk.PublicKey().Bytes()), b64(sk.Bytes()))
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (f *fixture) token(sub string, exp time.Time) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": sub, "aud": "agents", "iss": "https://issuer.test", "exp": exp.Unix(),
	})
	tok.Header["kid"] = "k1"

	s, err := tok.SignedString(f.signer)
	require.NoError(f.t, err)

	return s
}

// send runs req through the interceptor outbound and returns what reached the
// Temporal Service.
func (f *fixture) send(req proto.Message) (proto.Message, error) {
	var sent proto.Message
	err := f.unary(context.Background(), "/m", req, &workflowservice.SignalWorkflowExecutionResponse{}, nil,
		func(_ context.Context, _ string, req, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			sent = proto.Clone(req.(proto.Message))
			return nil
		})

	return sent, err
}

// receive runs reply through the interceptor inbound, as the response to req.
func (f *fixture) receive(req, reply proto.Message) proto.Message {
	out := reply.ProtoReflect().New().Interface()
	err := f.unary(context.Background(), "/m", req, out, nil,
		func(_ context.Context, _ string, _, r any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			proto.Merge(r.(proto.Message), reply)
			return nil
		})
	require.NoError(f.t, err)

	return out
}

func plainHeader(creds map[string]string) *common.Header {
	b, _ := json.Marshal(creds)
	return &common.Header{Fields: map[string]*common.Payload{"credentials": {Data: b}}}
}

func input(s string) *common.Payloads {
	return &common.Payloads{Payloads: []*common.Payload{{Metadata: map[string][]byte{"encoding": []byte("json/plain")}, Data: []byte(s)}}}
}

func result(t *testing.T, p *common.Payload) credentials.Result {
	t.Helper()
	require.NotNil(t, p, "no credentials header")

	var r credentials.Result
	require.NoError(t, json.Unmarshal(p.GetData(), &r))

	return r
}

func startedTask(wfID string, sealed *common.Header, in *common.Payloads, at time.Time) *workflowservice.PollWorkflowTaskQueueResponse {
	return &workflowservice.PollWorkflowTaskQueueResponse{
		WorkflowExecution: &common.WorkflowExecution{WorkflowId: wfID},
		History: &history.History{Events: []*history.HistoryEvent{{
			EventId:   1,
			EventTime: timestamppb.New(at),
			EventType: enums.EVENT_TYPE_WORKFLOW_EXECUTION_STARTED,
			Attributes: &history.HistoryEvent_WorkflowExecutionStartedEventAttributes{
				WorkflowExecutionStartedEventAttributes: &history.WorkflowExecutionStartedEventAttributes{
					WorkflowType: &common.WorkflowType{Name: "Agent"},
					Input:        in,
					Header:       sealed,
				},
			},
		}}},
	}
}

func startedResult(t *testing.T, m proto.Message) credentials.Result {
	t.Helper()

	task := m.(*workflowservice.PollWorkflowTaskQueueResponse)

	return result(t, task.GetHistory().GetEvents()[0].GetWorkflowExecutionStartedEventAttributes().GetHeader().GetFields()["credentials"])
}

func (f *fixture) start(wfID string, creds map[string]string, in *common.Payloads) *common.Header {
	sent, err := f.send(&workflowservice.StartWorkflowExecutionRequest{
		Namespace: "default", WorkflowId: wfID, WorkflowType: &common.WorkflowType{Name: "Agent"},
		Input: in, Header: plainHeader(creds),
	})
	require.NoError(f.t, err)

	return sent.(*workflowservice.StartWorkflowExecutionRequest).GetHeader()
}

var pollReq = &workflowservice.PollWorkflowTaskQueueRequest{Namespace: "default"}

func TestWorkflowStartRoundTrip(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tok := f.token("alice", time.Now().Add(time.Hour))
	sealed := f.start("wf-1", map[string]string{"user_token": tok, "unvalidated": "x"}, input(`"hi"`))
	require.Equal(t, "binary/credentials-sealed", string(sealed.GetFields()["credentials"].GetMetadata()["encoding"]))
	require.NotContains(t, string(sealed.GetFields()["credentials"].GetData()), tok)

	r := startedResult(t, f.receive(pollReq, startedTask("wf-1", sealed, input(`"hi"`), time.Now())))
	require.True(t, r.OK, r.Reason)
	require.Equal(t, tok, r.Credentials["user_token"].Value)
	require.Equal(t, "alice", r.Credentials["user_token"].Claims["sub"])
	require.NotContains(t, r.Credentials, "unvalidated", "credentials with no validator are dropped")
}

func TestWorkflowStartRejectsMovedOrTamperedHeader(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	sealed := f.start("wf-1", map[string]string{"user_token": f.token("alice", time.Now().Add(time.Hour))}, input(`"hi"`))

	for name, task := range map[string]*workflowservice.PollWorkflowTaskQueueResponse{
		"other workflow ID": startedTask("wf-2", proto.Clone(sealed).(*common.Header), input(`"hi"`), time.Now()),
		"other input":       startedTask("wf-1", proto.Clone(sealed).(*common.Header), input(`"bye"`), time.Now()),
		"plaintext":         startedTask("wf-1", plainHeader(map[string]string{"user_token": "forged"}), input(`"hi"`), time.Now()),
	} {
		r := startedResult(t, f.receive(pollReq, task))
		require.False(t, r.OK, name)
		require.Equal(t, "binding", r.Reason, name)
		require.Empty(t, r.Credentials, name)
	}
}

func TestWorkflowValidationUsesEventTime(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Valid when the Workflow started, expired now: a replay must still accept it.
	started := time.Now().Add(-2 * time.Hour)
	sealed := f.start("wf-1", map[string]string{"user_token": f.token("alice", started.Add(time.Hour))}, input(`"hi"`))
	r := startedResult(t, f.receive(pollReq, startedTask("wf-1", sealed, input(`"hi"`), started)))
	require.True(t, r.OK, r.Reason)

	// Expired when the Workflow started: rejected, whatever the current time.
	sealed = f.start("wf-2", map[string]string{"user_token": f.token("alice", time.Now().Add(-time.Minute))}, input(`"hi"`))
	r = startedResult(t, f.receive(pollReq, startedTask("wf-2", sealed, input(`"hi"`), time.Now())))
	require.False(t, r.OK)
	require.Equal(t, "validation: user_token", r.Reason)
}

func taskToken(wfID string) []byte {
	b := protowire.AppendTag(nil, 1, protowire.BytesType)
	b = protowire.AppendString(b, "ns-uuid")
	b = protowire.AppendTag(b, 2, protowire.BytesType)

	return protowire.AppendString(b, wfID)
}

func TestActivityRoundTrip(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tok := f.token("alice", time.Now().Add(time.Hour))
	sent, err := f.send(&workflowservice.RespondWorkflowTaskCompletedRequest{
		Namespace: "default",
		TaskToken: taskToken("wf-1"),
		Commands: []*command.Command{{
			CommandType: enums.COMMAND_TYPE_SCHEDULE_ACTIVITY_TASK,
			Attributes: &command.Command_ScheduleActivityTaskCommandAttributes{
				ScheduleActivityTaskCommandAttributes: &command.ScheduleActivityTaskCommandAttributes{
					ActivityId: "1", ActivityType: &common.ActivityType{Name: "call_llm"},
					Input: input(`"plan"`), Header: plainHeader(map[string]string{"user_token": tok}),
				},
			},
		}},
	})
	require.NoError(t, err)

	sealed := sent.(*workflowservice.RespondWorkflowTaskCompletedRequest).GetCommands()[0].GetScheduleActivityTaskCommandAttributes().GetHeader()

	task := func(activityID string) credentials.Result {
		got := f.receive(&workflowservice.PollActivityTaskQueueRequest{Namespace: "default"}, &workflowservice.PollActivityTaskQueueResponse{
			WorkflowExecution: &common.WorkflowExecution{WorkflowId: "wf-1"},
			ActivityId:        activityID, ActivityType: &common.ActivityType{Name: "call_llm"},
			Input: input(`"plan"`), Header: proto.Clone(sealed).(*common.Header),
		}).(*workflowservice.PollActivityTaskQueueResponse)

		return result(t, got.GetHeader().GetFields()["credentials"])
	}

	r := task("1")
	require.True(t, r.OK, r.Reason)
	require.Equal(t, tok, r.Credentials["user_token"].Value)

	require.Equal(t, "binding", task("2").Reason)
}

func TestNexusRoundTripAndEndpointOverride(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	tok := f.token("alice", time.Now().Add(time.Hour))
	schedule := func(endpoint string) string {
		creds, _ := json.Marshal(map[string]string{"user_token": tok})
		sent, err := f.send(&workflowservice.RespondWorkflowTaskCompletedRequest{
			Namespace: "default",
			TaskToken: taskToken("wf-1"),
			Commands: []*command.Command{{
				CommandType: enums.COMMAND_TYPE_SCHEDULE_NEXUS_OPERATION,
				Attributes: &command.Command_ScheduleNexusOperationCommandAttributes{
					ScheduleNexusOperationCommandAttributes: &command.ScheduleNexusOperationCommandAttributes{
						Endpoint: endpoint, Service: "Svc", Operation: "op",
						Input:       input(`"x"`).GetPayloads()[0],
						NexusHeader: map[string]string{"credentials": string(creds)},
					},
				},
			}},
		})
		require.NoError(t, err)

		return sent.(*workflowservice.RespondWorkflowTaskCompletedRequest).GetCommands()[0].
			GetScheduleNexusOperationCommandAttributes().GetNexusHeader()["credentials"]
	}

	receive := func(endpoint, sealed string) credentials.Result {
		got := f.receive(&workflowservice.PollNexusTaskQueueRequest{Namespace: "default"}, &workflowservice.PollNexusTaskQueueResponse{
			Request: &nexus.Request{
				Header:   map[string]string{"credentials": sealed},
				Endpoint: endpoint,
				Variant: &nexus.Request_StartOperation{StartOperation: &nexus.StartOperationRequest{
					Service: "Svc", Operation: "op", Payload: input(`"x"`).GetPayloads()[0],
				}},
			},
		}).(*workflowservice.PollNexusTaskQueueResponse)

		var r credentials.Result
		require.NoError(t, json.Unmarshal([]byte(got.GetRequest().GetHeader()["credentials"]), &r))

		return r
	}

	sealed := schedule("tools-ep")
	require.NotContains(t, sealed, tok)

	r := receive("tools-ep", sealed)
	require.True(t, r.OK, r.Reason)
	require.Equal(t, "alice", r.Credentials["user_token"].Claims["sub"])
	require.Equal(t, "binding", receive("payments-ep", sealed).Reason, "moved to another endpoint")
	require.False(t, receive("", sealed).OK, "no endpoint context")

	// Sealed to the payments key by the endpoint override, and opens there.
	paymentsSealed := schedule("payments-ep")
	raw, err := base64.RawURLEncoding.DecodeString(paymentsSealed[len(pkgcredentials.HeaderPrefix):])
	require.NoError(t, err)
	require.Equal(t, []byte{0, 0, 0, 0, 2}, raw[:pkgcredentials.KeyIDSize])
	require.True(t, receive("payments-ep", paymentsSealed).OK)
}

func TestUnsupportedCallsAreStripped(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// Outbound: an Update has no defined context, so its credentials never leave in plaintext.
	sent, err := f.send(&workflowservice.UpdateWorkflowExecutionRequest{
		Namespace: "default",
		Request: &update.Request{Input: &update.Input{
			Name: "u", Header: plainHeader(map[string]string{"user_token": "secret"}),
		}},
	})
	require.NoError(t, err)
	require.Empty(t, sent.(*workflowservice.UpdateWorkflowExecutionRequest).GetRequest().GetInput().GetHeader().GetFields())

	// Inbound: a header on an event the proxy doesn't open is never handed to the Worker.
	got := f.receive(pollReq, &workflowservice.PollWorkflowTaskQueueResponse{
		WorkflowExecution: &common.WorkflowExecution{WorkflowId: "wf-1"},
		History: &history.History{Events: []*history.HistoryEvent{{
			EventType: enums.EVENT_TYPE_ACTIVITY_TASK_SCHEDULED,
			Attributes: &history.HistoryEvent_ActivityTaskScheduledEventAttributes{
				ActivityTaskScheduledEventAttributes: &history.ActivityTaskScheduledEventAttributes{
					TaskQueue: &taskqueue.TaskQueue{Name: "tq"},
					Header:    plainHeader(map[string]string{"user_token": "injected"}),
				},
			},
		}}},
	}).(*workflowservice.PollWorkflowTaskQueueResponse)
	require.Empty(t, got.GetHistory().GetEvents()[0].GetActivityTaskScheduledEventAttributes().GetHeader().GetFields())
}

func TestUnknownKeyNameRefusesTheCall(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	h := plainHeader(map[string]string{"user_token": "t"})
	h.Fields["credentials-key"] = &common.Payload{Data: []byte(`"nope"`)}
	_, err := f.send(&workflowservice.StartWorkflowExecutionRequest{
		Namespace: "default", WorkflowId: "wf", WorkflowType: &common.WorkflowType{Name: "Agent"}, Header: h,
	})
	require.ErrorContains(t, err, "unknown key name")
}
