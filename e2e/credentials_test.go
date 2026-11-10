package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.temporal.io/api/common/v1"
	"go.temporal.io/api/history/v1"
	"go.temporal.io/api/query/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/contrib/credentials/binding"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"

	"go.temporal.io/proxy/internal/config"
	"go.temporal.io/proxy/internal/dataplane/dataplanetest"
)

// writeKeyset writes a keyset with one default key to a file the proxy loads,
// and returns its path and the parsed keyset, which stands in for the receiver.
func writeKeyset(t *testing.T) (string, *binding.Keyset) {
	t.Helper()

	k, err := binding.GenerateKey("agents")
	require.NoError(t, err)

	f := binding.KeysetJSON{Keys: []binding.KeyJSON{k}, Default: "agents"}
	data, err := json.Marshal(f)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "keyset.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	ks, err := binding.NewKeyset(f)
	require.NoError(t, err)

	return path, ks
}

// TestEndToEndCredentialBinding drives credentials through the full stack with
// payload encryption on. The application attaches plaintext credentials; the
// upstream sees only a sealed header bound to the payload bytes it stores,
// which are encrypted, so a Worker behind an SDK binding layer, which digests
// what the Temporal Service holds, opens it too. On the way back, the
// application gets the opened credentials and the decrypted input.
func TestEndToEndCredentialBinding(t *testing.T) {
	t.Parallel()

	up := dataplanetest.NewUpstream(t)
	keysetPath, receiver := writeKeyset(t)

	cfg := dataplanetest.Config(up)
	cfg.Encryption = config.Encryption{
		Enabled:          true,
		NamespaceBinding: config.NamespaceBindingStrict,
		Default:          &config.KeyPolicy{URI: testingKeyURI(t), Duration: time.Hour},
	}
	cfg.Credentials = &config.Credentials{Keyset: keysetPath}

	f := dataplanetest.StartApp(t, cfg)

	input := &common.Payload{Metadata: map[string][]byte{wireEncoding: []byte("json/plain")}, Data: []byte(`"plan"`)}
	creds := map[string]string{"user_token": "eyJ-user"}

	var md metadata.MD
	_, err := f.Client().StartWorkflowExecution(f.Context(), &workflowservice.StartWorkflowExecutionRequest{
		Namespace:    "ns1",
		WorkflowId:   "wf-1",
		WorkflowType: &common.WorkflowType{Name: "Agent"},
		Input:        &common.Payloads{Payloads: []*common.Payload{input}},
		Header:       &common.Header{Fields: map[string]*common.Payload{binding.HeaderCredentials: binding.PendingPayload(creds)}},
	}, grpc.WaitForReady(true), grpc.Header(&md))
	require.NoError(t, err)
	require.True(t, binding.IsAdvertised(md), "the proxy must identify itself as a credential-binding proxy")

	reqs := up.Requests()
	require.Len(t, reqs, 1)
	got, ok := reqs[0].(*workflowservice.StartWorkflowExecutionRequest)
	require.True(t, ok)

	stored := got.GetInput().GetPayloads()
	require.Equal(t, wireEncryptedMarker, string(stored[0].GetMetadata()[wireEncoding]))

	sealed := got.GetHeader().GetFields()[binding.HeaderCredentials]
	require.Equal(t, binding.EncodingSealed, string(sealed.GetMetadata()[wireEncoding]), "the codec must pass credentials through")
	require.NotContains(t, string(sealed.GetData()), "eyJ")

	opened, err := receiver.Open(binding.WorkflowContext("ns1", "Agent", "wf-1", stored), string(sealed.GetData()))
	require.NoError(t, err, "the header must be bound to the encrypted bytes the Temporal Service stores")
	require.Equal(t, creds, opened)

	up.SetWorkflowTask(&workflowservice.PollWorkflowTaskQueueResponse{
		WorkflowExecution: &common.WorkflowExecution{WorkflowId: "wf-1"},
		History: &history.History{Events: []*history.HistoryEvent{{
			EventId: 1,
			Attributes: &history.HistoryEvent_WorkflowExecutionStartedEventAttributes{
				WorkflowExecutionStartedEventAttributes: &history.WorkflowExecutionStartedEventAttributes{
					WorkflowType: &common.WorkflowType{Name: "Agent"},
					Input:        &common.Payloads{Payloads: stored},
					Header:       got.GetHeader(),
				},
			},
		}}},
	})

	task, err := f.Client().PollWorkflowTaskQueue(f.Context(), &workflowservice.PollWorkflowTaskQueueRequest{Namespace: "ns1"}, grpc.WaitForReady(true))
	require.NoError(t, err)

	started := task.GetHistory().GetEvents()[0].GetWorkflowExecutionStartedEventAttributes()
	require.True(t, proto.Equal(input, started.GetInput().GetPayloads()[0]), "the input must be decrypted")

	res, ok := binding.OpenedFromHeader(started.GetHeader().GetFields())
	require.True(t, ok)
	require.True(t, res.OK, res.Reason)
	require.Equal(t, creds, res.Credentials)
}

// TestEndToEndCredentialsNeverLeaveInPlaintext sends plaintext credentials on
// a call with no context to bind them to. The proxy drops them.
func TestEndToEndCredentialsNeverLeaveInPlaintext(t *testing.T) {
	t.Parallel()

	up := dataplanetest.NewUpstream(t)
	keysetPath, _ := writeKeyset(t)

	cfg := dataplanetest.Config(up)
	cfg.Credentials = &config.Credentials{Keyset: keysetPath}

	f := dataplanetest.StartApp(t, cfg)

	_, err := f.Client().QueryWorkflow(f.Context(), &workflowservice.QueryWorkflowRequest{
		Namespace: "ns1",
		Execution: &common.WorkflowExecution{WorkflowId: "wf-1"},
		Query: &query.WorkflowQuery{QueryType: "state", Header: &common.Header{Fields: map[string]*common.Payload{
			binding.HeaderCredentials: binding.PendingPayload(map[string]string{"user_token": "eyJ-user"}),
			binding.HeaderKey:         binding.KeyPayload("agents"),
		}}},
	}, grpc.WaitForReady(true))
	require.NoError(t, err)

	reqs := up.Requests()
	require.Len(t, reqs, 1)
	got, ok := reqs[0].(*workflowservice.QueryWorkflowRequest)
	require.True(t, ok)
	require.Empty(t, got.GetQuery().GetHeader().GetFields())
}

// TestEndToEndNoAdvertisementWithoutCredentials keeps a proxy that doesn't
// bind credentials from inviting applications to send them in plaintext.
func TestEndToEndNoAdvertisementWithoutCredentials(t *testing.T) {
	t.Parallel()

	up := dataplanetest.NewUpstream(t)
	f := dataplanetest.StartApp(t, dataplanetest.Config(up))

	var md metadata.MD
	_, err := f.Client().GetSystemInfo(f.Context(), &workflowservice.GetSystemInfoRequest{}, grpc.WaitForReady(true), grpc.Header(&md))
	require.NoError(t, err)
	require.False(t, binding.IsAdvertised(md))
}
