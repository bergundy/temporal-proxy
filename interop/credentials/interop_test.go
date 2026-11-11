package credentials_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nexus-rpc/sdk-go/nexus"
	"github.com/stretchr/testify/require"
	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	historypb "go.temporal.io/api/history/v1"
	nexuspb "go.temporal.io/api/nexus/v1"
	"go.temporal.io/api/operatorservice/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/contrib/credentials"
	"go.temporal.io/sdk/contrib/credentials/binding"
	"go.temporal.io/sdk/contrib/credentials/jwt"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"go.temporal.io/proxy/internal/config"
	"go.temporal.io/proxy/internal/dataplane/dataplanetest"
)

const (
	namespace = "default"
	missing   = "missing"
)

// devServer is the Temporal dev server every test shares, behind or beside a
// proxy.
var devServer string

func TestMain(m *testing.M) {
	srv, err := testsuite.StartDevServer(context.Background(), testsuite.DevServerOptions{
		CachedDownload: testsuite.CachedDownload{Version: "v1.9.3-nexus-serialization-context"},
		ClientOptions:  &client.Options{Namespace: namespace},
		LogLevel:       "warn",
		ExtraArgs: []string{
			"--dynamic-config-value", "frontend.enableExecuteMultiOperation=true",
			"--dynamic-config-value", "frontend.enableUpdateWorkflowExecution=true",
			"--dynamic-config-value", "frontend.activityAPIsEnabled=true",
			"--dynamic-config-value", "nexusoperation.enableStandalone=true",
			"--dynamic-config-value", "history.enableChasm=true",
			"--dynamic-config-value", "history.enableCHASMCallbacks=true",
			"--dynamic-config-value", `system.refreshNexusEndpointsMinWait="0s"`,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed starting dev server: %v\n", err)
		os.Exit(1)
	}
	devServer = srv.FrontendHostPort()
	code := m.Run()
	_ = srv.Stop()
	os.Exit(code)
}

type keys struct{ agents binding.KeyJSON }

func newKeys(t *testing.T) keys {
	t.Helper()
	k, err := binding.GenerateKey("agents")
	require.NoError(t, err)
	return keys{agents: k}
}

func (k keys) json(private bool) binding.KeysetJSON {
	key := k.agents
	if !private {
		key = key.PublicOnly()
	}
	return binding.KeysetJSON{Keys: []binding.KeyJSON{key}, Default: "agents"}
}

func (k keys) keyset(t *testing.T, private bool) *binding.Keyset {
	t.Helper()
	ks, err := binding.NewKeyset(k.json(private))
	require.NoError(t, err)
	return ks
}

// startProxy runs a proxy in front of the dev server, binding credentials
// with k's private key and, with encrypt, encrypting payloads.
func startProxy(t *testing.T, k keys, encrypt bool) string {
	t.Helper()
	data, err := json.Marshal(k.json(true))
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "keyset.json")
	require.NoError(t, os.WriteFile(path, data, 0o600))

	cfg := &config.Config{
		Routing: config.Routing{DefaultUpstream: "temporal"},
		Upstreams: config.UpstreamList{{
			Name:   "temporal",
			Listen: config.ListenConfig{HostPort: devServer, Insecure: true},
		}},
		Credentials: &config.Credentials{Keyset: path},
	}
	if encrypt {
		key, err := url.Parse("testing://" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{'k'}, 32)))
		require.NoError(t, err)
		cfg.Encryption = config.Encryption{
			Enabled:          true,
			NamespaceBinding: config.NamespaceBindingStrict,
			Default:          &config.KeyPolicy{URI: *key, Duration: time.Hour},
		}
	}
	return dataplanetest.StartApp(t, cfg).Addr()
}

func dial(t *testing.T, hostPort string, plugins ...client.Plugin) client.Client {
	t.Helper()
	c, err := client.Dial(client.Options{HostPort: hostPort, Namespace: namespace, Plugins: plugins})
	require.NoError(t, err)
	t.Cleanup(c.Close)
	return c
}

func newPlugin(t *testing.T, opts credentials.PluginOptions) *credentials.Plugin {
	t.Helper()
	p, err := credentials.NewPlugin(opts)
	require.NoError(t, err)
	return p
}

// proxyClient is an application in proxy mode, connected to the proxy.
func proxyClient(t *testing.T, proxy string) client.Client {
	return dial(t, proxy, newPlugin(t, credentials.PluginOptions{Proxy: true}))
}

// directClient is an application running the binding layer itself,
// connected straight to the Temporal Service.
func directClient(t *testing.T, ks *binding.Keyset) client.Client {
	return dial(t, devServer, newPlugin(t, credentials.PluginOptions{Keyset: ks}))
}

func newID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func startWorker(t *testing.T, c client.Client, taskQueue string) {
	t.Helper()
	w := worker.New(c, taskQueue, worker.Options{})
	for _, wf := range []any{Agent, Chain, ChildToken, Approval, SignalKeeper, UpdateWithStart} {
		w.RegisterWorkflow(wf)
	}
	w.RegisterActivity(TokenOf)
	s := nexus.NewService("tools")
	require.NoError(t, s.Register(tokenOp))
	w.RegisterNexusService(s)
	require.NoError(t, w.Start())
	t.Cleanup(w.Stop)
}

func createEndpoint(t *testing.T, taskQueue string) string {
	t.Helper()
	name := newID("ep")
	_, err := dial(t, devServer).OperatorService().CreateNexusEndpoint(context.Background(), &operatorservice.CreateNexusEndpointRequest{
		Spec: &nexuspb.EndpointSpec{Name: name, Target: &nexuspb.EndpointTarget{Variant: &nexuspb.EndpointTarget_Worker_{
			Worker: &nexuspb.EndpointTarget_Worker{Namespace: namespace, TaskQueue: taskQueue},
		}}},
	})
	require.NoError(t, err)
	return name
}

func startOpts(taskQueue string) client.StartWorkflowOptions {
	return client.StartWorkflowOptions{ID: newID("wf"), TaskQueue: taskQueue, WorkflowExecutionTimeout: time.Minute}
}

func user(token string) context.Context {
	return credentials.Attach(context.Background(), credentials.Values{"user_token": token})
}

func isMissing(err error) bool {
	var appErr *temporal.ApplicationError
	if errors.As(err, &appErr) {
		return appErr.Type() == credentials.ErrorTypeCredentialMissing
	}
	var handlerErr *nexus.HandlerError
	return errors.As(err, &handlerErr) && handlerErr.Type == nexus.HandlerErrorTypeUnauthenticated
}

func TokenOf(ctx context.Context, name string) (string, error) {
	cred, err := credentials.Get(ctx, name)
	if isMissing(err) {
		return missing, nil
	}
	return cred.Reveal(), err
}

var tokenOp = nexus.NewSyncOperation("token", func(ctx context.Context, name string, _ nexus.StartOperationOptions) (string, error) {
	cred, err := credentials.Get(ctx, name)
	if isMissing(err) {
		return missing, nil
	}
	return cred.Reveal(), err
})

var activityOptions = workflow.ActivityOptions{StartToCloseTimeout: time.Minute}

func Agent(ctx workflow.Context, endpoints []string) (map[string]string, error) {
	if err := credentials.Require(ctx, "user_token"); err != nil {
		return nil, err
	}
	ctx = workflow.WithActivityOptions(ctx, activityOptions)
	out := map[string]string{}
	var s string
	if err := workflow.ExecuteActivity(credentials.Propagate(ctx, "user_token"), TokenOf, "user_token").Get(ctx, &s); err != nil {
		return nil, err
	}
	out["activity"] = s
	for _, ep := range endpoints {
		var n string
		c := workflow.NewNexusClient(ep, "tools")
		if err := c.ExecuteOperation(credentials.Propagate(ctx, "user_token"), tokenOp, "user_token", workflow.NexusOperationOptions{}).Get(ctx, &n); err != nil {
			return nil, err
		}
		out["nexus"] = n
	}
	return out, nil
}

func Chain(ctx workflow.Context, iteration int) (string, error) {
	if err := credentials.Require(ctx, "user_token"); err != nil {
		return "", err
	}
	if iteration == 0 {
		return "", workflow.NewContinueAsNewError(credentials.PropagateAll(ctx), Chain, 1)
	}
	var s string
	err := workflow.ExecuteChildWorkflow(credentials.Propagate(ctx, "user_token"), ChildToken).Get(ctx, &s)
	return s, err
}

func ChildToken(ctx workflow.Context) (string, error) {
	cred, err := credentials.Get(ctx, "user_token")
	return cred.Reveal(), err
}

func Approval(ctx workflow.Context) (map[string]string, error) {
	if err := credentials.Require(ctx, "user_token"); err != nil {
		return nil, err
	}
	ctx = workflow.WithActivityOptions(ctx, activityOptions)
	if err := workflow.SetUpdateHandlerWithOptions(ctx, "approve",
		func(ctx workflow.Context) error {
			return credentials.Retain(ctx, "approver_token", credentials.IfAbsent)
		},
		workflow.UpdateHandlerOptions{Validator: func(ctx workflow.Context) error {
			return credentials.CheckRetain(ctx, "approver_token", credentials.IfAbsent)
		}},
	); err != nil {
		return nil, err
	}
	if err := workflow.SetUpdateHandlerWithOptions(ctx, "refresh",
		func(ctx workflow.Context) error { return credentials.Retain(ctx, "user_token", jwt.SameSubject) },
		workflow.UpdateHandlerOptions{Validator: func(ctx workflow.Context) error {
			return credentials.CheckRetain(ctx, "user_token", jwt.SameSubject)
		}},
	); err != nil {
		return nil, err
	}
	workflow.GetSignalChannel(ctx, "done").Receive(ctx, nil)
	out := map[string]string{}
	for _, name := range []string{"user_token", "approver_token"} {
		var s string
		if err := workflow.ExecuteActivity(credentials.Propagate(ctx, name), TokenOf, name).Get(ctx, &s); err != nil {
			return nil, err
		}
		out[name] = s
	}
	return out, nil
}

func SignalKeeper(ctx workflow.Context) ([]string, error) {
	ctx = workflow.WithActivityOptions(ctx, activityOptions)
	var out []string
	if err := credentials.Require(ctx, "user_token"); err != nil {
		out = append(out, "start-without-credentials")
	}
	c := workflow.GetSignalChannel(ctx, "approve")
	c.Receive(ctx, nil)
	if err := credentials.RetainFromSignal(ctx, c, "user_token", credentials.IfAbsent); err != nil {
		return append(out, "skipped"), nil
	}
	var s string
	err := workflow.ExecuteActivity(credentials.Propagate(ctx, "user_token"), TokenOf, "user_token").Get(ctx, &s)
	return append(out, s), err
}

func UpdateWithStart(ctx workflow.Context) (string, error) {
	start := credentials.Require(ctx, "user_token")
	handled := false
	if err := workflow.SetUpdateHandler(ctx, "token", func(ctx workflow.Context) (string, error) {
		handled = true
		cred, err := credentials.Get(ctx, "user_token")
		return cred.Reveal(), err
	}); err != nil {
		return "", err
	}
	if err := workflow.Await(ctx, func() bool { return handled }); err != nil {
		return "", err
	}
	if start != nil {
		return "", start
	}
	return "start-ok", nil
}

func jwtFor(sub, nonce string) string {
	b64 := base64.RawURLEncoding.EncodeToString
	return b64([]byte(`{"alg":"none"}`)) + "." + b64([]byte(`{"iss":"idp","sub":"`+sub+`","n":"`+nonce+`"}`)) + ".sig"
}

func startedEvent(t *testing.T, wfID, runID string) *commonpb.Header {
	t.Helper()
	iter := dial(t, devServer).GetWorkflowHistory(context.Background(), wfID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	e, err := iter.Next()
	require.NoError(t, err)
	return e.GetWorkflowExecutionStartedEventAttributes().GetHeader()
}

// TestProxyMode runs applications in proxy mode, clients and Workers alike,
// behind a proxy that binds their credentials.
func TestProxyMode(t *testing.T) {
	k := newKeys(t)
	proxy := startProxy(t, k, false)
	c := proxyClient(t, proxy)
	tq := newID("tq")
	startWorker(t, c, tq)
	ep := createEndpoint(t, tq)

	t.Run("Activity and Nexus", func(t *testing.T) {
		run, err := c.ExecuteWorkflow(user("eyJ-user"), startOpts(tq), Agent, []string{ep})
		require.NoError(t, err)
		var got map[string]string
		require.NoError(t, run.Get(context.Background(), &got))
		require.Equal(t, map[string]string{"activity": "eyJ-user", "nexus": "eyJ-user"}, got)

		p := startedEvent(t, run.GetID(), run.GetRunID()).GetFields()[binding.HeaderCredentials]
		require.Equal(t, binding.EncodingSealed, string(p.GetMetadata()["encoding"]), "the Temporal Service holds only ciphertext")

		// The same header, copied to another Workflow by a raw client, doesn't open.
		started := startedEvent(t, run.GetID(), run.GetRunID())
		input, err := dial(t, devServer).GetWorkflowHistory(context.Background(), run.GetID(), run.GetRunID(), false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT).Next()
		require.NoError(t, err)
		copied := newID("wf")
		_, err = dial(t, devServer).WorkflowService().StartWorkflowExecution(context.Background(), &workflowservice.StartWorkflowExecutionRequest{
			Namespace: namespace, WorkflowId: copied, WorkflowType: &commonpb.WorkflowType{Name: "Agent"},
			TaskQueue: input.GetWorkflowExecutionStartedEventAttributes().GetTaskQueue(),
			Input:     input.GetWorkflowExecutionStartedEventAttributes().GetInput(), Header: started, RequestId: copied,
		})
		require.NoError(t, err)
		err = c.GetWorkflow(context.Background(), copied, "").Get(context.Background(), nil)
		require.True(t, isMissing(err), "got %v", err)
	})

	t.Run("continue-as-new and child Workflows", func(t *testing.T) {
		run, err := c.ExecuteWorkflow(user("eyJ-user"), startOpts(tq), Chain, 0)
		require.NoError(t, err)
		var got string
		require.NoError(t, run.Get(context.Background(), &got))
		require.Equal(t, "eyJ-user", got)
	})

	t.Run("signal-with-start", func(t *testing.T) {
		opts := startOpts(tq)
		run, err := c.SignalWithStartWorkflow(user("eyJ-user"), opts.ID, "approve", nil, opts, SignalKeeper)
		require.NoError(t, err)
		var got []string
		require.NoError(t, run.Get(context.Background(), &got))
		require.Equal(t, []string{"start-without-credentials", "eyJ-user"}, got)
	})

	t.Run("update-with-start", func(t *testing.T) {
		opts := startOpts(tq)
		opts.WorkflowIDConflictPolicy = enumspb.WORKFLOW_ID_CONFLICT_POLICY_FAIL
		h, err := c.UpdateWithStartWorkflow(user("eyJ-user"), client.UpdateWithStartWorkflowOptions{
			StartWorkflowOperation: c.NewWithStartWorkflowOperation(opts, UpdateWithStart),
			UpdateOptions:          client.UpdateWorkflowOptions{UpdateName: "token", WaitForStage: client.WorkflowUpdateStageCompleted},
		})
		require.NoError(t, err)
		var token, result string
		require.NoError(t, h.Get(context.Background(), &token))
		require.Equal(t, "eyJ-user", token)
		require.NoError(t, c.GetWorkflow(context.Background(), opts.ID, "").Get(context.Background(), &result))
		require.Equal(t, "start-ok", result)
	})

	t.Run("Updates and refresh", func(t *testing.T) {
		run, err := c.ExecuteWorkflow(user(jwtFor("alice", "1")), startOpts(tq), Approval)
		require.NoError(t, err)
		update := func(ctx context.Context, name string) error {
			h, err := c.UpdateWorkflow(ctx, client.UpdateWorkflowOptions{WorkflowID: run.GetID(), UpdateName: name, WaitForStage: client.WorkflowUpdateStageCompleted})
			if err != nil {
				return err
			}
			return h.Get(ctx, nil)
		}
		approver := credentials.Attach(context.Background(), credentials.Values{"approver_token": "eyJ-approver"})
		require.True(t, isMissing(update(context.Background(), "approve")))
		require.NoError(t, update(approver, "approve"))
		require.True(t, isMissing(update(user(jwtFor("mallory", "1")), "refresh")))
		fresh := jwtFor("alice", "2")
		require.NoError(t, update(user(fresh), "refresh"))
		require.NoError(t, c.SignalWorkflow(context.Background(), run.GetID(), "", "done", nil))
		var got map[string]string
		require.NoError(t, run.Get(context.Background(), &got))
		require.Equal(t, map[string]string{"user_token": fresh, "approver_token": "eyJ-approver"}, got)
	})

	t.Run("standalone Activity and Nexus operation", func(t *testing.T) {
		h, err := c.ExecuteActivity(user("eyJ-user"), client.StartActivityOptions{ID: newID("act"), TaskQueue: tq, StartToCloseTimeout: time.Minute}, TokenOf, "user_token")
		require.NoError(t, err)
		var got string
		require.NoError(t, h.Get(context.Background(), &got))
		require.Equal(t, "eyJ-user", got)

		nc, err := c.NewNexusClient(client.NexusClientOptions{Endpoint: ep, Service: "tools"})
		require.NoError(t, err)
		op, err := nc.ExecuteOperation(user("eyJ-user"), tokenOp, "user_token", client.StartNexusOperationOptions{ID: newID("op"), ScheduleToCloseTimeout: time.Minute})
		require.NoError(t, err)
		require.NoError(t, op.Get(context.Background(), &got))
		require.Equal(t, "eyJ-user", got)
	})
}

// TestMixedDeployments pairs applications that run the binding layer
// themselves with ones behind the proxy. Both seal and open the same way.
func TestMixedDeployments(t *testing.T) {
	k := newKeys(t)
	proxy := startProxy(t, k, false)

	t.Run("SDK-sealed start, proxy-fronted Worker", func(t *testing.T) {
		tq := newID("tq")
		startWorker(t, proxyClient(t, proxy), tq)
		run, err := directClient(t, k.keyset(t, false)).ExecuteWorkflow(user("eyJ-user"), startOpts(tq), Agent, []string{})
		require.NoError(t, err)
		var got map[string]string
		require.NoError(t, run.Get(context.Background(), &got))
		require.Equal(t, "eyJ-user", got["activity"])
	})

	t.Run("proxy-sealed start, in-process Worker", func(t *testing.T) {
		tq := newID("tq")
		startWorker(t, directClient(t, k.keyset(t, true)), tq)
		run, err := proxyClient(t, proxy).ExecuteWorkflow(user("eyJ-user"), startOpts(tq), Agent, []string{})
		require.NoError(t, err)
		var got map[string]string
		require.NoError(t, run.Get(context.Background(), &got))
		require.Equal(t, "eyJ-user", got["activity"])
	})

	t.Run("Workflow behind the proxy, in-process Nexus Worker", func(t *testing.T) {
		nexusTQ := newID("tq")
		startWorker(t, directClient(t, k.keyset(t, true)), nexusTQ)
		ep := createEndpoint(t, nexusTQ)
		tq := newID("tq")
		c := proxyClient(t, proxy)
		startWorker(t, c, tq)
		run, err := c.ExecuteWorkflow(user("eyJ-user"), startOpts(tq), Agent, []string{ep})
		require.NoError(t, err)
		var got map[string]string
		require.NoError(t, run.Get(context.Background(), &got))
		require.Equal(t, map[string]string{"activity": "eyJ-user", "nexus": "eyJ-user"}, got)
	})
}

// TestEncryptingProxy has the proxy encrypt payloads too. It seals after
// encrypting and opens before decrypting, so both sides digest the encrypted
// bytes the Temporal Service stores, through its Nexus round trip too.
func TestEncryptingProxy(t *testing.T) {
	k := newKeys(t)
	proxy := startProxy(t, k, true)
	c := proxyClient(t, proxy)
	tq := newID("tq")
	startWorker(t, c, tq)
	ep := createEndpoint(t, tq)

	run, err := c.ExecuteWorkflow(user("eyJ-user"), startOpts(tq), Agent, []string{ep})
	require.NoError(t, err)
	var got map[string]string
	require.NoError(t, run.Get(context.Background(), &got))
	require.Equal(t, map[string]string{"activity": "eyJ-user", "nexus": "eyJ-user"}, got)

	e, err := dial(t, devServer).GetWorkflowHistory(context.Background(), run.GetID(), run.GetRunID(), false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT).Next()
	require.NoError(t, err)
	a := e.GetWorkflowExecutionStartedEventAttributes()
	require.Equal(t, "binary/encrypted", string(a.GetInput().GetPayloads()[0].GetMetadata()["encoding"]))
	require.Equal(t, binding.EncodingSealed, string(a.GetHeader().GetFields()[binding.HeaderCredentials].GetMetadata()["encoding"]))
}

// pythonVenv is the sdk-python build with the sdk-core resource_id fix.
func pythonVenv() string {
	if v := os.Getenv("CREDENTIALS_PYTHON_VENV"); v != "" {
		return v
	}
	return "/Users/bergundy/temporal/.worktrees/credential-propagation/sdk-python/.venv"
}

// runPython runs python/app.py with args and returns the JSON it prints.
func runPython(t *testing.T, args ...string) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(pythonVenv(), "bin", "python"), append([]string{"-I", "python/app.py"}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	require.NoError(t, err, "python/app.py %v failed:\n%s", args, stderr.String())
	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got), "python/app.py %v printed %q", args, out)
	return got
}

// startPythonWorker runs a Python Worker in proxy mode on taskQueue.
func startPythonWorker(t *testing.T, proxy, taskQueue string) {
	t.Helper()
	cmd := exec.Command(filepath.Join(pythonVenv(), "bin", "python"), "-I", "python/app.py", "worker", proxy, namespace, taskQueue)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Start(), "the Python check needs the sdk-python build with the resource_id fix; set CREDENTIALS_PYTHON_VENV")
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("Python Worker stderr:\n%s", stderr.String())
		}
	})
	started := make(chan struct{})
	go func() {
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if s.Text() == "worker started" {
				close(started)
			}
		}
	}()
	select {
	case <-started:
	case <-time.After(30 * time.Second):
		t.Fatalf("the Python Worker didn't start:\n%s", stderr.String())
	}
}

// historyEvents lists the event types of a Workflow's history, read straight
// from the Temporal Service.
func historyEvents(t *testing.T, wfID, runID string) []*historypb.HistoryEvent {
	t.Helper()
	iter := dial(t, devServer).GetWorkflowHistory(context.Background(), wfID, runID, false, enumspb.HISTORY_EVENT_FILTER_TYPE_ALL_EVENT)
	var events []*historypb.HistoryEvent
	for iter.HasNext() {
		e, err := iter.Next()
		require.NoError(t, err)
		events = append(events, e)
	}
	return events
}

// TestPython runs Python applications built on temporalio.contrib.credentials
// behind the proxy, next to Go applications in proxy mode. The proxy seals what
// a Python Workflow forwards from the Workflow task completion, using the
// completion's resource_id, which Core sends only with the local fix.
func TestPython(t *testing.T) {
	k := newKeys(t)
	proxy := startProxy(t, k, false)
	c := proxyClient(t, proxy)
	goTQ, pyTQ := newID("tq"), newID("tq")
	startWorker(t, c, goTQ)
	startPythonWorker(t, proxy, pyTQ)
	goEP, pyEP := createEndpoint(t, goTQ), createEndpoint(t, pyTQ)

	get := func(t *testing.T, run client.WorkflowRun, out any) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := run.Get(ctx, out); err != nil {
			var types []string
			for _, e := range historyEvents(t, run.GetID(), run.GetRunID()) {
				types = append(types, e.GetEventType().String())
			}
			t.Fatalf("the Workflow didn't complete: %v; history: %v", err, types)
		}
	}

	t.Run("Python Workflow forwards to Activities, a child, and a Go Nexus handler", func(t *testing.T) {
		run, err := c.ExecuteWorkflow(user("eyJ-user"), startOpts(pyTQ), "PyAgent", goEP)
		require.NoError(t, err)
		var got map[string]string
		get(t, run, &got)
		require.Equal(t, map[string]string{
			"activity": "eyJ-user", "local": "eyJ-user", "child": "eyJ-user", "nexus": "eyJ-user", "outside": missing,
		}, got)

		for _, e := range historyEvents(t, run.GetID(), run.GetRunID()) {
			if a := e.GetActivityTaskScheduledEventAttributes(); a != nil && a.GetHeader().GetFields()[binding.HeaderCredentials] != nil {
				require.Equal(t, binding.EncodingSealed, string(a.GetHeader().GetFields()[binding.HeaderCredentials].GetMetadata()["encoding"]),
					"the Temporal Service holds only ciphertext")
			}
		}
	})

	t.Run("continue-as-new", func(t *testing.T) {
		run, err := c.ExecuteWorkflow(user("eyJ-user"), startOpts(pyTQ), "PyChain", 0)
		require.NoError(t, err)
		var got string
		get(t, run, &got)
		require.Equal(t, "eyJ-user", got)
	})

	t.Run("Go Workflow, Python Nexus handler", func(t *testing.T) {
		run, err := c.ExecuteWorkflow(user("eyJ-user"), startOpts(goTQ), Agent, []string{pyEP})
		require.NoError(t, err)
		var got map[string]string
		get(t, run, &got)
		require.Equal(t, map[string]string{"activity": "eyJ-user", "nexus": "eyJ-user"}, got)
	})

	t.Run("Updates, Signals, and refresh", func(t *testing.T) {
		run, err := c.ExecuteWorkflow(user(jwtFor("alice", "1")), startOpts(pyTQ), "PyApproval")
		require.NoError(t, err)
		update := func(ctx context.Context, name string) error {
			h, err := c.UpdateWorkflow(ctx, client.UpdateWorkflowOptions{WorkflowID: run.GetID(), UpdateName: name, WaitForStage: client.WorkflowUpdateStageCompleted})
			if err != nil {
				return err
			}
			return h.Get(ctx, nil)
		}
		approver := credentials.Attach(context.Background(), credentials.Values{"approver_token": "eyJ-approver"})
		require.True(t, isMissing(update(context.Background(), "approve")))
		require.NoError(t, update(approver, "approve"))
		require.True(t, isMissing(update(approver, "approve")), "if_absent keeps the first one")
		require.True(t, isMissing(update(user(jwtFor("mallory", "1")), "refresh")))
		fresh := jwtFor("alice", "2")
		require.NoError(t, update(user(fresh), "refresh"))

		// The first Signal doesn't carry the credential its handler requires,
		// so it's dropped.
		require.NoError(t, c.SignalWorkflow(context.Background(), run.GetID(), "", "keep", nil))
		signaler := credentials.Attach(context.Background(), credentials.Values{"signal_token": "eyJ-signal"})
		require.NoError(t, c.SignalWorkflow(signaler, run.GetID(), "", "keep", nil))
		require.NoError(t, c.SignalWorkflow(context.Background(), run.GetID(), "", "done", nil))
		var got map[string]string
		get(t, run, &got)
		require.Equal(t, map[string]string{"user_token": fresh, "approver_token": "eyJ-approver", "signal_token": "eyJ-signal"}, got)
	})

	t.Run("Python client", func(t *testing.T) {
		got := runPython(t, "client", proxy, namespace, goTQ)
		require.Equal(t, map[string]any{"agent": map[string]any{"activity": "eyJ-python-client"}}, got)
	})

	t.Run("Python refuses a server that isn't a credential-binding proxy", func(t *testing.T) {
		got := runPython(t, "guard", devServer, namespace, newID("tq"))
		require.Equal(t, map[string]any{"client": "FAILED_PRECONDITION", "worker": "refused"}, got)
	})
}
