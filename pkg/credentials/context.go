package credentials

import "go.temporal.io/api/common/v1"

// The contexts a header can be bound to. Each is passed as the HPKE info, so a
// header sealed under one opens only under exactly the same one.

// WorkflowContext binds a Workflow start or continue-as-new header to its
// namespace, Workflow type and ID, and input.
func WorkflowContext(namespace, workflowType, workflowID string, input []*common.Payload) []byte {
	return Frame(
		[]byte("workflow-credential"), []byte("v1"),
		[]byte(namespace), []byte(workflowType), []byte(workflowID),
		Digest(input),
	)
}

// SignalContext binds a Signal header to its namespace, Workflow ID, Signal
// name and input. The design leaves Signal contexts to be specified; this is a
// provisional choice that addresses the Workflow, not a run, like the Signal.
func SignalContext(namespace, workflowID, signalName string, input []*common.Payload) []byte {
	return Frame(
		[]byte("signal-credential"), []byte("v1"),
		[]byte(namespace), []byte(workflowID), []byte(signalName),
		Digest(input),
	)
}

// ActivityContext binds an Activity header to its namespace, Workflow ID
// (empty for a standalone Activity), Activity ID and type, and input.
func ActivityContext(namespace, workflowID, activityID, activityType string, input []*common.Payload) []byte {
	return Frame(
		[]byte("activity-credential"), []byte("v1"),
		[]byte(namespace), []byte(workflowID), []byte(activityID), []byte(activityType),
		Digest(input),
	)
}

// NexusContext binds a Nexus header to its endpoint, service, operation and
// input.
func NexusContext(endpoint, service, operation string, input *common.Payload) []byte {
	return Frame(
		[]byte("nexus-credential"), []byte("v1"),
		[]byte(endpoint), []byte(service), []byte(operation),
		Digest([]*common.Payload{input}),
	)
}
