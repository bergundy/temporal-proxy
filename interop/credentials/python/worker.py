"""A minimal Core-based Worker behind Temporal Proxy, using the credentials link format.

The proxy runs the binding layer. This Worker reads the credentials the proxy
opened on its Workflow start, forwards the user's token to an Activity as a
pending value, and the Activity returns the token it received. The proxy seals
the Activity's header from the Workflow task completion, which needs the
completion's resource_id: sdk-core sends it only with the local fix.

Usage: worker.py <proxy host:port> <namespace> <task queue>
"""

import asyncio
import logging
import contextvars
import json
import sys
from datetime import timedelta
from typing import Any, Mapping, Optional, Type

from temporalio import activity, workflow
from temporalio.api.common.v1 import Payload
from temporalio.client import Client
from temporalio.worker import (
    ActivityInboundInterceptor,
    ExecuteActivityInput,
    ExecuteWorkflowInput,
    Interceptor,
    StartActivityInput,
    Worker,
    WorkflowInboundInterceptor,
    WorkflowInterceptorClassInput,
    WorkflowOutboundInterceptor,
)

CREDENTIALS = "credentials"
OPENED = "credentials-opened"
PENDING = b"json/credentials-pending"

_activity_credentials: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "activity_credentials", default={}
)


def opened(headers: Mapping[str, Payload]) -> dict:
    payload = headers.get(CREDENTIALS)
    if payload is None or OPENED not in payload.metadata:
        return {}
    result = json.loads(payload.metadata[OPENED])
    return result.get("credentials") or {} if result.get("ok") else {}


class _WorkflowOutbound(WorkflowOutboundInterceptor):
    def __init__(self, next: WorkflowOutboundInterceptor, inbound: "_WorkflowInbound"):
        super().__init__(next)
        self._inbound = inbound

    def start_activity(self, input: StartActivityInput) -> workflow.ActivityHandle:
        headers = {k: v for k, v in input.headers.items() if not k.startswith(CREDENTIALS)}
        token = self._inbound.held.get("user_token")
        if token is not None:
            headers[CREDENTIALS] = Payload(
                metadata={"encoding": PENDING},
                data=json.dumps({"user_token": token}).encode(),
            )
        input.headers = headers
        return super().start_activity(input)


class _WorkflowInbound(WorkflowInboundInterceptor):
    held: dict = {}

    def init(self, outbound: WorkflowOutboundInterceptor) -> None:
        super().init(_WorkflowOutbound(outbound, self))

    async def execute_workflow(self, input: ExecuteWorkflowInput) -> Any:
        self.held = dict(opened(input.headers))
        return await super().execute_workflow(input)


class _ActivityInbound(ActivityInboundInterceptor):
    async def execute_activity(self, input: ExecuteActivityInput) -> Any:
        _activity_credentials.set(opened(input.headers))
        return await super().execute_activity(input)


class CredentialsInterceptor(Interceptor):
    def intercept_activity(self, next: ActivityInboundInterceptor) -> ActivityInboundInterceptor:
        return _ActivityInbound(next)

    def workflow_interceptor_class(
        self, input: WorkflowInterceptorClassInput
    ) -> Optional[Type[WorkflowInboundInterceptor]]:
        return _WorkflowInbound


@activity.defn(name="TokenOf")
async def token_of(name: str) -> str:
    return _activity_credentials.get().get(name, "missing")


@workflow.defn(name="PyAgent")
class PyAgent:
    @workflow.run
    async def run(self) -> str:
        return await workflow.execute_activity(
            token_of, "user_token", start_to_close_timeout=timedelta(minutes=1)
        )


async def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    target, namespace, task_queue = sys.argv[1:4]
    client = await Client.connect(target, namespace=namespace)
    worker = Worker(
        client,
        task_queue=task_queue,
        workflows=[PyAgent],
        activities=[token_of],
        interceptors=[CredentialsInterceptor()],
    )
    print("worker started", flush=True)
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
