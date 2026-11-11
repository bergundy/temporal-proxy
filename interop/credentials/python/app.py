"""A Core-based Python application behind Temporal Proxy, using temporalio.contrib.credentials.

The proxy runs the binding layer. The proxy seals what a Workflow forwards from
the Workflow task completion, which needs the completion's resource_id: sdk-core
sends it only with the local fix.

Usage:
    app.py worker <host:port> <namespace> <task queue>
    app.py client <host:port> <namespace> <task queue of the Go Worker>
"""

import asyncio
import json
import logging
import sys
import uuid
from datetime import timedelta

import nexusrpc
from nexusrpc.handler import StartOperationContext, service_handler, sync_operation

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.contrib import credentials
from temporalio.worker import Worker

MINUTE = timedelta(minutes=1)


@nexusrpc.service(name="tools")
class Tools:
    token: nexusrpc.Operation[str, str]


@service_handler(service=Tools)
class ToolsHandler:
    @sync_operation
    @credentials.requires("user_token")
    async def token(self, _ctx: StartOperationContext, name: str) -> str:
        return credentials.get(name).reveal()


@activity.defn(name="PyTokenOf")
async def token_of(name: str) -> str:
    cred = credentials.lookup(name)
    return cred.reveal() if cred else "missing"


@workflow.defn(name="PyChild")
class PyChild:
    @workflow.run
    async def run(self) -> str:
        cred = credentials.lookup("user_token")
        return cred.reveal() if cred else "missing"


@workflow.defn(name="PyAgent")
class PyAgent:
    @workflow.run
    @credentials.requires("user_token")
    async def run(self, endpoint: str) -> dict[str, str]:
        out: dict[str, str] = {}
        tools = workflow.create_nexus_client(service=Tools, endpoint=endpoint)
        with credentials.propagate("user_token"):
            out["activity"] = await workflow.execute_activity(
                token_of, "user_token", start_to_close_timeout=MINUTE
            )
            out["local"] = await workflow.execute_local_activity(
                token_of, "user_token", start_to_close_timeout=MINUTE
            )
            out["child"] = await workflow.execute_child_workflow(
                PyChild.run, id=f"{workflow.info().workflow_id}-child"
            )
            out["nexus"] = await tools.execute_operation(Tools.token, "user_token")
        out["outside"] = await workflow.execute_activity(
            token_of, "user_token", start_to_close_timeout=MINUTE
        )
        return out


@workflow.defn(name="PyChain")
class PyChain:
    @workflow.run
    @credentials.requires("user_token")
    async def run(self, iteration: int) -> str:
        if iteration == 0:
            with credentials.propagate_all():
                workflow.continue_as_new(1)
        with credentials.propagate("user_token"):
            return await workflow.execute_child_workflow(
                PyChild.run, id=f"{workflow.info().workflow_id}-child"
            )


@workflow.defn(name="PyApproval")
class PyApproval:
    def __init__(self) -> None:
        self.done = False

    @workflow.run
    @credentials.requires("user_token")
    async def run(self) -> dict[str, str]:
        await workflow.wait_condition(lambda: self.done)
        out: dict[str, str] = {}
        for name in ("user_token", "approver_token", "signal_token"):
            with credentials.propagate(name):
                out[name] = await workflow.execute_activity(
                    token_of, name, start_to_close_timeout=MINUTE
                )
        return out

    @workflow.update(name="approve")
    @credentials.requires("approver_token", retain=credentials.if_absent)
    async def approve(self) -> None:
        pass

    @workflow.update(name="refresh")
    @credentials.requires("user_token", retain=credentials.jwt.same_subject)
    async def refresh(self) -> None:
        pass

    @workflow.signal(name="keep")
    @credentials.requires("signal_token", retain=credentials.if_absent)
    def keep(self) -> None:
        pass

    @workflow.signal(name="done")
    def finish(self) -> None:
        self.done = True


async def connect(target: str, namespace: str) -> Client:
    return await Client.connect(
        target, namespace=namespace, plugins=[credentials.Plugin(proxy=True)]
    )


async def run_worker(target: str, namespace: str, task_queue: str) -> None:
    worker = Worker(
        await connect(target, namespace),
        task_queue=task_queue,
        workflows=[PyAgent, PyChain, PyChild, PyApproval],
        activities=[token_of],
        nexus_service_handlers=[ToolsHandler()],
    )
    print("worker started", flush=True)
    await worker.run()


async def run_client(target: str, namespace: str, task_queue: str) -> None:
    client = await connect(target, namespace)
    with credentials.attach(user_token="eyJ-python-client"):
        agent = await client.execute_workflow(
            "Agent", [], id=f"py-client-{uuid.uuid4()}", task_queue=task_queue, result_type=dict
        )
    print(json.dumps({"agent": agent}), flush=True)


async def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    mode, target, namespace, task_queue = sys.argv[1:5]
    run = {"worker": run_worker, "client": run_client}[mode]
    await run(target, namespace, task_queue)


if __name__ == "__main__":
    asyncio.run(main())
