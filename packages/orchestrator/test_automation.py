import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))

import harness
import main


class GraphChangeTests(unittest.TestCase):
    def test_graph_change_includes_added_changed_and_impacted_endpoints(self):
        response = {
            "graphVersion": 12,
            "sourceHash": "source-12",
            "lastChangedFiles": ["src/routes/users.js"],
            "lastDiff": {
                "addedNodes": ["endpoint:new"],
                "changedNodes": ["endpoint:changed", "function:handler"],
            },
            "lastImpact": {"affectedEndpoints": ["endpoint:impacted"]},
            "graph": {
                "nodes": [
                    {
                        "id": "endpoint:new",
                        "kind": "endpoint",
                        "meta": {"method": "POST", "path": "/users"},
                        "loc": {"file": "src/routes/new.js"},
                    },
                    {
                        "id": "endpoint:changed",
                        "kind": "endpoint",
                        "meta": {"method": "GET", "path": "/changed"},
                        "loc": {"file": "src/routes/changed.js"},
                    },
                    {
                        "id": "endpoint:impacted",
                        "kind": "endpoint",
                        "meta": {"method": "GET", "path": "/impacted"},
                        "loc": {"file": "src/routes/other.js"},
                    },
                    {
                        "id": "endpoint:file",
                        "kind": "endpoint",
                        "meta": {"method": "GET", "path": "/users"},
                        "loc": {"file": "src/routes/users.js"},
                    },
                    {
                        "id": "function:handler",
                        "kind": "function",
                        "meta": {},
                    },
                ],
            },
        }
        with patch.object(harness.requests, "get") as get:
            get.return_value.json.return_value = response
            change = harness.graph_change("project")

        self.assertEqual(change["sourceHash"], "source-12")
        self.assertEqual(
            {(e["method"], e["path"]) for e in change["endpoints"]},
            {
                ("POST", "/users"),
                ("GET", "/changed"),
                ("GET", "/impacted"),
                ("GET", "/users"),
            },
        )

    def test_endpoint_free_graph_change_still_runs_dependency_scan(self):
        change = {
            "graphVersion": 4,
            "sourceHash": "source-4",
            "changedFiles": ["package-lock.json"],
            "endpoints": [],
        }
        with (
            patch.object(main, "investigate_endpoint") as investigate,
            patch.object(main, "scan_dependencies") as scan,
        ):
            main.scan_graph_change("project", change)

        investigate.assert_not_called()
        scan.assert_called_once_with("project", change)

    def test_unreachable_endpoint_is_not_saved_as_a_finding(self):
        with (
            patch.object(main.llm, "choose_tools", return_value=(["auth_probe"], "test")),
            patch.dict(main.tools.TOOLS, {"auth_probe": lambda endpoint: {
                "tool": "auth_probe",
                "endpoint": endpoint["path"],
                "error": "connection refused",
            }}),
            patch.object(main.memory, "upsert_one") as save,
            patch.object(main.harness, "log_event") as log_event,
        ):
            main.investigate_endpoint(
                "project", {"method": "GET", "path": "/health"}
            )

        save.assert_not_called()
        self.assertTrue(
            any(
                call.kwargs.get("data", {}).get("status") == "failed"
                for call in log_event.call_args_list
            )
        )


class ChangeQueueTests(unittest.IsolatedAsyncioTestCase):
    async def test_pending_graph_changes_coalesce_endpoints_to_latest_revision(self):
        queue = asyncio.Queue()
        queue.put_nowait({
            "graphVersion": 1,
            "sourceHash": "source-1",
            "changedFiles": ["a.js"],
            "endpoints": [{"id": "endpoint:a", "method": "GET", "path": "/a"}],
            "_currentEndpoints": {
                "endpoint:a": {"id": "endpoint:a", "method": "GET", "path": "/a"},
            },
        })
        queue.put_nowait({
            "graphVersion": 2,
            "sourceHash": "source-2",
            "changedFiles": ["b.js"],
            "endpoints": [{"id": "endpoint:b", "method": "POST", "path": "/b"}],
            "_currentEndpoints": {
                "endpoint:a": {"id": "endpoint:a", "method": "GET", "path": "/a"},
                "endpoint:b": {"id": "endpoint:b", "method": "POST", "path": "/b"},
            },
        })
        queue.put_nowait({
            "graphVersion": 3,
            "sourceHash": "source-3",
            "changedFiles": ["c.js"],
            "endpoints": [],
            "_currentEndpoints": {
                "endpoint:b": {"id": "endpoint:b", "method": "POST", "path": "/b"},
            },
        })
        completed = asyncio.Event()
        processed = []

        def record_change(project_id, change):
            processed.append(change)
            completed.set()

        async def run_inline(function, *args):
            function(*args)

        with (
            patch.object(main, "scan_graph_change", side_effect=record_change),
            patch.object(main.asyncio, "to_thread", side_effect=run_inline),
        ):
            worker = asyncio.create_task(main.process_changes("project", queue))
            await asyncio.wait_for(completed.wait(), timeout=2)
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)

        self.assertEqual(len(processed), 1)
        self.assertEqual(processed[0]["graphVersion"], 3)
        self.assertEqual(
            {(e["method"], e["path"]) for e in processed[0]["endpoints"]},
            {("POST", "/b")},
        )
        self.assertEqual(processed[0]["changedFiles"], ["a.js", "b.js", "c.js"])


if __name__ == "__main__":
    unittest.main()
