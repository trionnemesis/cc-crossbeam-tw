import json
import subprocess
import sys
import unittest


def send_json_rpc(process, payload):
    process.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
    process.stdin.flush()
    return json.loads(process.stdout.readline())


class StdioServerTests(unittest.TestCase):
    def test_server_lists_and_calls_v1_tools(self):
        process = subprocess.Popen(
            [sys.executable, "scripts/tw_law_mcp_stdio.py"],
            cwd=".",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        try:
            initialize = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "unittest", "version": "0.1.0"},
                    },
                },
            )
            tools = send_json_rpc(
                process,
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            )
            call = send_json_rpc(
                process,
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "verify_citation",
                        "arguments": {
                            "law_name": "建築物室內裝修管理辦法",
                            "article_no": "33",
                        },
                    },
                },
            )

            self.assertEqual(initialize["result"]["serverInfo"]["name"], "tw-law-mcp")
            tool_names = {tool["name"] for tool in tools["result"]["tools"]}
            self.assertIn("verify_citation", tool_names)
            self.assertIn("get_source_policy", tool_names)
            content = json.loads(call["result"]["content"][0]["text"])
            self.assertTrue(content["exists"])
            self.assertEqual(content["canonical_name"], "建築物室內裝修管理辦法")
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main()
