#!/usr/bin/env python
"""
CertiClaw LLM Agent — Full Workflow

Connects a real LLM (OpenAI GPT / compatible) to CertiClaw's
formally verified checker. The LLM produces structured tool calls;
the OCaml checker validates each one before execution.

Usage:
  python agent/agent.py [--policy examples/policy.json] [--model gpt-4o-mini]

Requires: OPENAI_API_KEY environment variable.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────

MODEL = os.environ.get("CERTICLAW_MODEL", "gpt-4o-mini")
MAX_TURNS = 20
POLICY_FILE = "examples/policy.json"
CHECKER_CMD = ["dune", "exec", "agent/checker_server.exe", "--"]
TOOL_SCHEMAS_FILE = Path(__file__).parent / "tool_schemas.json"

# ── Parse args ─────────────────────────────────────────────────

args = sys.argv[1:]
i = 0
while i < len(args):
    if args[i] == "--policy" and i + 1 < len(args):
        POLICY_FILE = args[i + 1]; i += 2
    elif args[i] == "--model" and i + 1 < len(args):
        MODEL = args[i + 1]; i += 2
    else:
        i += 1

# ── Load tool schemas ──────────────────────────────────────────

with open(TOOL_SCHEMAS_FILE) as f:
    TOOLS = json.load(f)

# ── Start checker subprocess ───────────────────────────────────

print(f"[Agent] Starting CertiClaw checker (policy: {POLICY_FILE})...")
checker = subprocess.Popen(
    CHECKER_CMD + [POLICY_FILE],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)

# Read the ready message from stderr
ready_msg = checker.stderr.readline().strip()
print(f"[Agent] {ready_msg}")

def check_action(tool_name: str, arguments: dict) -> dict:
    """Send an action to the OCaml checker and get the result."""
    request = json.dumps({"tool": tool_name, "arguments": arguments})
    checker.stdin.write(request + "\n")
    checker.stdin.flush()
    response_line = checker.stdout.readline().strip()
    if not response_line:
        return {"status": "error", "error": "Checker returned empty response"}
    return json.loads(response_line)

# ── System prompt ──────────────────────────────────────────────

SYSTEM_PROMPT = f"""You are a helpful coding assistant. You have access to tools for file operations, searching, downloading, and more.

IMPORTANT: Every tool call you make is validated by CertiClaw, a formally verified security checker. If a tool call is rejected, you will receive a typed error explaining WHY. You should then adjust your request and try again.

The active policy allows:
- Reading from paths under: (see policy file)
- Writing to paths under: (see policy file)
- Executing binaries: grep, curl, find
- Accessing hosts: (see policy file)
- MCP tools: (see policy file)

If you try to access a path, host, or tool not in the policy, the checker will reject your request with a specific error. Use that error to guide your next action.

You are operating in a real environment. Tool calls will actually execute."""

# ── OpenAI client ──────────────────────────────────────────────

try:
    from openai import OpenAI
    client = OpenAI()
except ImportError:
    print("[Agent] ERROR: openai package not installed. Run: pip install openai")
    sys.exit(1)

# ── Agent loop ─────────────────────────────────────────────────

def run_agent(user_message: str):
    """Run the full agent loop for a single user message."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_message},
    ]

    print(f"\n{'='*60}")
    print(f"User: {user_message}")
    print(f"{'='*60}\n")

    for turn in range(MAX_TURNS):
        print(f"[Turn {turn + 1}/{MAX_TURNS}] Calling {MODEL}...")

        response = client.chat.completions.create(
            model=MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
        )

        choice = response.choices[0]
        assistant_msg = choice.message

        # Add assistant message to history
        messages.append(assistant_msg.model_dump())

        # If no tool calls, we're done
        if not assistant_msg.tool_calls:
            print(f"\n[Agent Response]\n{assistant_msg.content}\n")
            return assistant_msg.content

        # Process each tool call
        for tool_call in assistant_msg.tool_calls:
            fn = tool_call.function
            tool_name = fn.name
            try:
                tool_args = json.loads(fn.arguments)
            except json.JSONDecodeError:
                tool_args = {}

            print(f"  [Tool Call] {tool_name}({json.dumps(tool_args, indent=None)[:100]})")

            # Send to CertiClaw checker
            result = check_action(tool_name, tool_args)
            status = result.get("status", "error")

            if status == "executed":
                output = result.get("output", "(no output)")
                rendered = result.get("rendered", "")
                print(f"  [Checker] ACCEPTED -> {rendered[:80]}")
                print(f"  [Output]  {output[:200]}")
                tool_result = f"Command executed successfully.\nRendered: {rendered}\nOutput:\n{output}"

            elif status == "rejected":
                error = result.get("error", "unknown")
                error_type = result.get("error_type", "unknown")
                print(f"  [Checker] REJECTED: {error}")
                tool_result = (
                    f"REJECTED by CertiClaw checker.\n"
                    f"Error type: {error_type}\n"
                    f"Error: {error}\n"
                    f"Please adjust your request to comply with the policy."
                )

            elif status == "exec_error":
                error = result.get("error", "unknown")
                rendered = result.get("rendered", "")
                print(f"  [Checker] ACCEPTED but execution failed: {error}")
                tool_result = f"Command was approved but execution failed.\nRendered: {rendered}\nError: {error}"

            else:
                error = result.get("error", "unknown")
                print(f"  [Checker] ERROR: {error}")
                tool_result = f"Error: {error}"

            # Add tool result to messages
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": tool_result,
            })

    print("[Agent] Max turns reached without final response.")
    return None

# ── Interactive loop ───────────────────────────────────────────

def main():
    print()
    print("=" * 60)
    print("  CertiClaw Agent — Formally Verified LLM Tool Execution")
    print(f"  Model: {MODEL}")
    print(f"  Policy: {POLICY_FILE}")
    print(f"  Max turns: {MAX_TURNS}")
    print("=" * 60)
    print()
    print("Type your request (or 'quit' to exit):")
    print()

    while True:
        try:
            user_input = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input:
            continue
        if user_input.lower() in ("quit", "exit", "q"):
            break

        try:
            run_agent(user_input)
        except Exception as e:
            print(f"[Agent] Error: {e}")

    # Cleanup
    checker.stdin.close()
    checker.wait()
    print("\n[Agent] Goodbye!")

if __name__ == "__main__":
    main()
