(** CertiClaw test suite.

    Simple test harness — no external dependencies required.
    Each test is a (name, thunk) pair that must not raise. *)

open Certiclaw.Types
open Certiclaw.Check
open Certiclaw.Infer
open Certiclaw.Exec

(* ------------------------------------------------------------------ *)
(* Minimal test framework                                              *)
(* ------------------------------------------------------------------ *)

let passed = ref 0
let failed = ref 0

let run_test name f =
  try
    f ();
    incr passed;
    Printf.printf "  PASS  %s\n" name
  with exn ->
    incr failed;
    Printf.printf "  FAIL  %s — %s\n" name (Printexc.to_string exn)

let assert_accepted result =
  match result with
  | Accepted -> ()
  | Rejected r -> failwith ("Expected Accepted, got Rejected: " ^ r)

let assert_rejected result =
  match result with
  | Rejected _ -> ()
  | Accepted -> failwith "Expected Rejected, got Accepted"

let assert_exec_ok result =
  match result with
  | ExecOk _ -> ()
  | ExecBlocked r -> failwith ("Expected ExecOk, got ExecBlocked: " ^ r)
  | ExecError r -> failwith ("Expected ExecOk, got ExecError: " ^ r)

let assert_exec_blocked result =
  match result with
  | ExecBlocked _ -> ()
  | ExecOk r -> failwith ("Expected ExecBlocked, got ExecOk: " ^ r)
  | ExecError r -> failwith ("Expected ExecBlocked, got ExecError: " ^ r)

(* ------------------------------------------------------------------ *)
(* Shared test policy                                                  *)
(* ------------------------------------------------------------------ *)

let test_policy : policy = {
  readable_paths = ["/home/user/src"];
  writable_paths = ["/home/user/src"; "/tmp"];
  allowed_bins   = ["grep"; "curl"; "find"];
  allowed_hosts  = ["example.com"];
  allowed_mcp    = [("files", "read_file"); ("search", "query")];
}

(* ------------------------------------------------------------------ *)
(* Test: accepted grep                                                 *)
(* ------------------------------------------------------------------ *)

let test_grep_accepted () =
  let action = GrepRecursive {
    pattern = "TODO";
    root    = "/home/user/src";
    output  = "/tmp/results.txt";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = Some "Search for TODOs";
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_accepted result

(* ------------------------------------------------------------------ *)
(* Test: rejected grep — output outside writable paths                 *)
(* ------------------------------------------------------------------ *)

let test_grep_rejected_bad_output () =
  let action = GrepRecursive {
    pattern = "TODO";
    root    = "/home/user/src";
    output  = "/etc/shadow";  (* not writable *)
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_rejected result

(* ------------------------------------------------------------------ *)
(* Test: accepted destructive remove with approval                     *)
(* ------------------------------------------------------------------ *)

let test_remove_accepted_with_approval () =
  let action = RemoveByGlob {
    root      = "/tmp";
    suffix    = ".tmp";
    recursive = true;
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = true;
    approval        = Some (ApprovedDestructive "cleanup ticket #42");
    explanation     = Some "Remove temp files";
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_accepted result

(* ------------------------------------------------------------------ *)
(* Test: rejected destructive remove without approval                  *)
(* ------------------------------------------------------------------ *)

let test_remove_rejected_no_approval () =
  let action = RemoveByGlob {
    root      = "/tmp";
    suffix    = ".tmp";
    recursive = false;
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = true;
    approval        = None;
    explanation     = None;
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_rejected result

(* ------------------------------------------------------------------ *)
(* Test: accepted curl with allowed host                               *)
(* ------------------------------------------------------------------ *)

let test_curl_accepted () =
  let action = CurlToFile {
    url    = "https://example.com/data.json";
    host   = "example.com";
    output = "/tmp/data.json";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_accepted result

(* ------------------------------------------------------------------ *)
(* Test: rejected curl with disallowed host                            *)
(* ------------------------------------------------------------------ *)

let test_curl_rejected_bad_host () =
  let action = CurlToFile {
    url    = "https://evil.com/payload";
    host   = "evil.com";
    output = "/tmp/payload";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_rejected result

(* ------------------------------------------------------------------ *)
(* Test: accepted MCP call with allowed tool                           *)
(* ------------------------------------------------------------------ *)

let test_mcp_accepted () =
  let action = McpCall {
    server = "files";
    tool   = "read_file";
    args   = {|{"path": "/home/user/src/main.ml"}|};
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_accepted result

(* ------------------------------------------------------------------ *)
(* Test: rejected MCP call with disallowed tool                        *)
(* ------------------------------------------------------------------ *)

let test_mcp_rejected () =
  let action = McpCall {
    server = "files";
    tool   = "delete_file";  (* not in allowed_mcp *)
    args   = {|{"path": "/tmp/x"}|};
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_rejected result

(* ------------------------------------------------------------------ *)
(* Test: effect mismatch between proof and IR                          *)
(* ------------------------------------------------------------------ *)

let test_effect_mismatch () =
  let action = GrepRecursive {
    pattern = "TODO";
    root    = "/home/user/src";
    output  = "/tmp/results.txt";
  } in
  (* Deliberately wrong claimed effects *)
  let proof = {
    claimed_effects = [ReadPath "/home/user/src"];  (* incomplete *)
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = check ~policy:test_policy ~proof ~action in
  assert_rejected result

(* ------------------------------------------------------------------ *)
(* Test: executor dry-run accepted                                     *)
(* ------------------------------------------------------------------ *)

let test_executor_dry_run_ok () =
  let action = GrepRecursive {
    pattern = "TODO";
    root    = "/home/user/src";
    output  = "/tmp/results.txt";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = execute ~dry_run:true ~policy:test_policy ~proof action in
  assert_exec_ok result

(* ------------------------------------------------------------------ *)
(* Test: executor blocks rejected action                               *)
(* ------------------------------------------------------------------ *)

let test_executor_blocked () =
  let action = CurlToFile {
    url    = "https://evil.com/x";
    host   = "evil.com";
    output = "/tmp/x";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = execute ~dry_run:true ~policy:test_policy ~proof action in
  assert_exec_blocked result

(* ------------------------------------------------------------------ *)
(* Test: MCP through executor                                          *)
(* ------------------------------------------------------------------ *)

let test_executor_mcp () =
  let action = McpCall {
    server = "search";
    tool   = "query";
    args   = {|{"q": "hello"}|};
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects;
    destructive     = false;
    approval        = None;
    explanation     = None;
  } in
  let result = execute ~dry_run:true ~policy:test_policy ~proof action in
  assert_exec_ok result

(* ------------------------------------------------------------------ *)
(* Runner                                                              *)
(* ------------------------------------------------------------------ *)

let () =
  Printf.printf "\n=== CertiClaw Test Suite ===\n\n";

  run_test "grep accepted"                     test_grep_accepted;
  run_test "grep rejected (bad output path)"   test_grep_rejected_bad_output;
  run_test "remove accepted (with approval)"   test_remove_accepted_with_approval;
  run_test "remove rejected (no approval)"     test_remove_rejected_no_approval;
  run_test "curl accepted (allowed host)"      test_curl_accepted;
  run_test "curl rejected (disallowed host)"   test_curl_rejected_bad_host;
  run_test "mcp accepted (allowed tool)"       test_mcp_accepted;
  run_test "mcp rejected (disallowed tool)"    test_mcp_rejected;
  run_test "effect mismatch fails"             test_effect_mismatch;
  run_test "executor dry-run ok"               test_executor_dry_run_ok;
  run_test "executor blocks rejected action"   test_executor_blocked;
  run_test "executor MCP dry-run"              test_executor_mcp;

  Printf.printf "\n  Results: %d passed, %d failed\n\n" !passed !failed;
  if !failed > 0 then exit 1
