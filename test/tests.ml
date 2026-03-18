(** CertiClaw test suite.

    Simple test harness — no external dependencies required.
    Each test is a (name, thunk) pair that must not raise. *)

open Certiclaw.Types
open Certiclaw.Check
open Certiclaw.Infer
open Certiclaw.Exec
open Certiclaw.Path_check
open Certiclaw.Policy_load
module Audit = Certiclaw.Audit

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

let assert_true msg b =
  if not b then failwith ("assert_true failed: " ^ msg)

let assert_false msg b =
  if b then failwith ("assert_false failed: " ^ msg)

let assert_equal msg ~expected ~actual =
  if expected <> actual then
    failwith (Printf.sprintf "assert_equal failed: %s (expected %S, got %S)"
                msg expected actual)

let assert_accepted result =
  match result with
  | Accepted -> ()
  | Rejected r -> failwith ("Expected Accepted, got Rejected: " ^
                             show_check_error r)

let assert_rejected result =
  match result with
  | Rejected _ -> ()
  | Accepted -> failwith "Expected Rejected, got Accepted"

(** Assert Rejected with a specific error constructor. *)
let assert_rejected_with expected result =
  match result with
  | Accepted -> failwith "Expected Rejected, got Accepted"
  | Rejected err ->
    if err <> expected then
      failwith (Printf.sprintf "Wrong error: expected %S, got %S"
                  (show_check_error expected) (show_check_error err))

let assert_exec_ok result =
  match result with
  | ExecOk _ -> ()
  | ExecBlocked r -> failwith ("Expected ExecOk, got ExecBlocked: " ^
                                show_check_error r)
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

(* ================================================================== *)
(* SECTION 1: Original MVP tests (preserved)                          *)
(* ================================================================== *)

let test_grep_accepted () =
  let action = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src";
    output = "/tmp/results.txt";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = Some "Search for TODOs";
  } in
  assert_accepted (check ~policy:test_policy ~proof ~action)

let test_grep_rejected_bad_output () =
  let action = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src";
    output = "/etc/shadow";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected (check ~policy:test_policy ~proof ~action)

let test_remove_accepted_with_approval () =
  let action = RemoveByGlob {
    root = "/tmp"; suffix = ".tmp"; recursive = true;
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = true;
    approval = Some (ApprovedDestructive "cleanup ticket #42");
    explanation = Some "Remove temp files";
  } in
  assert_accepted (check ~policy:test_policy ~proof ~action)

let test_remove_rejected_no_approval () =
  let action = RemoveByGlob {
    root = "/tmp"; suffix = ".tmp"; recursive = false;
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = true;
    approval = None; explanation = None;
  } in
  assert_rejected (check ~policy:test_policy ~proof ~action)

let test_curl_accepted () =
  let action = CurlToFile {
    url = "https://example.com/data.json"; host = "example.com";
    output = "/tmp/data.json";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_accepted (check ~policy:test_policy ~proof ~action)

let test_curl_rejected_bad_host () =
  let action = CurlToFile {
    url = "https://evil.com/payload"; host = "evil.com";
    output = "/tmp/payload";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected (check ~policy:test_policy ~proof ~action)

let test_mcp_accepted () =
  let action = McpCall {
    server = "files"; tool = "read_file";
    args = {|{"path": "/home/user/src/main.ml"}|};
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_accepted (check ~policy:test_policy ~proof ~action)

let test_mcp_rejected () =
  let action = McpCall {
    server = "files"; tool = "delete_file";
    args = {|{"path": "/tmp/x"}|};
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected (check ~policy:test_policy ~proof ~action)

let test_effect_mismatch () =
  let action = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src";
    output = "/tmp/results.txt";
  } in
  let proof = {
    claimed_effects = [ReadPath "/home/user/src"];
    destructive = false; approval = None; explanation = None;
  } in
  assert_rejected (check ~policy:test_policy ~proof ~action)

let test_executor_dry_run_ok () =
  let action = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src";
    output = "/tmp/results.txt";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_exec_ok (execute ~dry_run:true ~policy:test_policy ~proof action)

let test_executor_blocked () =
  let action = CurlToFile {
    url = "https://evil.com/x"; host = "evil.com";
    output = "/tmp/x";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_exec_blocked (execute ~dry_run:true ~policy:test_policy ~proof action)

let test_executor_mcp () =
  let action = McpCall {
    server = "search"; tool = "query";
    args = {|{"q": "hello"}|};
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_exec_ok (execute ~dry_run:true ~policy:test_policy ~proof action)

(* ================================================================== *)
(* SECTION 2: Path normalization unit tests                           *)
(* ================================================================== *)

let test_normalize_absolute () =
  assert_equal "basic absolute" ~expected:"/home/user/src"
    ~actual:(match normalize "/home/user/src" with Some s -> s | None -> "NONE")

let test_normalize_trailing_slash () =
  assert_equal "trailing slash" ~expected:"/home/user/src"
    ~actual:(match normalize "/home/user/src/" with Some s -> s | None -> "NONE")

let test_normalize_double_slash () =
  assert_equal "double slash" ~expected:"/home/user/src"
    ~actual:(match normalize "/home//user///src" with Some s -> s | None -> "NONE")

let test_normalize_dot_segments () =
  assert_equal "dot segments" ~expected:"/home/user/src"
    ~actual:(match normalize "/home/./user/./src" with Some s -> s | None -> "NONE")

let test_normalize_dotdot () =
  assert_equal "dotdot resolution" ~expected:"/home/user"
    ~actual:(match normalize "/home/user/src/.." with Some s -> s | None -> "NONE")

let test_normalize_dotdot_at_root () =
  assert_equal "dotdot at root" ~expected:"/etc"
    ~actual:(match normalize "/../etc" with Some s -> s | None -> "NONE")

let test_normalize_backslash () =
  assert_equal "backslash" ~expected:"/home/user/src"
    ~actual:(match normalize "\\home\\user\\src" with Some s -> s | None -> "NONE")

let test_normalize_root () =
  assert_equal "root" ~expected:"/"
    ~actual:(match normalize "/" with Some s -> s | None -> "NONE")

let test_normalize_empty () =
  assert_true "empty normalizes to None"
    (normalize "" = None)

(* ================================================================== *)
(* SECTION 3: Segment-based path containment                          *)
(* ================================================================== *)

let test_path_within_exact () =
  assert_true "exact match" (path_within ~parent:"/tmp" "/tmp")

let test_path_within_child () =
  assert_true "child" (path_within ~parent:"/tmp" "/tmp/foo/bar.txt")

let test_path_within_sibling_prefix () =
  assert_false "sibling prefix confusion"
    (path_within ~parent:"/workspace/reports" "/workspace/reports2/x.txt")

let test_path_within_traversal_escape () =
  assert_false "traversal escape"
    (path_within ~parent:"/home/user/src" "/home/user/src/../../etc")

let test_path_within_relative () =
  assert_true "relative containment"
    (path_within ~parent:"src" "src/lib/foo.ml")

let test_path_within_relative_no_match () =
  assert_false "relative no match"
    (path_within ~parent:"src" "other/lib/foo.ml")

let test_path_within_nested_allowed () =
  assert_true "nested allowed"
    (path_within ~parent:"/home/user/src/lib" "/home/user/src/lib/types.ml")

let test_path_within_not_child () =
  assert_false "not a child"
    (path_within ~parent:"/home/user/src" "/home/user/other/file.ml")

let test_has_traversal_yes () =
  assert_true "has .." (has_traversal "/home/../etc")

let test_has_traversal_no () =
  assert_false "no .." (has_traversal "/home/user/src/file.ml")

let test_has_traversal_backslash () =
  assert_true "backslash .." (has_traversal "\\home\\..\\etc")

(* ================================================================== *)
(* SECTION 4: Typed checker error tests                               *)
(* ================================================================== *)

let test_error_claimed_mismatch () =
  let action = GrepRecursive {
    pattern = "x"; root = "/home/user/src"; output = "/tmp/out";
  } in
  let proof = {
    claimed_effects = [ReadPath "/home/user/src"];
    destructive = false; approval = None; explanation = None;
  } in
  assert_rejected_with ClaimedEffectsMismatch
    (check ~policy:test_policy ~proof ~action)

let test_error_unauthorized_write () =
  let action = GrepRecursive {
    pattern = "x"; root = "/home/user/src"; output = "/etc/passwd";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected_with (UnauthorizedWrite "/etc/passwd")
    (check ~policy:test_policy ~proof ~action)

let test_error_unauthorized_host () =
  let action = CurlToFile {
    url = "https://evil.com/x"; host = "evil.com"; output = "/tmp/x";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected_with (UnauthorizedHost "evil.com")
    (check ~policy:test_policy ~proof ~action)

let test_error_unauthorized_mcp () =
  let action = McpCall {
    server = "files"; tool = "delete_file"; args = "{}";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected_with (UnauthorizedMcpTool ("files", "delete_file"))
    (check ~policy:test_policy ~proof ~action)

let test_error_missing_approval () =
  let action = RemoveByGlob {
    root = "/tmp"; suffix = ".log"; recursive = false;
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = true;
    approval = None; explanation = None;
  } in
  assert_rejected_with MissingDestructiveApproval
    (check ~policy:test_policy ~proof ~action)

let test_error_path_traversal () =
  let action = GrepRecursive {
    pattern = "secret"; root = "/home/user/src/../../../etc";
    output = "/tmp/out";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected_with (PathTraversalBlocked "/home/user/src/../../../etc")
    (check ~policy:test_policy ~proof ~action)

(* ================================================================== *)
(* SECTION 5: Plan module tests                                       *)
(* ================================================================== *)

let test_plan_ok () =
  let action = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src"; output = "/tmp/out";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  match Certiclaw.Plan.plan ~dry_run:true ~policy:test_policy ~proof action with
  | Ok p ->
    assert_true "plan has effects" (List.length p.inferred_effects > 0);
    assert_true "plan is dry-run" p.dry_run
  | Error err ->
    failwith ("Expected Ok plan, got Error: " ^ show_check_error err)

let test_plan_error () =
  let action = CurlToFile {
    url = "https://evil.com/x"; host = "evil.com"; output = "/tmp/x";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  match Certiclaw.Plan.plan ~dry_run:true ~policy:test_policy ~proof action with
  | Ok _ -> failwith "Expected Error, got Ok"
  | Error _ -> ()

(* ================================================================== *)
(* SECTION 6: Policy loading tests                                    *)
(* ================================================================== *)

let test_policy_load_valid () =
  let json = {|{
    "readable_paths": ["/home/user/src"],
    "writable_paths": ["/tmp"],
    "allowed_bins":   ["grep"],
    "allowed_hosts":  ["example.com"],
    "allowed_mcp":    [["files", "read_file"]]
  }|} in
  match parse_json_string json with
  | Ok pol ->
    assert_equal "readable" ~expected:"/home/user/src"
      ~actual:(List.hd pol.readable_paths);
    assert_equal "writable" ~expected:"/tmp"
      ~actual:(List.hd pol.writable_paths);
    assert_equal "bins" ~expected:"grep"
      ~actual:(List.hd pol.allowed_bins);
    assert_equal "hosts" ~expected:"example.com"
      ~actual:(List.hd pol.allowed_hosts);
    let (s, t) = List.hd pol.allowed_mcp in
    assert_equal "mcp server" ~expected:"files" ~actual:s;
    assert_equal "mcp tool" ~expected:"read_file" ~actual:t
  | Error e -> failwith ("Expected Ok, got: " ^ show_policy_load_error e)

let test_policy_load_missing_fields () =
  (* Missing fields default to empty — deny by default *)
  let json = {|{}|} in
  match parse_json_string json with
  | Ok pol ->
    assert_true "empty readable" (pol.readable_paths = []);
    assert_true "empty writable" (pol.writable_paths = []);
    assert_true "empty bins" (pol.allowed_bins = []);
    assert_true "empty hosts" (pol.allowed_hosts = []);
    assert_true "empty mcp" (pol.allowed_mcp = [])
  | Error e -> failwith ("Expected Ok, got: " ^ show_policy_load_error e)

let test_policy_load_malformed_json () =
  let json = {|{ not valid json |} in
  match parse_json_string json with
  | Ok _ -> failwith "Expected Error for malformed JSON"
  | Error (JsonParseError _) -> ()
  | Error e -> failwith ("Wrong error kind: " ^ show_policy_load_error e)

let test_policy_load_wrong_type () =
  let json = {|{"readable_paths": "not-an-array"}|} in
  match parse_json_string json with
  | Ok _ -> failwith "Expected Error for wrong type"
  | Error (SchemaError _) -> ()
  | Error e -> failwith ("Wrong error kind: " ^ show_policy_load_error e)

let test_policy_load_bad_mcp_shape () =
  let json = {|{"allowed_mcp": ["not-a-pair"]}|} in
  match parse_json_string json with
  | Ok _ -> failwith "Expected Error for bad MCP shape"
  | Error (SchemaError _) -> ()
  | Error e -> failwith ("Wrong error kind: " ^ show_policy_load_error e)

let test_policy_load_not_object () =
  let json = {|[1, 2, 3]|} in
  match parse_json_string json with
  | Ok _ -> failwith "Expected Error for non-object"
  | Error (SchemaError _) -> ()
  | Error e -> failwith ("Wrong error kind: " ^ show_policy_load_error e)

let test_policy_load_file_not_found () =
  match load_file "/nonexistent/policy.json" with
  | Ok _ -> failwith "Expected FileNotFound"
  | Error (FileNotFound _) -> ()
  | Error e -> failwith ("Wrong error kind: " ^ show_policy_load_error e)

let test_policy_deny_by_default () =
  (* Empty policy denies everything *)
  let pol = empty_policy in
  let action = GrepRecursive {
    pattern = "x"; root = "/home/user/src"; output = "/tmp/out";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  assert_rejected (check ~policy:pol ~proof ~action)

(* ================================================================== *)
(* SECTION 7: Audit log tests                                         *)
(* ================================================================== *)

let test_audit_record_accepted () =
  Audit.reset_seq ();
  let action = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src"; output = "/tmp/out";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  let cr = check ~policy:test_policy ~proof ~action in
  let record = Audit.make_record ~action ~proof ~mode:DryRun ~check_result:cr in
  assert_true "seq is 0" (record.seq = 0);
  (match record.decision with
   | Audit.Accepted -> ()
   | Audit.Rejected _ -> failwith "Expected Accepted audit decision");
  assert_true "rendered is Some" (record.rendered <> None);
  assert_true "mode is DryRun" (record.mode = DryRun)

let test_audit_record_rejected () =
  Audit.reset_seq ();
  let action = CurlToFile {
    url = "https://evil.com/x"; host = "evil.com"; output = "/tmp/x";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  let cr = check ~policy:test_policy ~proof ~action in
  let record = Audit.make_record ~action ~proof ~mode:CheckOnly ~check_result:cr in
  (match record.decision with
   | Audit.Rejected _ -> ()
   | Audit.Accepted -> failwith "Expected Rejected audit decision");
  assert_true "rendered is None for rejection" (record.rendered = None);
  assert_true "mode is CheckOnly" (record.mode = CheckOnly)

let test_audit_log_collects () =
  Audit.reset_seq ();
  let log = Audit.create_log () in
  (* Run two actions through executor with audit *)
  let action1 = GrepRecursive {
    pattern = "x"; root = "/home/user/src"; output = "/tmp/out";
  } in
  let effects1 = infer_effects action1 in
  let proof1 = {
    claimed_effects = effects1; destructive = false;
    approval = None; explanation = None;
  } in
  let _ = execute ~dry_run:true ~audit_log:log ~policy:test_policy
      ~proof:proof1 action1 in
  let action2 = CurlToFile {
    url = "https://evil.com/x"; host = "evil.com"; output = "/tmp/x";
  } in
  let effects2 = infer_effects action2 in
  let proof2 = {
    claimed_effects = effects2; destructive = false;
    approval = None; explanation = None;
  } in
  let _ = execute ~dry_run:true ~audit_log:log ~policy:test_policy
      ~proof:proof2 action2 in
  let records = Audit.get_records log in
  assert_true "2 records" (List.length records = 2);
  let r0 = List.nth records 0 in
  let r1 = List.nth records 1 in
  assert_true "first seq < second seq" (r0.seq < r1.seq);
  (match r0.decision with
   | Audit.Accepted -> ()
   | _ -> failwith "First should be accepted");
  (match r1.decision with
   | Audit.Rejected _ -> ()
   | _ -> failwith "Second should be rejected")

let test_audit_json_format () =
  Audit.reset_seq ();
  let action = GrepRecursive {
    pattern = "x"; root = "/home/user/src"; output = "/tmp/out";
  } in
  let effects = infer_effects action in
  let proof = {
    claimed_effects = effects; destructive = false;
    approval = None; explanation = None;
  } in
  let cr = check ~policy:test_policy ~proof ~action in
  let record = Audit.make_record ~action ~proof ~mode:DryRun ~check_result:cr in
  let json_str = Audit.json_record record in
  (* Basic structural checks *)
  assert_true "starts with {" (String.length json_str > 0 && json_str.[0] = '{');
  assert_true "contains seq" (String.length json_str > 5);
  assert_true "contains accepted"
    (let idx = ref false in
     String.iter (fun _ -> idx := true) json_str;
     !idx)

(* ================================================================== *)
(* Runner                                                              *)
(* ================================================================== *)

let () =
  Printf.printf "\n=== CertiClaw Test Suite ===\n\n";

  Printf.printf "  -- Original MVP tests --\n";
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

  Printf.printf "\n  -- Path normalization --\n";
  run_test "normalize absolute"                test_normalize_absolute;
  run_test "normalize trailing slash"          test_normalize_trailing_slash;
  run_test "normalize double slash"            test_normalize_double_slash;
  run_test "normalize dot segments"            test_normalize_dot_segments;
  run_test "normalize dotdot"                  test_normalize_dotdot;
  run_test "normalize dotdot at root"          test_normalize_dotdot_at_root;
  run_test "normalize backslash"               test_normalize_backslash;
  run_test "normalize root"                    test_normalize_root;
  run_test "normalize empty"                   test_normalize_empty;

  Printf.printf "\n  -- Segment-based containment --\n";
  run_test "path within exact"                 test_path_within_exact;
  run_test "path within child"                 test_path_within_child;
  run_test "path within sibling prefix"        test_path_within_sibling_prefix;
  run_test "path within traversal escape"      test_path_within_traversal_escape;
  run_test "path within relative"              test_path_within_relative;
  run_test "path within relative no match"     test_path_within_relative_no_match;
  run_test "path within nested allowed"        test_path_within_nested_allowed;
  run_test "path within not child"             test_path_within_not_child;
  run_test "has_traversal yes"                 test_has_traversal_yes;
  run_test "has_traversal no"                  test_has_traversal_no;
  run_test "has_traversal backslash"           test_has_traversal_backslash;

  Printf.printf "\n  -- Typed checker errors --\n";
  run_test "error: claimed mismatch"           test_error_claimed_mismatch;
  run_test "error: unauthorized write"         test_error_unauthorized_write;
  run_test "error: unauthorized host"          test_error_unauthorized_host;
  run_test "error: unauthorized mcp"           test_error_unauthorized_mcp;
  run_test "error: missing approval"           test_error_missing_approval;
  run_test "error: path traversal"             test_error_path_traversal;

  Printf.printf "\n  -- Plan module --\n";
  run_test "plan ok"                           test_plan_ok;
  run_test "plan error"                        test_plan_error;

  Printf.printf "\n  -- Policy loading --\n";
  run_test "policy load valid"                 test_policy_load_valid;
  run_test "policy load missing fields"        test_policy_load_missing_fields;
  run_test "policy load malformed JSON"        test_policy_load_malformed_json;
  run_test "policy load wrong type"            test_policy_load_wrong_type;
  run_test "policy load bad MCP shape"         test_policy_load_bad_mcp_shape;
  run_test "policy load not object"            test_policy_load_not_object;
  run_test "policy load file not found"        test_policy_load_file_not_found;
  run_test "policy deny by default"            test_policy_deny_by_default;

  Printf.printf "\n  -- Audit logging --\n";
  run_test "audit record accepted"             test_audit_record_accepted;
  run_test "audit record rejected"             test_audit_record_rejected;
  run_test "audit log collects"                test_audit_log_collects;
  run_test "audit JSON format"                 test_audit_json_format;

  Printf.printf "\n  Results: %d passed, %d failed\n\n" !passed !failed;
  if !failed > 0 then exit 1
