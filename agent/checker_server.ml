(** CertiClaw Checker Server

    Reads JSON action requests from stdin, runs the checker,
    and writes JSON results to stdout.  This is the bridge
    between the Python LLM agent and the OCaml trusted core.

    Protocol:
      Input:  {"action": <action_json>, "policy_file": <path>}
      Output: {"status": "accepted", "rendered": <string>}
           or {"status": "rejected", "error": <string>, "error_type": <string>}
           or {"status": "executed", "output": <string>}
*)

open Certiclaw.Types

(* ── JSON parsing ──────────────────────────────────────────── *)

let parse_action (json : Yojson.Basic.t) : action option =
  let open Yojson.Basic.Util in
  try
    let tool = json |> member "tool" |> to_string in
    let args = json |> member "arguments" in
    match tool with
    | "grep_recursive" ->
      Some (GrepRecursive {
        pattern = args |> member "pattern" |> to_string;
        root = args |> member "root" |> to_string;
        output = args |> member "output" |> to_string;
      })
    | "remove_by_glob" ->
      Some (RemoveByGlob {
        root = args |> member "root" |> to_string;
        suffix = args |> member "suffix" |> to_string;
        recursive = args |> member "recursive" |> to_bool;
      })
    | "curl_to_file" ->
      Some (CurlToFile {
        url = args |> member "url" |> to_string;
        host = args |> member "host" |> to_string;
        output = args |> member "output" |> to_string;
      })
    | "read_file" ->
      Some (ReadFile {
        path = args |> member "path" |> to_string;
      })
    | "write_file" ->
      Some (WriteFile {
        path = args |> member "path" |> to_string;
        content = args |> member "content" |> to_string;
      })
    | "list_dir" ->
      Some (ListDir {
        path = args |> member "path" |> to_string;
      })
    | "mcp_call" ->
      Some (McpCall {
        server = args |> member "server" |> to_string;
        tool = args |> member "tool" |> to_string;
        args = args |> member "args" |> to_string;
      })
    | _ -> None
  with _ -> None

(* ── Certificate generation ────────────────────────────────── *)

let make_cert action =
  let effects = Certiclaw.Infer.infer_effects action in
  { claimed_effects = effects;
    destructive = Certiclaw.Infer.is_destructive action;
    approval = None;  (* TODO: read from approval store *)
    explanation = None }

(* ── Render result to string ───────────────────────────────── *)

let show_rendered = function
  | BashCommand cmd -> cmd
  | McpRequest { server; tool; args } ->
    Printf.sprintf "[MCP] server=%s tool=%s args=%s" server tool args
  | DirectOp desc -> desc

(* ── Main: process one request ─────────────────────────────── *)

let process_request json_str policy =
  try
    let json = Yojson.Basic.from_string json_str in
    match parse_action json with
    | None ->
      Printf.sprintf
        {|{"status":"error","error":"Failed to parse action from JSON"}|}
    | Some action ->
      let cert = make_cert action in
      let result = Certiclaw.Check.check ~policy ~proof:cert ~action in
      match result with
      | Rejected err ->
        let err_type = match err with
          | ClaimedEffectsMismatch -> "ClaimedEffectsMismatch"
          | UnauthorizedRead _ -> "UnauthorizedRead"
          | UnauthorizedWrite _ -> "UnauthorizedWrite"
          | UnauthorizedBinary _ -> "UnauthorizedBinary"
          | UnauthorizedHost _ -> "UnauthorizedHost"
          | UnauthorizedMcpTool _ -> "UnauthorizedMcpTool"
          | MissingDestructiveApproval -> "MissingDestructiveApproval"
          | PathTraversalBlocked _ -> "PathTraversalBlocked"
        in
        Yojson.Basic.to_string (`Assoc [
          ("status", `String "rejected");
          ("error", `String (show_check_error err));
          ("error_type", `String err_type);
          ("action", `String (show_action action)) ])
      | Accepted ->
        let rendered = Certiclaw.Render.render action in
        (* Execute the action *)
        let exec_result =
          Certiclaw.Exec.execute ~dry_run:false ~policy ~proof:cert action
        in
        match exec_result with
        | Certiclaw.Exec.ExecOk output ->
          let out = if String.length output > 2000
                    then String.sub output 0 2000 ^ "..."
                    else output in
          (* Use Yojson for proper JSON escaping *)
          let json = `Assoc [
            ("status", `String "executed");
            ("rendered", `String (show_rendered rendered));
            ("output", `String out);
          ] in
          Yojson.Basic.to_string json
        | Certiclaw.Exec.ExecBlocked _ ->
          Yojson.Basic.to_string (`Assoc [
            ("status", `String "error");
            ("error", `String "Blocked after accept (bug)") ])
        | Certiclaw.Exec.ExecError msg ->
          Yojson.Basic.to_string (`Assoc [
            ("status", `String "exec_error");
            ("rendered", `String (show_rendered rendered));
            ("error", `String msg) ])
  with exn ->
    Printf.sprintf
      {|{"status":"error","error":"Exception: %s"}|}
      (String.escaped (Printexc.to_string exn))

(* ── Main loop ─────────────────────────────────────────────── *)

let () =
  (* Load policy *)
  let policy_path = if Array.length Sys.argv > 1 then Sys.argv.(1)
    else "examples/policy.json" in
  let policy = match Certiclaw.Policy_load.load_file policy_path with
    | Ok p -> p
    | Error e ->
      Printf.eprintf "Failed to load policy from %s: %s\n"
        policy_path (Certiclaw.Policy_load.show_policy_load_error e);
      exit 1
  in
  Printf.eprintf "[CertiClaw checker ready, policy loaded: %s]\n%!" policy_path;

  (* Read JSON lines from stdin, process each *)
  try while true do
    let line = input_line stdin in
    let result = process_request line policy in
    Printf.printf "%s\n%!" result
  done with End_of_file -> ()
