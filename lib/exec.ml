(** {1 Executor}

    {b [SUPPORT]} — Provides the check → render → execute pipeline.
    The executor NEVER runs an action that has not been validated.
    A bug in this module cannot cause an unauthorized action to pass
    {!Check.check}.

    By default, execution is simulated (dry-run).  All decisions are
    recorded in an optional {!Audit.audit_log}. *)

open Types

(* ------------------------------------------------------------------ *)
(* Execution result                                                    *)
(* ------------------------------------------------------------------ *)

(** The outcome of attempting to execute an action. *)
type exec_result =
  | ExecOk      of string       (** success message / rendered command *)
  | ExecBlocked of check_error  (** checker rejected the action *)
  | ExecError   of string       (** post-check error (render / runtime) *)

(* ------------------------------------------------------------------ *)
(* Simulated MCP transport                                             *)
(* ------------------------------------------------------------------ *)

(** Placeholder MCP invocation.  In a real system this would call the
    MCP server over JSON-RPC.  For now it returns a dry-run message. *)
let simulate_mcp ~server ~tool ~args =
  Printf.sprintf "[DRY-RUN MCP] server=%s tool=%s args=%s" server tool args

(* ------------------------------------------------------------------ *)
(* Execute pipeline                                                    *)
(* ------------------------------------------------------------------ *)

(** Run the full check → render → execute pipeline.

    [~dry_run] (default [true]) controls whether the Bash command is
    actually executed.  In dry-run mode the rendered command is
    returned without being run.

    If [~audit_log] is provided, an audit record is appended for
    every decision (accepted or rejected). *)
let execute ?(dry_run = true) ?(audit_log : Audit.audit_log option)
    ~(policy : policy) ~(proof : proof) (action : action) : exec_result =

  (* Phase 1: check *)
  let cr = Check.check ~policy ~proof ~action in

  (* Emit audit record *)
  let mode = if dry_run then Audit.DryRun else Audit.Live in
  (match audit_log with
   | Some log ->
     let record = Audit.make_record ~action ~proof ~mode ~check_result:cr in
     Audit.log_record log record
   | None -> ());

  match cr with
  | Rejected err -> ExecBlocked err

  | Accepted ->
    (* Phase 2: render *)
    match Render.render action with
    | BashCommand cmd ->
      if dry_run then
        ExecOk ("[DRY-RUN] " ^ cmd)
      else begin
        (* Phase 3: real execution — guarded by dry_run=false *)
        let exit_code = Sys.command cmd in
        if exit_code = 0 then ExecOk cmd
        else ExecError (Printf.sprintf "Command exited with code %d: %s"
                          exit_code cmd)
      end

    | McpRequest { server; tool; args } ->
      ExecOk (simulate_mcp ~server ~tool ~args)
