(** Executor module.

    Provides a clean pipeline:  check → render → execute.
    The executor NEVER runs an action that has not been validated.

    By default, execution is simulated (dry-run).  A real executor
    would call [Sys.command] or invoke an MCP transport; those are
    out of scope for this MVP. *)

open Types

(* ------------------------------------------------------------------ *)
(* Execution result                                                    *)
(* ------------------------------------------------------------------ *)

(** The outcome of attempting to execute an action. *)
type exec_result =
  | ExecOk      of string   (** success message / rendered command *)
  | ExecBlocked of string   (** checker rejected the action *)
  | ExecError   of string   (** post-check error (render / runtime) *)

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
    returned without being run. *)
let execute ?(dry_run = true) ~(policy : policy) ~(proof : proof)
    (action : action) : exec_result =

  (* Phase 1: check *)
  match Check.check ~policy ~proof ~action with
  | Rejected reason -> ExecBlocked reason

  | Accepted ->
    (* Phase 2: render *)
    match Render.render action with
    | Render.BashCommand cmd ->
      if dry_run then
        ExecOk ("[DRY-RUN] " ^ cmd)
      else begin
        (* Phase 3: real execution — guarded by dry_run=false *)
        let exit_code = Sys.command cmd in
        if exit_code = 0 then ExecOk cmd
        else ExecError (Printf.sprintf "Command exited with code %d: %s"
                          exit_code cmd)
      end

    | Render.NotBashRenderable _msg ->
      (* MCP path: always simulated for now *)
      match action with
      | McpCall { server; tool; args } ->
        ExecOk (simulate_mcp ~server ~tool ~args)
      | _ ->
        ExecError "Action is not Bash-renderable and not an MCP call"
