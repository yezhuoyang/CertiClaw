(** {1 Execution Plans}

    {b [SUPPORT]} — Runs the check-and-render pipeline and returns a
    structured [execution_plan] on success, or a [check_error] on
    failure.  Never executes anything.

    If an audit log is provided, both accepted and rejected decisions
    are recorded. *)

open Types

(** Build an execution plan: check, infer effects, render.
    Returns [Ok plan] or [Error check_error].
    The [dry_run] flag is recorded in the plan for informational
    purposes only — this function never executes.

    If [~audit_log] is provided, an audit record is appended. *)
let plan ?(dry_run = true) ?(audit_log : Audit.audit_log option)
    ~(policy : policy) ~(proof : proof)
    (action : action) : (execution_plan, check_error) result =
  let cr = Check.check ~policy ~proof ~action in

  (* Emit audit record *)
  (match audit_log with
   | Some log ->
     let record = Audit.make_record ~action ~proof
         ~mode:Audit.CheckOnly ~check_result:cr in
     Audit.log_record log record
   | None -> ());

  match cr with
  | Rejected err -> Error err
  | Accepted ->
    let inferred = Infer.infer_effects action in
    let rendered = Render.render action in
    Ok {
      input_action     = action;
      inferred_effects = inferred;
      rendered;
      dry_run;
    }

(* ------------------------------------------------------------------ *)
(* Pretty-printing                                                     *)
(* ------------------------------------------------------------------ *)

(** Format a rendered_form for display. *)
let show_rendered = function
  | BashCommand cmd ->
    "Bash: " ^ cmd
  | McpRequest { server; tool; args } ->
    Printf.sprintf "MCP: server=%s tool=%s args=%s" server tool args
  | DirectOp desc ->
    "Direct: " ^ desc

(** Format a full execution plan for display. *)
let show_plan (p : execution_plan) : string =
  let buf = Buffer.create 256 in
  let pr fmt = Printf.bprintf buf fmt in
  pr "Action:   %s\n" (show_action p.input_action);
  pr "Effects:  [%s]\n"
    (String.concat "; " (List.map show_action_effect p.inferred_effects));
  pr "Rendered: %s\n" (show_rendered p.rendered);
  pr "Mode:     %s" (if p.dry_run then "dry-run" else "live");
  Buffer.contents buf
