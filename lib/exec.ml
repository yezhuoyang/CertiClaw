(** {1 Executor}

    {b [SUPPORT]} — Check -> render -> execute pipeline.
    Supports both dry-run and live execution modes. *)

open Types

type exec_result =
  | ExecOk      of string
  | ExecBlocked of check_error
  | ExecError   of string

let simulate_mcp ~server ~tool ~args =
  Printf.sprintf "[DRY-RUN MCP] server=%s tool=%s args=%s" server tool args

(** Execute a direct file operation (ReadFile/WriteFile/ListDir). *)
let execute_direct_op action =
  match action with
  | ReadFile { path } ->
    (try
       let ic = open_in path in
       let n = in_channel_length ic in
       let content = really_input_string ic n in
       close_in ic;
       ExecOk (Printf.sprintf "Read %d bytes from %s" n path
               ^ "\n" ^ (if n > 500 then String.sub content 0 500 ^ "..."
                         else content))
     with exn ->
       ExecError (Printf.sprintf "Read failed: %s" (Printexc.to_string exn)))
  | WriteFile { path; content } ->
    (try
       let oc = open_out path in
       output_string oc content;
       close_out oc;
       ExecOk (Printf.sprintf "Wrote %d bytes to %s"
                 (String.length content) path)
     with exn ->
       ExecError (Printf.sprintf "Write failed: %s" (Printexc.to_string exn)))
  | ListDir { path } ->
    (try
       let entries = Sys.readdir path in
       let listing = Array.to_list entries |> String.concat "\n" in
       ExecOk (Printf.sprintf "Directory %s (%d entries):\n%s"
                 path (Array.length entries) listing)
     with exn ->
       ExecError (Printf.sprintf "ListDir failed: %s" (Printexc.to_string exn)))
  | _ -> ExecError "Not a direct operation"

let execute ?(dry_run = true) ?(audit_log : Audit.audit_log option)
    ~(policy : policy) ~(proof : proof) (action : action) : exec_result =

  let cr = Check.check ~policy ~proof ~action in

  let mode = if dry_run then Audit.DryRun else Audit.Live in
  (match audit_log with
   | Some log ->
     let record = Audit.make_record ~action ~proof ~mode ~check_result:cr in
     Audit.log_record log record
   | None -> ());

  match cr with
  | Rejected err -> ExecBlocked err
  | Accepted ->
    match Render.render action with
    | BashCommand cmd ->
      if dry_run then ExecOk ("[DRY-RUN] " ^ cmd)
      else begin
        let exit_code = Sys.command cmd in
        if exit_code = 0 then ExecOk cmd
        else ExecError (Printf.sprintf "Exit code %d: %s" exit_code cmd)
      end
    | McpRequest { server; tool; args } ->
      ExecOk (simulate_mcp ~server ~tool ~args)
    | DirectOp desc ->
      if dry_run then ExecOk ("[DRY-RUN] " ^ desc)
      else execute_direct_op action
