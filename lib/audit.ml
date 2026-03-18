(** {1 Audit Logging}

    {b [SUPPORT]} — Every check/execute decision produces an
    {!audit_record}.  Records can be formatted as human-readable text
    or JSON lines for machine consumption.  A bug here cannot cause
    an unauthorized action to pass {!Check.check}. *)

open Types

(* ------------------------------------------------------------------ *)
(* Audit record                                                        *)
(* ------------------------------------------------------------------ *)

(** The decision that was made. *)
type decision =
  | Accepted
  | Rejected of check_error

(** What mode the action was run in. *)
type exec_mode =
  | DryRun
  | Live
  | CheckOnly  (** plan / check without execution *)

(** A single audit record.  Captures everything about one
    check-or-execute decision. *)
type audit_record = {
  seq             : int;                  (** logical sequence number *)
  action          : action;
  inferred_effects : action_effect list;
  claimed_effects : action_effect list;
  decision        : decision;
  rendered        : rendered_form option; (** None if rejected *)
  mode            : exec_mode;
}

(* ------------------------------------------------------------------ *)
(* Sequence counter                                                    *)
(* ------------------------------------------------------------------ *)

let seq_counter = ref 0

(** Get the next sequence number (monotonically increasing). *)
let next_seq () =
  let n = !seq_counter in
  incr seq_counter;
  n

(** Reset sequence counter (for testing). *)
let reset_seq () = seq_counter := 0

(* ------------------------------------------------------------------ *)
(* Record creation helpers                                             *)
(* ------------------------------------------------------------------ *)

(** Create an audit record from a check result.  Call this from the
    pipeline after checking. *)
let make_record ~(action : action) ~(proof : proof) ~(mode : exec_mode)
    ~(check_result : check_result)
    : audit_record =
  let inferred = Infer.infer_effects action in
  let decision = match check_result with
    | Types.Accepted -> Accepted
    | Types.Rejected e -> Rejected e
  in
  let rendered = match check_result with
    | Types.Accepted -> Some (Render.render action)
    | Types.Rejected _ -> None
  in
  { seq = next_seq ();
    action;
    inferred_effects = inferred;
    claimed_effects  = proof.claimed_effects;
    decision;
    rendered;
    mode }

(* ------------------------------------------------------------------ *)
(* Text formatting                                                     *)
(* ------------------------------------------------------------------ *)

let show_decision = function
  | Accepted -> "ACCEPTED"
  | Rejected e -> "REJECTED: " ^ show_check_error e

let show_mode = function
  | DryRun -> "dry-run"
  | Live -> "live"
  | CheckOnly -> "check-only"

let show_rendered_opt = function
  | None -> "(not rendered)"
  | Some (BashCommand cmd) -> "Bash: " ^ cmd
  | Some (McpRequest { server; tool; args }) ->
    Printf.sprintf "MCP: server=%s tool=%s args=%s" server tool args

(** Format an audit record as human-readable text. *)
let show_record (r : audit_record) : string =
  let buf = Buffer.create 512 in
  let pr fmt = Printf.bprintf buf fmt in
  pr "[audit #%d] %s\n" r.seq (show_decision r.decision);
  pr "  Action:   %s\n" (show_action r.action);
  pr "  Inferred: [%s]\n"
    (String.concat "; " (List.map show_action_effect r.inferred_effects));
  pr "  Claimed:  [%s]\n"
    (String.concat "; " (List.map show_action_effect r.claimed_effects));
  pr "  Rendered: %s\n" (show_rendered_opt r.rendered);
  pr "  Mode:     %s" (show_mode r.mode);
  Buffer.contents buf

(* ------------------------------------------------------------------ *)
(* JSON lines formatting                                               *)
(* ------------------------------------------------------------------ *)

(** Escape a string for embedding in JSON. *)
let json_escape s =
  let buf = Buffer.create (String.length s + 8) in
  String.iter (fun c ->
    match c with
    | '"'  -> Buffer.add_string buf "\\\""
    | '\\' -> Buffer.add_string buf "\\\\"
    | '\n' -> Buffer.add_string buf "\\n"
    | '\t' -> Buffer.add_string buf "\\t"
    | c    -> Buffer.add_char buf c
  ) s;
  Buffer.contents buf

(** Format an effect as a JSON string value. *)
let json_effect e = "\"" ^ json_escape (show_action_effect e) ^ "\""

(** Format an audit record as a single JSON line. *)
let json_record (r : audit_record) : string =
  let decision_str = match r.decision with
    | Accepted -> {|"accepted"|}
    | Rejected _ -> {|"rejected"|}
  in
  let error_str = match r.decision with
    | Accepted -> "null"
    | Rejected e ->
      "\"" ^ json_escape (show_check_error e) ^ "\""
  in
  let rendered_str = match r.rendered with
    | None -> "null"
    | Some (BashCommand cmd) ->
      Printf.sprintf {|{"type":"bash","command":"%s"}|}
        (json_escape cmd)
    | Some (McpRequest { server; tool; args }) ->
      Printf.sprintf {|{"type":"mcp","server":"%s","tool":"%s","args":"%s"}|}
        (json_escape server) (json_escape tool) (json_escape args)
  in
  Printf.sprintf
    {|{"seq":%d,"decision":%s,"error":%s,"action":"%s","inferred":[%s],"claimed":[%s],"rendered":%s,"mode":"%s"}|}
    r.seq
    decision_str
    error_str
    (json_escape (show_action r.action))
    (String.concat "," (List.map json_effect r.inferred_effects))
    (String.concat "," (List.map json_effect r.claimed_effects))
    rendered_str
    (json_escape (show_mode r.mode))

(* ------------------------------------------------------------------ *)
(* In-memory log                                                       *)
(* ------------------------------------------------------------------ *)

(** A simple in-memory audit log (append-only). *)
type audit_log = {
  mutable records : audit_record list;  (** stored in reverse order *)
}

(** Create a fresh empty log. *)
let create_log () : audit_log = { records = [] }

(** Append a record to the log. *)
let log_record (log : audit_log) (r : audit_record) : unit =
  log.records <- r :: log.records

(** Get all records in chronological order. *)
let get_records (log : audit_log) : audit_record list =
  List.rev log.records
