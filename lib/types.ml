(** CertiClaw core types.

    This module defines the typed IR for agent actions, effects,
    policies, approvals, proof certificates, and checker error types.
    The trusted core reasons over these types — never over free-form
    strings. *)

(* ------------------------------------------------------------------ *)
(* Effects: what an action does to the outside world                   *)
(* ------------------------------------------------------------------ *)

(** A single observable side-effect of an action. *)
type action_effect =
  | ReadPath  of string          (** Read from a filesystem path *)
  | WritePath of string          (** Write / delete a filesystem path *)
  | ExecBin   of string          (** Execute a binary *)
  | NetTo     of string          (** Network access to a host *)
  | McpUse    of string * string (** MCP server × tool invocation *)

(** Compare two effects for equality. *)
let action_effect_equal a b =
  match a, b with
  | ReadPath  x,    ReadPath  y    -> x = y
  | WritePath x,    WritePath y    -> x = y
  | ExecBin   x,    ExecBin   y    -> x = y
  | NetTo     x,    NetTo     y    -> x = y
  | McpUse (s1,t1), McpUse (s2,t2) -> s1 = s2 && t1 = t2
  | _ -> false

(** Pretty-print an effect. *)
let show_action_effect = function
  | ReadPath  p     -> "ReadPath("  ^ p ^ ")"
  | WritePath p     -> "WritePath(" ^ p ^ ")"
  | ExecBin   b     -> "ExecBin("   ^ b ^ ")"
  | NetTo     h     -> "NetTo("     ^ h ^ ")"
  | McpUse (s, t)   -> "McpUse("    ^ s ^ ", " ^ t ^ ")"

(* ------------------------------------------------------------------ *)
(* Approval model                                                      *)
(* ------------------------------------------------------------------ *)

(** Approval token for destructive actions. *)
type approval =
  | NoApproval
  | ApprovedDestructive of string  (** reason / ticket id *)

(* ------------------------------------------------------------------ *)
(* Proof / certificate                                                 *)
(* ------------------------------------------------------------------ *)

(** A proof object that the agent supplies alongside an action.
    The checker will verify that [claimed_effects] match the effects
    inferred from the IR, and that approval is present when needed. *)
type proof = {
  claimed_effects : action_effect list;
  destructive     : bool;
  approval        : approval option;
  explanation     : string option;
}

(* ------------------------------------------------------------------ *)
(* Policy                                                              *)
(* ------------------------------------------------------------------ *)

(** An authorization policy that constrains which effects are allowed. *)
type policy = {
  readable_paths : string list;
  writable_paths : string list;
  allowed_bins   : string list;
  allowed_hosts  : string list;
  allowed_mcp    : (string * string) list;  (** (server, tool) pairs *)
}

(* ------------------------------------------------------------------ *)
(* Typed IR for actions                                                *)
(* ------------------------------------------------------------------ *)

(** The structured intermediate representation for agent actions.
    Every action the agent wants to perform must be expressed as one
    of these variants — no arbitrary Bash strings pass through. *)
type action =
  | GrepRecursive of {
      pattern : string;  (** search pattern *)
      root    : string;  (** directory to search *)
      output  : string;  (** file to write results to *)
    }
  | RemoveByGlob of {
      root      : string;  (** base directory *)
      suffix    : string;  (** file suffix / glob tail, e.g. ".tmp" *)
      recursive : bool;
    }
  | CurlToFile of {
      url    : string;  (** full URL *)
      host   : string;  (** hostname for policy check *)
      output : string;  (** destination file *)
    }
  | McpCall of {
      server : string;  (** MCP server name *)
      tool   : string;  (** tool name on that server *)
      args   : string;  (** JSON-encoded arguments *)
    }

(** Pretty-print an action (compact form for logs/demos). *)
let show_action = function
  | GrepRecursive { pattern; root; output } ->
    Printf.sprintf "GrepRecursive { pattern=%S; root=%S; output=%S }"
      pattern root output
  | RemoveByGlob { root; suffix; recursive } ->
    Printf.sprintf "RemoveByGlob { root=%S; suffix=%S; recursive=%b }"
      root suffix recursive
  | CurlToFile { url; host; output } ->
    Printf.sprintf "CurlToFile { url=%S; host=%S; output=%S }"
      url host output
  | McpCall { server; tool; args } ->
    Printf.sprintf "McpCall { server=%S; tool=%S; args=%S }"
      server tool args

(* ------------------------------------------------------------------ *)
(* Typed checker errors                                                *)
(* ------------------------------------------------------------------ *)

(** Structured error type for checker rejections.
    Each variant captures the specific reason for rejection so that
    callers can match on error kind without parsing strings. *)
type check_error =
  | ClaimedEffectsMismatch
  | UnauthorizedRead     of string
  | UnauthorizedWrite    of string
  | UnauthorizedBinary   of string
  | UnauthorizedHost     of string
  | UnauthorizedMcpTool  of string * string
  | MissingDestructiveApproval
  | PathTraversalBlocked of string

(** Pretty-print a checker error for human consumption. *)
let show_check_error = function
  | ClaimedEffectsMismatch ->
    "Claimed effects do not match inferred effects"
  | UnauthorizedRead p ->
    "Unauthorized read: " ^ p
  | UnauthorizedWrite p ->
    "Unauthorized write: " ^ p
  | UnauthorizedBinary b ->
    "Unauthorized binary: " ^ b
  | UnauthorizedHost h ->
    "Unauthorized host: " ^ h
  | UnauthorizedMcpTool (s, t) ->
    "Unauthorized MCP tool: " ^ s ^ "/" ^ t
  | MissingDestructiveApproval ->
    "Destructive action requires explicit approval"
  | PathTraversalBlocked p ->
    "Path traversal blocked: " ^ p

(* ------------------------------------------------------------------ *)
(* Checker result                                                      *)
(* ------------------------------------------------------------------ *)

(** Result of running the checker on an (action, proof, policy) triple. *)
type check_result =
  | Accepted
  | Rejected of check_error  (** structured rejection reason *)

(* ------------------------------------------------------------------ *)
(* Execution plan (dry-run output)                                     *)
(* ------------------------------------------------------------------ *)

(** What the renderer produced for a validated action. *)
type rendered_form =
  | BashCommand of string
  | McpRequest  of { server : string; tool : string; args : string }

(** A structured execution plan returned by [Plan.plan] after a
    successful check-and-render pass.  Contains everything needed
    to inspect what would happen, without actually executing. *)
type execution_plan = {
  input_action    : action;
  inferred_effects : action_effect list;
  rendered        : rendered_form;
  dry_run         : bool;
}
