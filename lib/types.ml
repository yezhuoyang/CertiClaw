(** {1 CertiClaw Core Types}

    {b [TRUSTED CORE]} — This module defines the type language for the
    entire system.  All security-relevant reasoning happens over these
    types.  A bug here compromises the whole system.

    {2 Formal correspondence}

    Each type here corresponds to a definition in [docs/formal-core.md]:
    - [action]        ↔  Action syntax  (§1)
    - [action_effect] ↔  Effect domain  (§2)
    - [policy]        ↔  Policy         (§3)
    - [proof]         ↔  Certificate    (§4)
    - [check_error]   ↔  Error domain   (§5)
    - [check_result]  ↔  Judgment output (§5) *)

(* ================================================================== *)
(* Effects                                                             *)
(* ================================================================== *)

(** A single observable side-effect of an action. *)
type action_effect =
  | ReadPath  of string          (** Read from a filesystem path *)
  | WritePath of string          (** Write / delete a filesystem path *)
  | ExecBin   of string          (** Execute a binary *)
  | NetTo     of string          (** Network access to a host *)
  | McpUse    of string * string (** MCP server × tool invocation *)

(** Structural equality on effects. *)
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

(* ================================================================== *)
(* Approval                                                            *)
(* ================================================================== *)

(** Approval token for destructive actions. *)
type approval =
  | NoApproval
  | ApprovedDestructive of string  (** reason / ticket id *)

(* ================================================================== *)
(* Certificate (proof)                                                 *)
(* ================================================================== *)

type proof = {
  claimed_effects : action_effect list;
  destructive     : bool;
  approval        : approval option;
  explanation     : string option;
}

(* ================================================================== *)
(* Policy                                                              *)
(* ================================================================== *)

type policy = {
  readable_paths : string list;
  writable_paths : string list;
  allowed_bins   : string list;
  allowed_hosts  : string list;
  allowed_mcp    : (string * string) list;
}

(* ================================================================== *)
(* Action IR                                                           *)
(* ================================================================== *)

(** Typed intermediate representation for agent actions.
    Seven variants covering file I/O, search, deletion, network
    download, directory listing, and MCP tool invocation. *)
type action =
  | GrepRecursive of {
      pattern : string;
      root    : string;
      output  : string;
    }
  | RemoveByGlob of {
      root      : string;
      suffix    : string;
      recursive : bool;
    }
  | CurlToFile of {
      url    : string;
      host   : string;
      output : string;
    }
  | McpCall of {
      server : string;
      tool   : string;
      args   : string;
    }
  | ReadFile of {
      path : string;
    }
  | WriteFile of {
      path    : string;
      content : string;
    }
  | ListDir of {
      path : string;
    }

(** Pretty-print an action (compact form for logs). *)
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
  | ReadFile { path } ->
    Printf.sprintf "ReadFile { path=%S }" path
  | WriteFile { path; content } ->
    Printf.sprintf "WriteFile { path=%S; content=%S }" path
      (if String.length content > 40
       then String.sub content 0 37 ^ "..."
       else content)
  | ListDir { path } ->
    Printf.sprintf "ListDir { path=%S }" path

(* ================================================================== *)
(* Checker errors                                                      *)
(* ================================================================== *)

type check_error =
  | ClaimedEffectsMismatch
  | UnauthorizedRead     of string
  | UnauthorizedWrite    of string
  | UnauthorizedBinary   of string
  | UnauthorizedHost     of string
  | UnauthorizedMcpTool  of string * string
  | MissingDestructiveApproval
  | PathTraversalBlocked of string

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

(* ================================================================== *)
(* Checker result                                                      *)
(* ================================================================== *)

type check_result =
  | Accepted
  | Rejected of check_error

(* ================================================================== *)
(* Rendering / plan types  [SUPPORT]                                   *)
(* ================================================================== *)

type rendered_form =
  | BashCommand of string
  | McpRequest  of { server : string; tool : string; args : string }
  | DirectOp    of string  (** OCaml-native file operation description *)

type execution_plan = {
  input_action     : action;
  inferred_effects : action_effect list;
  rendered         : rendered_form;
  dry_run          : bool;
}

(* ================================================================== *)
(* Pipeline result  [SUPPORT]                                          *)
(* ================================================================== *)

type rejection_context = {
  rejected_action  : action;
  inferred_effects : action_effect list;
  claimed_effects  : action_effect list;
}

type pipeline_result =
  | PipelineAccepted of execution_plan
  | PipelineRejected of check_error * rejection_context
