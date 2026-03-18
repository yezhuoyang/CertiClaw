(** CertiClaw core types.

    This module defines the typed IR for agent actions, effects,
    policies, approvals, and proof certificates. The trusted core
    reasons over these types — never over free-form strings. *)

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

(* ------------------------------------------------------------------ *)
(* Checker result                                                      *)
(* ------------------------------------------------------------------ *)

(** Result of running the checker on an (action, proof, policy) triple. *)
type check_result =
  | Accepted
  | Rejected of string  (** human-readable reason *)
