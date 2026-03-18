(** Effect inference.

    Given a typed IR action, compute the complete list of effects it
    would produce.  This is the ground truth — the checker always
    recomputes effects from the IR rather than trusting the proof. *)

open Types

(** Infer the effects of [action].  The returned list is deterministic
    and does not depend on the proof. *)
let infer_effects (action : action) : action_effect list =
  match action with
  | GrepRecursive { pattern = _; root; output } ->
    [ ReadPath root;
      ExecBin "grep";
      WritePath output ]
  | RemoveByGlob { root; suffix = _; recursive = _ } ->
    [ ExecBin "find";
      WritePath root ]
  | CurlToFile { url = _; host; output } ->
    [ ExecBin "curl";
      NetTo host;
      WritePath output ]
  | McpCall { server; tool; args = _ } ->
    [ McpUse (server, tool) ]

(** Is an action destructive?  Currently only [RemoveByGlob] counts. *)
let is_destructive (action : action) : bool =
  match action with
  | RemoveByGlob _ -> true
  | _ -> false
