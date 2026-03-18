(** {1 Effect Inference}

    {b [TRUSTED CORE]} — Given a typed IR action, compute the complete
    list of effects it would produce.  This is the ground truth — the
    checker always recomputes effects from the IR rather than trusting
    the certificate.

    {2 Formal correspondence}
    Implements the ⟦·⟧ function from §2 of formal-core.md. *)

open Types

(** [infer_effects action] returns the deterministic effect list for
    [action].  Does not depend on the certificate. *)
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

(** [is_destructive action] is [true] iff [action] requires explicit
    approval.  Currently only [RemoveByGlob] qualifies.

    Corresponds to the {i destructive} predicate in §2. *)
let is_destructive (action : action) : bool =
  match action with
  | RemoveByGlob _ -> true
  | _ -> false
