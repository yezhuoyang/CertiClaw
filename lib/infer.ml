(** {1 Effect Inference}

    {b [TRUSTED CORE]} — Given a typed IR action, compute the complete
    list of effects it would produce.  This is the ground truth — the
    checker always recomputes effects from the IR rather than trusting
    the certificate.

    {2 Formal correspondence}
    Implements the ⟦·⟧ function from §2 of formal-core.md.
    Lean: [CertiClaw.infer] in [formal/CertiClaw/Infer.lean].

    {2 Canonical effect ordering}
    [infer_effects] returns effects in a {b fixed deterministic order}
    for each action variant.  The checker compares claimed effects
    against this canonical list using structural list equality ([<>]),
    not set equality.  This matches the Lean model exactly.

    The canonical order per variant is:
    - GrepRecursive: [ReadPath root; ExecBin "grep"; WritePath output]
    - RemoveByGlob:  [ExecBin "find"; WritePath root]
    - CurlToFile:    [ExecBin "curl"; NetTo host; WritePath output]
    - McpCall:       [McpUse (server, tool)]

    A correct agent populates its certificate by calling
    [infer_effects] and using the result directly. *)

open Types

(** [infer_effects action] returns the deterministic, canonically-ordered
    effect list for [action].  Does not depend on the certificate. *)
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

    Corresponds to the {i destructive} predicate in §2.
    Lean: [CertiClaw.isDestructive]. *)
let is_destructive (action : action) : bool =
  match action with
  | RemoveByGlob _ -> true
  | _ -> false
