(** {1 Certificate Checker}

    {b [TRUSTED CORE]} — The central security component.  Validates:
    1. Certificate's claimed effects match inferred effects.
    2. All inferred effects are authorized by the policy.
    3. Destructive actions carry explicit approval.

    The checker NEVER trusts the certificate — it always recomputes
    effects from the IR via {!Infer.infer_effects}.

    {2 Formal correspondence}
    Implements the {i check}(π, C, a) judgment from §5 of
    formal-core.md.  The four steps correspond directly to the
    four premises of the judgment rule.

    {2 Effect comparison}
    Step 2 uses {b canonical list equality}, not set equality.
    [Infer.infer_effects] returns effects in a fixed deterministic
    order for each action variant (see infer.ml), and the checker
    compares the claimed list against this canonical order.

    This matches the Lean formal model exactly:
    - Lean: [if cert.claimedEffects ≠ inferred then ...]
    - OCaml: [if proof.claimed_effects <> inferred then ...]

    A correct agent populates its certificate by calling
    [Infer.infer_effects] and using the result directly, which
    guarantees the lists match. *)

open Types

(* ================================================================== *)
(* Main judgment                                                       *)
(* ================================================================== *)

(** [check ~policy ~proof ~action] runs the four-step validation.

    Step 1: E ← infer(a)
    Step 2: C.claimed = E  (canonical list equality)
    Step 3: ∀ e ∈ E. authorized(π, e)
    Step 4: destructive(a) ⟹ C.approval = ApprovedDestructive(_) *)
let check ~(policy : policy) ~(proof : proof) ~(action : action)
  : check_result =

  (* Step 1 *)
  let inferred = Infer.infer_effects action in

  (* Step 2: canonical list equality — matches Lean model exactly *)
  if proof.claimed_effects <> inferred then
    Rejected ClaimedEffectsMismatch

  (* Step 3 *)
  else match Policy.authorize_all policy inferred with
  | Some err -> Rejected err

  (* Step 4 *)
  | None ->
    if Infer.is_destructive action then
      match proof.approval with
      | Some (ApprovedDestructive _) -> Accepted
      | _ -> Rejected MissingDestructiveApproval
    else
      Accepted
