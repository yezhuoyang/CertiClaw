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
    four premises of the judgment rule. *)

open Types

(* ================================================================== *)
(* Effect-set comparison                                               *)
(* ================================================================== *)

(** [effects_match a b] checks set equality (order-insensitive). *)
let effects_match (a : action_effect list) (b : action_effect list) : bool =
  let subset xs ys =
    List.for_all (fun x -> List.exists (fun y -> action_effect_equal x y) ys) xs
  in
  subset a b && subset b a

(* ================================================================== *)
(* Main judgment                                                       *)
(* ================================================================== *)

(** [check ~policy ~proof ~action] runs the four-step validation.

    Step 1: E ← infer(a)
    Step 2: C.claimed = E  (set equality)
    Step 3: ∀ e ∈ E. authorized(π, e)
    Step 4: destructive(a) ⟹ C.approval = ApprovedDestructive(_) *)
let check ~(policy : policy) ~(proof : proof) ~(action : action)
  : check_result =

  (* Step 1 *)
  let inferred = Infer.infer_effects action in

  (* Step 2 *)
  if not (effects_match proof.claimed_effects inferred) then
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
