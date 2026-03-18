(** Proof-carrying certificate checker.

    This is the core trusted component.  It validates that:
    1. The proof's claimed effects match the effects inferred from the IR.
    2. All inferred effects are permitted by the policy.
    3. Destructive actions carry an explicit approval.

    The checker NEVER trusts the proof's claims — it always recomputes
    effects from the IR. *)

open Types

(* ------------------------------------------------------------------ *)
(* Effect-list comparison                                              *)
(* ------------------------------------------------------------------ *)

(** Check that two action_effect lists are equal as sets (order-insensitive).
    Returns [true] iff every element in [a] appears in [b] and vice
    versa.  O(n*m) — fine for small action_effect lists. *)
let effects_match (a : action_effect list) (b : action_effect list) : bool =
  let subset xs ys =
    List.for_all (fun x -> List.exists (fun y -> action_effect_equal x y) ys) xs
  in
  subset a b && subset b a

(* ------------------------------------------------------------------ *)
(* Main checker                                                        *)
(* ------------------------------------------------------------------ *)

(** Run all validation checks on [(action, proof, policy)].
    Returns [Accepted] or [Rejected reason]. *)
let check ~(policy : policy) ~(proof : proof) ~(action : action)
  : check_result =

  (* Step 1: infer ground-truth effects from the IR *)
  let inferred = Infer.infer_effects action in

  (* Step 2: verify claimed effects match inferred effects *)
  if not (effects_match proof.claimed_effects inferred) then
    Rejected "Claimed effects do not match inferred effects"

  (* Step 3: verify all effects are authorized by policy *)
  else match Policy.authorize_all policy inferred with
  | Some reason -> Rejected reason

  (* Step 4: if action is destructive, require explicit approval *)
  | None ->
    if Infer.is_destructive action then
      match proof.approval with
      | Some (ApprovedDestructive _) -> Accepted
      | _ -> Rejected "Destructive action requires explicit approval"
    else
      Accepted
