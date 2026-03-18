/-
  CertiClaw Formal Model — Certificate Checker

  Corresponds to lib/check.ml and §5 of docs/formal-core.md.
  Implements the four-step check judgment as a total function.

  Implementation note: This uses decidable propositional equality
  (`if ... = ... then`) instead of BEq (`!=`).  Since `Effect` has
  `DecidableEq`, this gives the same computational behavior but is
  much easier to reason about in proofs.
-/

import CertiClaw.Types
import CertiClaw.Infer
import CertiClaw.Policy

namespace CertiClaw

/-- The core check judgment.  Four sequential steps:
    1. Infer effects from the action.
    2. Verify claimed effects match inferred effects (list equality).
    3. Verify all effects are authorized by policy.
    4. If destructive, verify approval is present. -/
def check (pol : Policy) (cert : Certificate) (a : Action) : CheckResult :=
  let inferred := infer a
  -- Step 2: claimed effects must equal inferred effects
  if cert.claimedEffects ≠ inferred then
    .rejected .claimedEffectsMismatch
  else
    -- Step 3: all effects must be authorized
    match authorizeAll pol inferred with
    | some err => .rejected err
    | none =>
        -- Step 4: destructive actions require approval
        if isDestructive a then
          match cert.approval with
          | some (.approvedDestructive _) => .accepted
          | _ => .rejected .missingDestructiveApproval
        else
          .accepted

end CertiClaw
