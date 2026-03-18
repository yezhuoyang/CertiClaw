(** {1 CertiClaw Trusted Core — Facade}

    This module re-exports exactly the trusted computing base (TCB).
    If you can express a security property using only names from this
    module, then a proof of that property depends only on the TCB.

    {b Modules in the TCB:}
    - {!Types}      — type definitions
    - {!Path_check} — path normalization and containment
    - {!Infer}      — effect inference
    - {!Policy}     — per-effect authorization
    - {!Check}      — certificate validation judgment

    {b Modules outside the TCB:}
    Render, Plan, Pipeline, Exec, Audit, Policy_load — these depend
    on the core but a bug in them cannot cause an unauthorized action
    to pass {!Check.check}. *)

(** {2 Re-exports} *)

module Types      = Types
module Path_check = Path_check
module Infer      = Infer
module Policy     = Policy
module Check      = Check
