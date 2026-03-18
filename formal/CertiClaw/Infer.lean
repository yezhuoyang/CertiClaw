/-
  CertiClaw Formal Model — Effect Inference

  Corresponds to lib/infer.ml and §2 of docs/formal-core.md.
  Defines the total function `infer` and the `isDestructive` predicate.
-/

import CertiClaw.Types

namespace CertiClaw

/-- Deterministic effect inference from an action.
    The checker always recomputes this — it never trusts the certificate.
    Corresponds to OCaml `Infer.infer_effects`. -/
def infer (a : Action) : List Effect :=
  match a with
  | .grepRecursive _pattern root output =>
      [.readPath root, .execBin "grep", .writePath output]
  | .removeByGlob root _suffix _recursive =>
      [.execBin "find", .writePath root]
  | .curlToFile _url host output =>
      [.execBin "curl", .netTo host, .writePath output]
  | .mcpCall server tool _args =>
      [.mcpUse server tool]

/-- Is an action destructive (requires explicit approval)?
    Currently only `removeByGlob` qualifies.
    Corresponds to OCaml `Infer.is_destructive`. -/
def isDestructive (a : Action) : Bool :=
  match a with
  | .removeByGlob .. => true
  | _ => false

end CertiClaw
