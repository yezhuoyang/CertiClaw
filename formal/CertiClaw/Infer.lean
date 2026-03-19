/-
  CertiClaw Formal Model — Effect Inference

  Corresponds to lib/infer.ml. All 7 action variants covered.
-/

import CertiClaw.Types

namespace CertiClaw

/-- Deterministic effect inference. Covers all 7 action variants. -/
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
  | .readFile path =>
      [.readPath path]
  | .writeFile path _content =>
      [.writePath path]
  | .listDir path =>
      [.readPath path]

/-- Is an action destructive? Only removeByGlob qualifies. -/
def isDestructive (a : Action) : Bool :=
  match a with
  | .removeByGlob .. => true
  | _ => false

end CertiClaw
