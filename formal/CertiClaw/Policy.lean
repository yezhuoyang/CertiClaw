/-
  CertiClaw Formal Model — Policy Authorization

  Corresponds to lib/policy.ml and §3 of docs/formal-core.md.

  Key abstraction: paths are `List String` (pre-normalized), and
  containment is `List.isPrefixOf` on segment lists.
-/

import CertiClaw.Types

namespace CertiClaw

/-- Segment-based path containment.
    `pathContains parent child` holds when `parent` is a prefix of `child`. -/
def pathContains (parent child : Path) : Bool :=
  parent.isPrefixOf child

/-- Does `path` fall inside at least one of the `allowed` directories? -/
def pathAllowed (allowed : List Path) (path : Path) : Bool :=
  allowed.any (pathContains · path)

/-- Check a single effect against the policy.
    Returns `none` if authorized, or `some error` if denied. -/
def authorizeEffect (pol : Policy) (eff : Effect) : Option CheckError :=
  match eff with
  | .readPath p =>
      if pathAllowed pol.readablePaths p then none
      else some (.unauthorizedRead p)
  | .writePath p =>
      if pathAllowed pol.writablePaths p then none
      else some (.unauthorizedWrite p)
  | .execBin b =>
      if b ∈ pol.allowedBins then none
      else some (.unauthorizedBinary b)
  | .netTo h =>
      if h ∈ pol.allowedHosts then none
      else some (.unauthorizedHost h)
  | .mcpUse s t =>
      if (s, t) ∈ pol.allowedMcp then none
      else some (.unauthorizedMcpTool s t)

/-- Authorize every effect.  Returns the first denial, or `none`. -/
def authorizeAll (pol : Policy) : List Effect → Option CheckError
  | [] => none
  | e :: rest =>
      match authorizeEffect pol e with
      | some err => some err
      | none => authorizeAll pol rest

/-- Check whether a single effect is authorized (Bool version). -/
def isAuthorized (pol : Policy) (eff : Effect) : Bool :=
  (authorizeEffect pol eff).isNone

/-- The empty policy — denies everything. -/
def emptyPolicy : Policy where
  readablePaths := []
  writablePaths := []
  allowedBins   := []
  allowedHosts  := []
  allowedMcp    := []

end CertiClaw
