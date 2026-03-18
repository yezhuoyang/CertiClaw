/-
  CertiClaw Formal Model — Core Types

  Corresponds to the core section of lib/types.ml in the OCaml implementation,
  and to §1–§5 of docs/formal-core.md.

  Key abstraction: paths are represented as `List String` (segment lists),
  not raw `String`.  This models *normalized* paths — the normalization
  step (resolve_dots, unify_separators) is an implementation concern handled
  by the OCaml Path_check module before any path enters the checker.
  By using segment lists here, path traversal ("..") is impossible by
  construction, which eliminates PathTraversalBlocked from the formal model.
-/

namespace CertiClaw

/-- A filesystem path represented as a list of directory/file segments.
    Example: `/home/user/src` is `["home", "user", "src"]`.
    This models *already-normalized* paths. -/
abbrev Path := List String

/-- A single observable side-effect of an action.
    Corresponds to OCaml `action_effect`. -/
inductive Effect where
  | readPath  : Path → Effect
  | writePath : Path → Effect
  | execBin   : String → Effect
  | netTo     : String → Effect
  | mcpUse    : String → String → Effect
  deriving BEq, Repr, DecidableEq, Hashable

/-- Approval token for destructive actions.
    Corresponds to OCaml `approval`. -/
inductive Approval where
  | noApproval : Approval
  | approvedDestructive : String → Approval
  deriving BEq, Repr, DecidableEq

/-- A certificate (proof) that the agent supplies alongside an action.
    The checker verifies `claimedEffects` against independently inferred
    effects — it never trusts the certificate directly.
    Corresponds to OCaml `proof`. -/
structure Certificate where
  claimedEffects : List Effect
  destructive    : Bool
  approval       : Option Approval
  deriving BEq, Repr

/-- An authorization policy.  All fields are allowlists; absence = deny.
    Corresponds to OCaml `policy`.
    Note: paths in the policy are `List String` (segment lists). -/
structure Policy where
  readablePaths : List Path
  writablePaths : List Path
  allowedBins   : List String
  allowedHosts  : List String
  allowedMcp    : List (String × String)
  deriving BEq, Repr

/-- Typed intermediate representation for agent actions.
    Corresponds to OCaml `action`.
    Path fields use `Path` (= `List String`) instead of raw strings. -/
inductive Action where
  | grepRecursive (pattern : String) (root : Path) (output : Path) : Action
  | removeByGlob  (root : Path) (suffix : String) (recursive : Bool) : Action
  | curlToFile    (url : String) (host : String) (output : Path) : Action
  | mcpCall       (server : String) (tool : String) (args : String) : Action
  deriving BEq, Repr

/-- Structured error type for checker rejections.
    Corresponds to OCaml `check_error`.
    Note: `PathTraversalBlocked` is absent because paths are pre-normalized
    segment lists — traversal is impossible by construction. -/
inductive CheckError where
  | claimedEffectsMismatch   : CheckError
  | unauthorizedRead         : Path → CheckError
  | unauthorizedWrite        : Path → CheckError
  | unauthorizedBinary       : String → CheckError
  | unauthorizedHost         : String → CheckError
  | unauthorizedMcpTool      : String → String → CheckError
  | missingDestructiveApproval : CheckError
  deriving BEq, Repr, DecidableEq

/-- Result of the core check judgment.
    Corresponds to OCaml `check_result`. -/
inductive CheckResult where
  | accepted : CheckResult
  | rejected : CheckError → CheckResult
  deriving BEq, Repr

end CertiClaw
