/-
  CertiClaw Formal Model — Path Normalization

  Models the lexical normalization that the OCaml `Path_check.resolve_dots`
  performs on path segment lists.

  Scope:
  - Operates on `List String` (segment lists), NOT raw path strings.
  - Does NOT model separator unification or string splitting.
  - Does NOT model filesystem semantics (symlinks, mount points).
  - Matches OCaml `resolve_dots` behavior exactly.
-/

import CertiClaw.Types

namespace CertiClaw

-- ═══════════════════════════════════════════════════════════════════
-- Core normalization function
-- ═══════════════════════════════════════════════════════════════════

/-- The internal helper for resolving "." and ".." segments.
    Processes segments left-to-right with an accumulator (stack in reverse).
    Defined as a top-level recursive function so Lean generates
    clean equation lemmas for proofs. -/
def resolveDotsGo (acc : List String) : List String → List String
  | [] => acc.reverse
  | "." :: rest => resolveDotsGo acc rest
  | ".." :: rest =>
      match acc with
      | _ :: tl => resolveDotsGo tl rest
      | [] => resolveDotsGo [] rest
  | "" :: rest => resolveDotsGo acc rest
  | seg :: rest => resolveDotsGo (seg :: acc) rest

/-- Resolve "." and ".." in a segment list, matching OCaml `resolve_dots`.
    Empty strings are also filtered (matching OCaml `split_segments`). -/
def resolveDots (segs : List String) : List String :=
  resolveDotsGo [] segs

-- ═══════════════════════════════════════════════════════════════════
-- Predicates on segment lists
-- ═══════════════════════════════════════════════════════════════════

/-- A segment is "clean": not ".", "..", or "". -/
def isClean (s : String) : Prop := s ≠ "." ∧ s ≠ ".." ∧ s ≠ ""

/-- All segments in a list are clean. -/
def AllClean (segs : List String) : Prop :=
  ∀ s, s ∈ segs → isClean s

/-- No "." entries. -/
def NoDot (segs : List String) : Prop := "." ∉ segs

/-- No ".." entries. -/
def NoDotDot (segs : List String) : Prop := ".." ∉ segs

/-- No empty string entries. -/
def NoEmpty (segs : List String) : Prop := "" ∉ segs

/-- Fully normalized. -/
def IsNormalized (segs : List String) : Prop :=
  NoDot segs ∧ NoDotDot segs ∧ NoEmpty segs

-- ═══════════════════════════════════════════════════════════════════
-- Containment
-- ═══════════════════════════════════════════════════════════════════

/-- Segment-based path containment (prefix relation). -/
def segmentContains (parent child : List String) : Bool :=
  parent.isPrefixOf child

end CertiClaw
