/-
  CertiClaw Formal Model — Path Frontend

  Models the lexical preprocessing that converts raw path strings into
  segment lists before `resolveDots` runs.

  OCaml pipeline:
    raw string → unify_separators → split_on '/' → filter empty → resolveDots
  Lean model:
    List Char → unifySepChars → splitOnSlashChars → map String.ofList → filterEmpty → resolveDots

  The core proofs operate on `List Char` for tractability.  String-level
  wrappers are provided for convenience.

  Scope:
  - Purely lexical — no filesystem access.
  - Platform-agnostic except for backslash unification.
-/

import CertiClaw.Normalize
import CertiClaw.NormalizeTheorems

namespace CertiClaw

-- ═══════════════════════════════════════════════════════════════════
-- Step 1: Separator unification
-- ═══════════════════════════════════════════════════════════════════

/-- The backslash character (U+005C). -/
def backslashChar : Char := Char.ofNat 92

/-- Replace backslash with forward slash in a character list.
    Corresponds to OCaml `Path_check.unify_separators`. -/
def unifySepChars (cs : List Char) : List Char :=
  cs.map (fun c => if c == backslashChar then '/' else c)

/-- String-level wrapper. -/
def unifySeparators (s : String) : String :=
  String.ofList (unifySepChars s.toList)

-- ═══════════════════════════════════════════════════════════════════
-- Step 2: Split on '/' into segments
-- ═══════════════════════════════════════════════════════════════════

/-- Split a character list on '/' into groups (sublists between separators).
    Produces empty sublists for consecutive '/' or leading/trailing '/'. -/
def splitOnSlashChars : List Char → List (List Char)
  | [] => [[]]
  | c :: cs =>
    if c == '/' then
      [] :: splitOnSlashChars cs
    else
      match splitOnSlashChars cs with
      | [] => [[c]]
      | seg :: rest => (c :: seg) :: rest

/-- Convert a character-list split into a string-list split. -/
def splitOnSlash (s : String) : List String :=
  (splitOnSlashChars (unifySepChars s.toList)).map String.ofList

-- ═══════════════════════════════════════════════════════════════════
-- Step 3: Filter empty segments
-- ═══════════════════════════════════════════════════════════════════

/-- Remove empty strings from a segment list.
    Corresponds to OCaml `List.filter (fun s -> s <> "")`. -/
def filterEmpty (segs : List String) : List String :=
  segs.filter (· ≠ "")

-- ═══════════════════════════════════════════════════════════════════
-- Full pipeline
-- ═══════════════════════════════════════════════════════════════════

/-- The complete lexical normalization pipeline.
    Corresponds to OCaml: `split_segments p |> resolve_dots`. -/
def normalizePath (s : String) : List String :=
  resolveDots (filterEmpty (splitOnSlash s))

-- ═══════════════════════════════════════════════════════════════════
-- Char-level split properties
-- ═══════════════════════════════════════════════════════════════════

/-- `splitOnSlashChars` always produces a non-empty result. -/
theorem splitOnSlashChars_nonempty (cs : List Char) :
    splitOnSlashChars cs ≠ [] := by
  cases cs with
  | nil => simp [splitOnSlashChars]
  | cons c cs =>
    simp [splitOnSlashChars]
    split
    · simp
    · have := splitOnSlashChars_nonempty cs
      match h : splitOnSlashChars cs with
      | [] => exact absurd h this
      | _ :: _ => simp

/-- No segment produced by `splitOnSlashChars` contains '/'. -/
theorem splitOnSlashChars_no_slash (cs : List Char) :
    ∀ seg, seg ∈ splitOnSlashChars cs → '/' ∉ seg := by
  induction cs with
  | nil =>
    simp [splitOnSlashChars]
  | cons c rest ih =>
    intro seg hseg slash_in_seg
    unfold splitOnSlashChars at hseg
    split at hseg
    · -- c == '/'
      simp at hseg
      cases hseg with
      | inl h => subst h; simp at slash_in_seg
      | inr h => exact ih seg h slash_in_seg
    · -- c ≠ '/'
      rename_i hne
      have hrest := splitOnSlashChars_nonempty rest
      match hm : splitOnSlashChars rest with
      | [] => exact absurd hm hrest
      | first :: others =>
        rw [hm] at hseg
        simp at hseg
        cases hseg with
        | inl h =>
          subst h
          cases slash_in_seg with
          | head => exact hne rfl
          | tail _ hm' => exact ih first (by rw [hm]; exact .head _) hm'
        | inr h => exact ih seg (by rw [hm]; exact .tail _ h) slash_in_seg

-- ═══════════════════════════════════════════════════════════════════
-- filterEmpty properties
-- ═══════════════════════════════════════════════════════════════════

/-- `filterEmpty` output contains no empty strings. -/
theorem filterEmpty_noEmpty (segs : List String) :
    "" ∉ filterEmpty segs := by
  simp [filterEmpty, List.mem_filter]

/-- `filterEmpty` preserves membership of non-empty strings. -/
theorem filterEmpty_preserves {s : String} {segs : List String}
    (hne : s ≠ "") (hmem : s ∈ segs) :
    s ∈ filterEmpty segs := by
  simp [filterEmpty, List.mem_filter]
  exact ⟨hmem, hne⟩

-- ═══════════════════════════════════════════════════════════════════
-- Full pipeline composition theorem
-- ═══════════════════════════════════════════════════════════════════

/-- The full `normalizePath` pipeline produces a normalized path:
    no ".", no "..", no empty segments.
    This is the key theorem connecting the raw-string frontend
    to the clean segment representation used by the checker. -/
theorem normalizePath_isNormalized (s : String) :
    IsNormalized (normalizePath s) :=
  resolveDots_isNormalized _

/-- Applying `resolveDots` to an already-normalized path is a no-op. -/
theorem normalizePath_resolveDots_idempotent (s : String) :
    resolveDots (normalizePath s) = normalizePath s :=
  resolveDots_idempotent _

end CertiClaw
