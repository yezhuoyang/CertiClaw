/-
  CertiClaw Formal Model — Normalization Contract Theorems

  Proves:
  1. resolveDots output contains no "."
  2. resolveDots output contains no ".."
  3. resolveDots output contains no ""
  4. resolveDots is idempotent
  5. containment commutes with normalization
  6. traversal inputs are consumed
-/

import CertiClaw.Types
import CertiClaw.Normalize

namespace CertiClaw

-- ═══════════════════════════════════════════════════════════════════
-- Helpers for AllClean
-- ═══════════════════════════════════════════════════════════════════

theorem allClean_nil : AllClean [] :=
  fun _ hm => absurd hm (by simp)

theorem allClean_reverse {segs : List String} (h : AllClean segs) :
    AllClean segs.reverse :=
  fun s hs => h s (List.mem_reverse.mp hs)

theorem allClean_cons {s : String} {segs : List String}
    (hs : isClean s) (ht : AllClean segs) : AllClean (s :: segs) :=
  fun x hx => match hx with
    | .head _ => hs
    | .tail _ hm => ht x hm

theorem allClean_of_tail {s : String} {segs : List String}
    (h : AllClean (s :: segs)) : AllClean segs :=
  fun x hx => h x (.tail _ hx)

-- ═══════════════════════════════════════════════════════════════════
-- Core invariant: resolveDotsGo preserves AllClean
-- ═══════════════════════════════════════════════════════════════════

theorem resolveDotsGo_allClean (acc : List String) (input : List String)
    (hacc : AllClean acc) :
    AllClean (resolveDotsGo acc input) := by
  induction input generalizing acc with
  | nil => exact allClean_reverse hacc
  | cons hd tl ih =>
    -- Case split on what hd is
    by_cases h1 : hd = "."
    · subst h1; simp [resolveDotsGo]; exact ih acc hacc
    · by_cases h2 : hd = ".."
      · subst h2
        match acc with
        | _ :: tl' =>
          simp [resolveDotsGo]
          exact ih tl' (allClean_of_tail hacc)
        | [] =>
          simp [resolveDotsGo]
          exact ih [] allClean_nil
      · by_cases h3 : hd = ""
        · subst h3; simp [resolveDotsGo]; exact ih acc hacc
        · -- hd is a regular segment
          simp only [resolveDotsGo]
          exact ih (hd :: acc) (allClean_cons ⟨h1, h2, h3⟩ hacc)

-- ═══════════════════════════════════════════════════════════════════
-- Theorems 1-3: No ".", "..", "" in output
-- ═══════════════════════════════════════════════════════════════════

theorem resolveDots_noDot (segs : List String) :
    NoDot (resolveDots segs) := by
  unfold NoDot resolveDots
  intro hmem
  exact (resolveDotsGo_allClean [] segs allClean_nil "." hmem).1 rfl

theorem resolveDots_noDotDot (segs : List String) :
    NoDotDot (resolveDots segs) := by
  unfold NoDotDot resolveDots
  intro hmem
  exact (resolveDotsGo_allClean [] segs allClean_nil ".." hmem).2.1 rfl

theorem resolveDots_noEmpty (segs : List String) :
    NoEmpty (resolveDots segs) := by
  unfold NoEmpty resolveDots
  intro hmem
  exact (resolveDotsGo_allClean [] segs allClean_nil "" hmem).2.2 rfl

/-- `resolveDots` output is fully normalized. -/
theorem resolveDots_isNormalized (segs : List String) :
    IsNormalized (resolveDots segs) :=
  ⟨resolveDots_noDot segs, resolveDots_noDotDot segs, resolveDots_noEmpty segs⟩

-- ═══════════════════════════════════════════════════════════════════
-- Theorem 4: Idempotence
-- ═══════════════════════════════════════════════════════════════════

/-- On clean input, resolveDotsGo just reverses acc and appends input. -/
theorem resolveDotsGo_clean (acc : List String) (input : List String)
    (hinput : AllClean input) (hacc : AllClean acc) :
    resolveDotsGo acc input = acc.reverse ++ input := by
  induction input generalizing acc with
  | nil => simp [resolveDotsGo]
  | cons hd tl ih =>
    have hhd := hinput hd (.head _)
    have htl := allClean_of_tail hinput
    -- hd is clean, so none of the special cases match
    have h1 := hhd.1  -- hd ≠ "."
    have h2 := hhd.2.1  -- hd ≠ ".."
    have h3 := hhd.2.2  -- hd ≠ ""
    simp only [resolveDotsGo]
    rw [ih (hd :: acc) htl (allClean_cons hhd hacc)]
    simp [List.reverse_cons, List.append_assoc]

/-- `resolveDots` is idempotent. -/
theorem resolveDots_idempotent (segs : List String) :
    resolveDots (resolveDots segs) = resolveDots segs := by
  unfold resolveDots
  have hclean := resolveDotsGo_allClean [] segs allClean_nil
  rw [resolveDotsGo_clean [] (resolveDotsGo [] segs) hclean allClean_nil]
  simp

-- ═══════════════════════════════════════════════════════════════════
-- Theorem 5: Containment commutes with normalization
-- ═══════════════════════════════════════════════════════════════════

/-- Re-normalizing doesn't change containment (by idempotence). -/
theorem containment_idempotent (parent child : List String) :
    segmentContains (resolveDots (resolveDots parent))
                    (resolveDots (resolveDots child)) =
    segmentContains (resolveDots parent) (resolveDots child) := by
  rw [resolveDots_idempotent, resolveDots_idempotent]

-- ═══════════════════════════════════════════════════════════════════
-- Theorem 6: Traversal inputs are consumed
-- ═══════════════════════════════════════════════════════════════════

/-- ".." never appears in resolveDots output. -/
theorem traversal_consumed (segs : List String) :
    ".." ∉ resolveDots segs :=
  resolveDots_noDotDot segs

end CertiClaw
