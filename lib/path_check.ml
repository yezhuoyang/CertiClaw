(** {1 Path Normalization and Containment}

    {b [TRUSTED CORE]} — Provides segment-based path containment with
    lexical normalization.  Used by {!Policy} to authorize path effects.

    {2 Formal correspondence}
    Implements the {i contains}(parent, child) predicate and
    {i normalize}(p) function from §3 of formal-core.md.

    {2 Limitations}
    - No symlink resolution (would require filesystem access).
    - No Windows drive-letter canonicalization.
    - Relative paths work but are not anchored to a working directory. *)

(* ================================================================== *)
(* Normalization                                                       *)
(* ================================================================== *)

(** Split on '/' and filter empty segments. *)
let split_segments (p : string) : string list =
  String.split_on_char '/' p
  |> List.filter (fun s -> s <> "")

(** Resolve "." and ".." purely lexically.
    ".." at root is dropped — cannot escape above root. *)
let resolve_dots (segs : string list) : string list =
  let rec go acc = function
    | [] -> List.rev acc
    | "." :: rest -> go acc rest
    | ".." :: rest ->
      let acc' = match acc with _ :: tl -> tl | [] -> [] in
      go acc' rest
    | seg :: rest -> go (seg :: acc) rest
  in
  go [] segs

(** Replace backslashes with forward slashes. *)
let unify_separators (p : string) : string =
  String.map (fun c -> if c = '\\' then '/' else c) p

(** Normalize a path to canonical form.
    Returns [None] for empty paths. *)
let normalize (p : string) : string option =
  let p = unify_separators p in
  let is_absolute = String.length p > 0 && p.[0] = '/' in
  let segs = split_segments p |> resolve_dots in
  match segs with
  | [] -> if is_absolute then Some "/" else None
  | _ ->
    let joined = String.concat "/" segs in
    Some (if is_absolute then "/" ^ joined else joined)

(* ================================================================== *)
(* Segment-based containment                                           *)
(* ================================================================== *)

(** [segments_within ~parent ~child] checks that child's normalized
    segments start with exactly parent's normalized segments. *)
let segments_within ~parent ~child =
  let parent_segs = split_segments parent |> resolve_dots in
  let child_segs  = split_segments child  |> resolve_dots in
  let rec starts_with ps cs =
    match ps, cs with
    | [], _ -> true
    | _ :: _, [] -> false
    | p :: ps', c :: cs' ->
      p = c && starts_with ps' cs'
  in
  starts_with parent_segs child_segs

(** [path_within ~parent path] checks containment after normalizing
    both sides. *)
let path_within ~parent path =
  match normalize parent, normalize path with
  | Some np, Some nc -> segments_within ~parent:np ~child:nc
  | _ -> false

(** Does [path] fall inside at least one of the [allowed] directories? *)
let path_allowed allowed path =
  List.exists (fun parent -> path_within ~parent path) allowed

(** Does [path] contain any ".." segments? Quick pre-check for
    flagging traversal attempts with clear error messages. *)
let has_traversal (p : string) : bool =
  let p = unify_separators p in
  let segs = String.split_on_char '/' p in
  List.mem ".." segs
