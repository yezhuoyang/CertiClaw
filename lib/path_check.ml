(** Path normalization and segment-based containment.

    This module replaces the naive prefix check with a safer approach:
    1. Normalize: backslashes → forward slashes, collapse "//" and
       resolve ".." / "." segments purely lexically.
    2. Containment: compare path *segments*, not byte prefixes, so
       "/workspace/reports2" is NOT accepted under "/workspace/reports".

    Limitations (documented, by design for pure-OCaml MVP):
    - No symlink resolution (would require filesystem access).
    - No Windows drive-letter canonicalization beyond lowercasing.
    - Relative paths are checked as-is after normalization; callers
      should pass absolute paths for reliable results. *)

(* ------------------------------------------------------------------ *)
(* Normalization                                                       *)
(* ------------------------------------------------------------------ *)

(** Split a path string on '/' into segments, filtering empty strings
    that arise from leading/trailing/doubled slashes. *)
let split_segments (p : string) : string list =
  String.split_on_char '/' p
  |> List.filter (fun s -> s <> "")

(** Resolve "." and ".." segments purely lexically.
    - "."  is dropped.
    - ".." pops the previous segment if one exists; at the root it is
      dropped (cannot escape above root).
    Returns segments in forward order. *)
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

(** Normalize a path:
    1. Unify separators to '/'.
    2. Split into segments.
    3. Resolve "." and "..".
    4. Reconstruct with a leading '/' if the original was absolute.

    The result is a canonical form suitable for segment comparison.
    Returns [None] if the path is empty after normalization. *)
let normalize (p : string) : string option =
  let p = unify_separators p in
  let is_absolute = String.length p > 0 && p.[0] = '/' in
  let segs = split_segments p |> resolve_dots in
  match segs with
  | [] -> if is_absolute then Some "/" else None
  | _ ->
    let joined = String.concat "/" segs in
    Some (if is_absolute then "/" ^ joined else joined)

(* ------------------------------------------------------------------ *)
(* Segment-based containment                                           *)
(* ------------------------------------------------------------------ *)

(** [segments_within ~parent ~child] is true when [child]'s segments
    start with exactly [parent]'s segments.  This avoids the prefix
    bug: ["/a/bc"] does NOT start-with ["/a/b"]. *)
let segments_within ~parent ~child =
  let parent_segs = split_segments parent |> resolve_dots in
  let child_segs  = split_segments child  |> resolve_dots in
  let rec starts_with ps cs =
    match ps, cs with
    | [], _ -> true                    (* parent exhausted → child is inside *)
    | _ :: _, [] -> false              (* child shorter than parent *)
    | p :: ps', c :: cs' ->
      p = c && starts_with ps' cs'
  in
  starts_with parent_segs child_segs

(** [path_within ~parent path] checks containment after normalizing
    both sides.  Returns [false] if either path fails to normalize. *)
let path_within ~parent path =
  match normalize parent, normalize path with
  | Some np, Some nc -> segments_within ~parent:np ~child:nc
  | _ -> false

(** Does [path] fall inside at least one of the [allowed] directories? *)
let path_allowed allowed path =
  List.exists (fun parent -> path_within ~parent path) allowed

(** Does [path] contain any ".." segments after separator unification?
    This is a quick pre-check before full normalization — useful for
    flagging traversal attempts in error messages. *)
let has_traversal (p : string) : bool =
  let p = unify_separators p in
  let segs = String.split_on_char '/' p in
  List.mem ".." segs
