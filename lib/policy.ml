(** Policy authorization.

    Check whether every effect in a list is permitted by a given
    policy.  Path containment uses segment-based logic with
    normalization (see {!Path_check}). *)

open Types

(* ------------------------------------------------------------------ *)
(* Per-effect authorization                                            *)
(* ------------------------------------------------------------------ *)

(** Check a single effect against the policy.
    Returns [None] if authorized, or [Some check_error] if denied. *)
let authorize_effect (pol : policy) (eff : action_effect) : check_error option =
  match eff with
  | ReadPath p ->
    if Path_check.has_traversal p then
      Some (PathTraversalBlocked p)
    else if Path_check.path_allowed pol.readable_paths p then None
    else Some (UnauthorizedRead p)
  | WritePath p ->
    if Path_check.has_traversal p then
      Some (PathTraversalBlocked p)
    else if Path_check.path_allowed pol.writable_paths p then None
    else Some (UnauthorizedWrite p)
  | ExecBin b ->
    if List.mem b pol.allowed_bins then None
    else Some (UnauthorizedBinary b)
  | NetTo h ->
    if List.mem h pol.allowed_hosts then None
    else Some (UnauthorizedHost h)
  | McpUse (s, t) ->
    if List.mem (s, t) pol.allowed_mcp then None
    else Some (UnauthorizedMcpTool (s, t))

(** Authorize every effect in [effects] against [pol].
    Returns the first denial error, or [None] if all pass. *)
let authorize_all (pol : policy) (effects : action_effect list)
  : check_error option =
  let rec go = function
    | [] -> None
    | e :: rest ->
      match authorize_effect pol e with
      | Some err -> Some err
      | None -> go rest
  in
  go effects
