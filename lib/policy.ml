(** {1 Policy Authorization}

    {b [TRUSTED CORE]} — Check whether every effect in a list is
    permitted by a given policy.  Path containment uses segment-based
    logic with normalization (see {!Path_check}).

    {2 Formal correspondence}
    Implements the {i authorized}(π, e) judgment from §3 of
    formal-core.md, and the {i all-authorized}(π, E) lifting. *)

open Types

(** [authorize_effect pol eff] returns [None] if [eff] is authorized
    by [pol], or [Some check_error] if denied.

    Paths with ".." segments are rejected immediately with
    [PathTraversalBlocked] before containment is checked. *)
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

(** [authorize_all pol effects] returns the first denial, or [None]. *)
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
