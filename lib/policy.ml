(** Policy authorization.

    Check whether every effect in a list is permitted by a given
    policy.  Path containment uses a simple prefix check. *)

open Types

(* ------------------------------------------------------------------ *)
(* Path containment                                                    *)
(* ------------------------------------------------------------------ *)

(** [path_within ~parent path] is true when [path] starts with
    [parent].  This is a simplified prefix check — sufficient for the
    MVP but should be hardened for production use. *)
let path_within ~parent path =
  let plen = String.length parent in
  String.length path >= plen
  && String.sub path 0 plen = parent

(** Does [path] fall inside at least one of the [allowed] prefixes? *)
let path_allowed allowed path =
  List.exists (fun parent -> path_within ~parent path) allowed

(* ------------------------------------------------------------------ *)
(* Per-effect authorization                                            *)
(* ------------------------------------------------------------------ *)

(** Check a single effect against the policy.
    Returns [None] if authorized, [Some reason] if denied. *)
let authorize_effect (pol : policy) (eff : action_effect) : string option =
  match eff with
  | ReadPath p ->
    if path_allowed pol.readable_paths p then None
    else Some ("ReadPath not allowed: " ^ p)
  | WritePath p ->
    if path_allowed pol.writable_paths p then None
    else Some ("WritePath not allowed: " ^ p)
  | ExecBin b ->
    if List.mem b pol.allowed_bins then None
    else Some ("ExecBin not allowed: " ^ b)
  | NetTo h ->
    if List.mem h pol.allowed_hosts then None
    else Some ("NetTo not allowed: " ^ h)
  | McpUse (s, t) ->
    if List.mem (s, t) pol.allowed_mcp then None
    else Some ("McpUse not allowed: " ^ s ^ "/" ^ t)

(** Authorize every effect in [effects] against [pol].
    Returns the first denial reason, or [None] if all pass. *)
let authorize_all (pol : policy) (effects : action_effect list) : string option =
  let rec go = function
    | [] -> None
    | e :: rest ->
      match authorize_effect pol e with
      | Some reason -> Some reason
      | None -> go rest
  in
  go effects
