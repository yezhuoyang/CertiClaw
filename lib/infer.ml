(** {1 Effect Inference}

    {b [TRUSTED CORE]} — Deterministic effect inference from the IR.

    {2 Canonical effect ordering}
    - GrepRecursive: [ReadPath root; ExecBin "grep"; WritePath output]
    - RemoveByGlob:  [ExecBin "find"; WritePath root]
    - CurlToFile:    [ExecBin "curl"; NetTo host; WritePath output]
    - McpCall:       [McpUse (server, tool)]
    - ReadFile:      [ReadPath path]
    - WriteFile:     [WritePath path]
    - ListDir:       [ReadPath path] *)

open Types

let infer_effects (action : action) : action_effect list =
  match action with
  | GrepRecursive { pattern = _; root; output } ->
    [ ReadPath root; ExecBin "grep"; WritePath output ]
  | RemoveByGlob { root; suffix = _; recursive = _ } ->
    [ ExecBin "find"; WritePath root ]
  | CurlToFile { url = _; host; output } ->
    [ ExecBin "curl"; NetTo host; WritePath output ]
  | McpCall { server; tool; args = _ } ->
    [ McpUse (server, tool) ]
  | ReadFile { path } ->
    [ ReadPath path ]
  | WriteFile { path; content = _ } ->
    [ WritePath path ]
  | ListDir { path } ->
    [ ReadPath path ]

let is_destructive (action : action) : bool =
  match action with
  | RemoveByGlob _ -> true
  | _ -> false
