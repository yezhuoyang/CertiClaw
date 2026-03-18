(** Bash rendering for IR actions.

    Converts validated IR nodes into shell command strings.
    McpCall does NOT render to Bash — it is handled separately.

    IMPORTANT: This module should only be called on actions that have
    already passed the checker. *)

open Types

(* ------------------------------------------------------------------ *)
(* Shell quoting                                                       *)
(* ------------------------------------------------------------------ *)

(** Simple single-quote escaping for shell arguments.
    Wraps the string in single quotes with internal quotes escaped. *)
let shell_quote s =
  "'" ^ String.concat "'\\''" (String.split_on_char '\'' s) ^ "'"

(* ------------------------------------------------------------------ *)
(* Rendering                                                           *)
(* ------------------------------------------------------------------ *)

(** Render result: either a Bash command or a note that the action
    is not Bash-renderable (e.g. MCP calls). *)
type render_result =
  | BashCommand of string
  | NotBashRenderable of string

(** Render an action to its shell command form.
    Only Bash-backed actions produce [BashCommand]; MCP calls produce
    [NotBashRenderable]. *)
let render (action : action) : render_result =
  match action with
  | GrepRecursive { pattern; root; output } ->
    let cmd = Printf.sprintf "grep -R -n %s %s > %s"
        (shell_quote pattern) (shell_quote root) (shell_quote output)
    in
    BashCommand cmd

  | RemoveByGlob { root; suffix; recursive } ->
    let maxdepth = if recursive then "" else " -maxdepth 1" in
    let cmd = Printf.sprintf "find %s%s -name %s -delete"
        (shell_quote root) maxdepth (shell_quote ("*" ^ suffix))
    in
    BashCommand cmd

  | CurlToFile { url; host = _; output } ->
    let cmd = Printf.sprintf "curl -fsSL %s -o %s"
        (shell_quote url) (shell_quote output)
    in
    BashCommand cmd

  | McpCall { server; tool; args = _ } ->
    NotBashRenderable
      (Printf.sprintf "MCP call: server=%s tool=%s (use MCP transport)"
         server tool)
