(** {1 Bash Rendering}

    {b [SUPPORT]} — Converts validated IR nodes into shell commands.
    McpCall produces a structured [McpRequest] instead.

    IMPORTANT: This module should only be called on actions that have
    already passed the checker.  A bug here cannot cause an
    unauthorized action to pass {!Check.check}. *)

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

(** Render an action to its [rendered_form].
    Bash-backed actions produce [BashCommand]; MCP calls produce
    [McpRequest]. *)
let render (action : action) : rendered_form =
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

  | McpCall { server; tool; args } ->
    McpRequest { server; tool; args }
