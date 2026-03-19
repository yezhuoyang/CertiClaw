(** {1 Bash Rendering}

    {b [SUPPORT]} — Converts validated IR nodes into executable forms.
    ReadFile/WriteFile/ListDir are rendered as direct OCaml operations
    (no shell involved).  McpCall produces a structured McpRequest. *)

open Types

let shell_quote s =
  "'" ^ String.concat "'\\''" (String.split_on_char '\'' s) ^ "'"

let render (action : action) : rendered_form =
  match action with
  | GrepRecursive { pattern; root; output } ->
    BashCommand (Printf.sprintf "grep -R -n %s %s > %s"
        (shell_quote pattern) (shell_quote root) (shell_quote output))

  | RemoveByGlob { root; suffix; recursive } ->
    let maxdepth = if recursive then "" else " -maxdepth 1" in
    BashCommand (Printf.sprintf "find %s%s -name %s -delete"
        (shell_quote root) maxdepth (shell_quote ("*" ^ suffix)))

  | CurlToFile { url; host = _; output } ->
    BashCommand (Printf.sprintf "curl -fsSL %s -o %s"
        (shell_quote url) (shell_quote output))

  | McpCall { server; tool; args } ->
    McpRequest { server; tool; args }

  | ReadFile { path } ->
    DirectOp (Printf.sprintf "read_file(%s)" path)

  | WriteFile { path; content = _ } ->
    DirectOp (Printf.sprintf "write_file(%s)" path)

  | ListDir { path } ->
    DirectOp (Printf.sprintf "list_dir(%s)" path)
