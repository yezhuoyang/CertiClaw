(** Policy file loading and validation.

    Loads a {!Types.policy} from a JSON file.  The JSON schema is:

    {v
    {
      "readable_paths": ["/home/user/src"],
      "writable_paths": ["/tmp"],
      "allowed_bins":   ["grep", "curl"],
      "allowed_hosts":  ["example.com"],
      "allowed_mcp":    [["server", "tool"]]
    }
    v}

    Missing fields default to empty lists (deny-by-default).
    Invalid shapes produce typed {!policy_load_error} values. *)

open Types

(* ------------------------------------------------------------------ *)
(* Error types                                                         *)
(* ------------------------------------------------------------------ *)

(** What can go wrong when loading a policy file. *)
type policy_load_error =
  | FileNotFound    of string
  | JsonParseError  of string
  | SchemaError     of string  (** field present but wrong type/shape *)

(** Pretty-print a load error. *)
let show_policy_load_error = function
  | FileNotFound path  -> "Policy file not found: " ^ path
  | JsonParseError msg -> "JSON parse error: " ^ msg
  | SchemaError msg    -> "Policy schema error: " ^ msg

(* ------------------------------------------------------------------ *)
(* JSON helpers                                                        *)
(* ------------------------------------------------------------------ *)

(** Extract a string list from a JSON field.  Returns [] if absent. *)
let string_list_field (obj : (string * Yojson.Basic.t) list)
    (key : string) : (string list, policy_load_error) result =
  match List.assoc_opt key obj with
  | None -> Ok []
  | Some (`List items) ->
    let rec go acc = function
      | [] -> Ok (List.rev acc)
      | `String s :: rest -> go (s :: acc) rest
      | _ :: _ -> Error (SchemaError (
          Printf.sprintf "%S: expected array of strings" key))
    in
    go [] items
  | Some _ ->
    Error (SchemaError (Printf.sprintf "%S: expected array" key))

(** Extract an MCP pair list from "allowed_mcp".
    Each element must be a 2-element array of strings: ["server","tool"]. *)
let mcp_list_field (obj : (string * Yojson.Basic.t) list)
  : ((string * string) list, policy_load_error) result =
  match List.assoc_opt "allowed_mcp" obj with
  | None -> Ok []
  | Some (`List items) ->
    let rec go acc = function
      | [] -> Ok (List.rev acc)
      | `List [`String s; `String t] :: rest ->
        go ((s, t) :: acc) rest
      | _ :: _ ->
        Error (SchemaError
                 "\"allowed_mcp\": each entry must be [\"server\", \"tool\"]")
    in
    go [] items
  | Some _ ->
    Error (SchemaError "\"allowed_mcp\": expected array")

(* ------------------------------------------------------------------ *)
(* Core parsing                                                        *)
(* ------------------------------------------------------------------ *)

(** Parse a JSON string into a policy.  Missing fields default to [[]]. *)
let parse_json_string (json_str : string) : (policy, policy_load_error) result =
  let json =
    try Ok (Yojson.Basic.from_string json_str)
    with Yojson.Json_error msg -> Error (JsonParseError msg)
  in
  match json with
  | Error _ as e -> e
  | Ok (`Assoc obj) ->
    (* Use a Result-chaining style for clarity *)
    (match string_list_field obj "readable_paths" with
     | Error _ as e -> e
     | Ok readable_paths ->
       match string_list_field obj "writable_paths" with
       | Error _ as e -> e
       | Ok writable_paths ->
         match string_list_field obj "allowed_bins" with
         | Error _ as e -> e
         | Ok allowed_bins ->
           match string_list_field obj "allowed_hosts" with
           | Error _ as e -> e
           | Ok allowed_hosts ->
             match mcp_list_field obj with
             | Error _ as e -> e
             | Ok allowed_mcp ->
               Ok { readable_paths; writable_paths;
                    allowed_bins; allowed_hosts; allowed_mcp })
  | Ok _ ->
    Error (SchemaError "Top-level JSON must be an object")

(** Load a policy from a file path. *)
let load_file (path : string) : (policy, policy_load_error) result =
  if not (Sys.file_exists path) then
    Error (FileNotFound path)
  else
    let ic = open_in path in
    let n = in_channel_length ic in
    let buf = Bytes.create n in
    really_input ic buf 0 n;
    close_in ic;
    parse_json_string (Bytes.to_string buf)

(* ------------------------------------------------------------------ *)
(* Default (empty) policy — deny everything                            *)
(* ------------------------------------------------------------------ *)

(** A policy that denies all effects.  Useful as a safe starting point. *)
let empty_policy : policy = {
  readable_paths = [];
  writable_paths = [];
  allowed_bins   = [];
  allowed_hosts  = [];
  allowed_mcp    = [];
}
