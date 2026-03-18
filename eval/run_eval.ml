(** CertiClaw Evaluation Harness

    Usage:
      dune exec eval/run_eval.exe              -- text table
      dune exec eval/run_eval.exe -- --csv     -- CSV output
      dune exec eval/run_eval.exe -- --json    -- JSON lines
      dune exec eval/run_eval.exe -- --summary -- paper-ready summary *)

open Certiclaw.Types
open Certiclaw.Eval_corpus

(* ================================================================== *)
(* Timing                                                              *)
(* ================================================================== *)

let timing_iterations = 10_000

let time_us f =
  let result = f () in
  let t0 = Sys.time () in
  for _ = 1 to timing_iterations do
    ignore (f ())
  done;
  let t1 = Sys.time () in
  let elapsed_us = (t1 -. t0) *. 1_000_000.0
                   /. float_of_int timing_iterations in
  (result, elapsed_us)

(* ================================================================== *)
(* Result comparison                                                   *)
(* ================================================================== *)

let result_matches expected actual =
  match expected, actual with
  | Accepted, Accepted -> true
  | Rejected e1, Rejected e2 -> e1 = e2
  | _ -> false

let show_result = function
  | Accepted -> "ACCEPTED"
  | Rejected e -> "REJECTED(" ^ show_check_error e ^ ")"

(* ================================================================== *)
(* Single case runner                                                  *)
(* ================================================================== *)

type case_result = {
  name       : string;
  category   : string;
  expected   : string;
  actual     : string;
  pass       : bool;
  time_us    : float;
}

let run_case (c : eval_case) : case_result =
  let (actual, elapsed) = time_us (fun () ->
    Certiclaw.Check.check ~policy:c.policy ~proof:c.proof ~action:c.action
  ) in
  { name     = c.name;
    category = c.category;
    expected = show_result c.expected;
    actual   = show_result actual;
    pass     = result_matches c.expected actual;
    time_us  = elapsed }

(* ================================================================== *)
(* Text output                                                         *)
(* ================================================================== *)

let print_text_header () =
  Printf.printf "\n=== CertiClaw Evaluation Harness ===\n\n";
  Printf.printf "%-35s %-8s %-6s %10s  %s\n"
    "Case" "Category" "Pass" "Time(us)" "Result";
  Printf.printf "%s\n" (String.make 95 '-')

let print_text_row (r : case_result) =
  Printf.printf "%-35s %-8s %-6s %10.1f  %s\n"
    r.name r.category
    (if r.pass then "PASS" else "FAIL")
    r.time_us r.actual

let print_text_summary results =
  let total = List.length results in
  let passed = List.length (List.filter (fun r -> r.pass) results) in
  let failed = total - passed in
  let by_cat cat = List.filter (fun r -> r.category = cat) results in
  let pass_count rs = List.length (List.filter (fun r -> r.pass) rs) in
  let benign = by_cat "benign" in
  let attacks = by_cat "attack" in
  let scale = by_cat "scale" in
  let times = List.map (fun r -> r.time_us) results in
  let total_time = List.fold_left ( +. ) 0.0 times in
  let avg_time = if total > 0 then total_time /. float_of_int total else 0.0 in
  let max_time = List.fold_left max 0.0 times in
  let core = by_cat "benign" @ by_cat "attack" in
  let core_times = List.map (fun r -> r.time_us) core in
  let core_avg = if core <> [] then
    List.fold_left ( +. ) 0.0 core_times /. float_of_int (List.length core)
    else 0.0 in
  Printf.printf "%s\n\n" (String.make 95 '-');
  Printf.printf "Summary:\n";
  Printf.printf "  Total cases:      %d\n" total;
  Printf.printf "  Passed:           %d\n" passed;
  Printf.printf "  Failed:           %d\n" failed;
  Printf.printf "  Benign accepted:  %d / %d\n" (pass_count benign) (List.length benign);
  Printf.printf "  Attacks blocked:  %d / %d\n" (pass_count attacks) (List.length attacks);
  Printf.printf "  Scale passed:     %d / %d\n" (pass_count scale) (List.length scale);
  Printf.printf "  Core avg time:    %.1f us\n" core_avg;
  Printf.printf "  Overall avg time: %.1f us\n" avg_time;
  Printf.printf "  Max check time:   %.1f us\n" max_time;
  Printf.printf "  Total time:       %.1f us\n\n" total_time;
  if failed > 0 then begin
    Printf.printf "FAILED cases:\n";
    List.iter (fun r ->
      if not r.pass then
        Printf.printf "  %s: expected %s, got %s\n"
          r.name r.expected r.actual
    ) results
  end

(* ================================================================== *)
(* CSV output                                                          *)
(* ================================================================== *)

let print_csv results =
  Printf.printf "name,category,expected,actual,pass,time_us\n";
  List.iter (fun r ->
    Printf.printf "%s,%s,%s,%s,%b,%.1f\n"
      r.name r.category r.expected r.actual r.pass r.time_us
  ) results

(* ================================================================== *)
(* JSON lines output                                                   *)
(* ================================================================== *)

let print_json results =
  List.iter (fun r ->
    Printf.printf
      {|{"name":"%s","category":"%s","pass":%b,"time_us":%.1f,"result":"%s"}|}
      r.name r.category r.pass r.time_us r.actual;
    Printf.printf "\n"
  ) results

(* ================================================================== *)
(* Paper-ready summary                                                 *)
(* ================================================================== *)

let print_summary results =
  let by_cat cat = List.filter (fun r -> r.category = cat) results in
  let pass_count rs = List.length (List.filter (fun r -> r.pass) rs) in
  let benign = by_cat "benign" in
  let attacks = by_cat "attack" in
  let scale = by_cat "scale" in
  let core = benign @ attacks in
  let core_times = List.map (fun r -> r.time_us) core in
  let core_avg = if core <> [] then
    List.fold_left ( +. ) 0.0 core_times /. float_of_int (List.length core)
    else 0.0 in
  let core_max = List.fold_left max 0.0 core_times in

  Printf.printf "# CertiClaw Evaluation Summary\n\n";

  Printf.printf "## Attack Classes Blocked\n\n";
  Printf.printf "| Attack class | Cases | Blocked | Error |\n";
  Printf.printf "|---|---|---|---|\n";
  let attack_classes = [
    ("Unauthorized write", "T1_unauthorized_write");
    ("Unauthorized host", "T1_unauthorized_host");
    ("Unauthorized MCP tool", "T1_unauthorized_mcp");
    ("Missing approval", "T1_no_approval");
    ("Forged cert (reorder)", "T1_forged_reorder");
    ("Forged cert (subset)", "T1_forged_subset");
    ("Default deny", "T1_default_deny");
    ("Path traversal", "T1_path_escape");
    ("Sibling prefix", "T2_sibling_prefix_reject");
    ("Write to read-only", "T2_write_to_read_only");
    ("Extra effect in cert", "T2_forged_extra_effect");
    ("Empty cert", "T2_forged_empty_effects");
    ("Wrong binary in cert", "T2_forged_wrong_binary");
    ("Wrong MCP server", "T2_mcp_wrong_server");
    ("Right server wrong tool", "T2_mcp_right_server_wrong_tool");
    ("Unauthorized binary", "T2_unauthorized_binary");
    ("Deny all MCP", "T2_deny_all_mcp");
  ] in
  List.iter (fun (cls, case_name) ->
    let case = List.find_opt (fun r -> r.name = case_name) results in
    match case with
    | Some r ->
      Printf.printf "| %s | 1 | %s | %s |\n"
        cls (if r.pass then "Yes" else "NO") r.actual
    | None ->
      Printf.printf "| %s | 0 | - | - |\n" cls
  ) attack_classes;

  Printf.printf "\n## Acceptance Summary\n\n";
  Printf.printf "| Category | Total | Correct |\n";
  Printf.printf "|---|---|---|\n";
  Printf.printf "| Benign (accepted) | %d | %d |\n"
    (List.length benign) (pass_count benign);
  Printf.printf "| Attack (blocked) | %d | %d |\n"
    (List.length attacks) (pass_count attacks);
  Printf.printf "| Scale | %d | %d |\n"
    (List.length scale) (pass_count scale);
  Printf.printf "| **Total** | **%d** | **%d** |\n"
    (List.length results)
    (List.length (List.filter (fun r -> r.pass) results));

  Printf.printf "\n## Timing\n\n";
  Printf.printf "| Metric | Value |\n";
  Printf.printf "|---|---|\n";
  Printf.printf "| Core cases avg | %.1f us |\n" core_avg;
  Printf.printf "| Core cases max | %.1f us |\n" core_max;
  Printf.printf "| Iterations/case | %d |\n" timing_iterations;

  Printf.printf "\n## Scalability (policy size)\n\n";
  Printf.printf "| Policy entries | Check time (us) | Pass |\n";
  Printf.printf "|---|---|---|\n";
  List.iter (fun r ->
    if r.category = "scale" then
      Printf.printf "| %s | %.1f | %b |\n" r.name r.time_us r.pass
  ) results;

  Printf.printf "\n"

(* ================================================================== *)
(* Main                                                                *)
(* ================================================================== *)

let () =
  let args = Array.to_list Sys.argv |> List.tl in
  let results = List.map run_case corpus in

  if List.mem "--csv" args then
    print_csv results
  else if List.mem "--json" args then
    print_json results
  else if List.mem "--summary" args then
    print_summary results
  else begin
    print_text_header ();
    List.iter print_text_row results;
    print_text_summary results
  end;

  if List.exists (fun r -> not r.pass) results then exit 1
