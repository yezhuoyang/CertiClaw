(** CertiClaw Evaluation Harness

    Runs the full evaluation corpus, reports pass/fail for each case,
    measures checking time, and produces summary output in both
    human-readable and CSV formats.

    Usage:
      dune exec eval/run_eval.exe
      dune exec eval/run_eval.exe -- --csv
      dune exec eval/run_eval.exe -- --json *)

open Certiclaw.Types
open Certiclaw.Eval_corpus

(* ================================================================== *)
(* Timing                                                              *)
(* ================================================================== *)

(** Number of iterations for timing measurement.
    We run many iterations because a single check is sub-microsecond. *)
let timing_iterations = 10_000

(** Time a thunk by running it [timing_iterations] times and
    reporting the average in microseconds. *)
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
(* Output formats                                                      *)
(* ================================================================== *)

let print_text_header () =
  Printf.printf "\n";
  Printf.printf "=== CertiClaw Evaluation Harness ===\n";
  Printf.printf "\n";
  Printf.printf "%-35s %-8s %-6s %10s  %s\n"
    "Case" "Category" "Pass" "Time(us)" "Result";
  Printf.printf "%s\n" (String.make 90 '-')

let print_text_row (r : case_result) =
  Printf.printf "%-35s %-8s %-6s %10.1f  %s\n"
    r.name
    r.category
    (if r.pass then "PASS" else "FAIL")
    r.time_us
    r.actual

let print_text_summary results =
  let total = List.length results in
  let passed = List.length (List.filter (fun r -> r.pass) results) in
  let failed = total - passed in
  let benign = List.filter (fun r -> r.category = "benign") results in
  let attacks = List.filter (fun r -> r.category = "attack") results in
  let benign_pass = List.length (List.filter (fun r -> r.pass) benign) in
  let attack_pass = List.length (List.filter (fun r -> r.pass) attacks) in
  let times = List.map (fun r -> r.time_us) results in
  let total_time = List.fold_left ( +. ) 0.0 times in
  let avg_time = if total > 0 then total_time /. float_of_int total else 0.0 in
  let max_time = List.fold_left max 0.0 times in
  Printf.printf "%s\n" (String.make 90 '-');
  Printf.printf "\n";
  Printf.printf "Summary:\n";
  Printf.printf "  Total cases:      %d\n" total;
  Printf.printf "  Passed:           %d\n" passed;
  Printf.printf "  Failed:           %d\n" failed;
  Printf.printf "  Benign accepted:  %d / %d\n" benign_pass (List.length benign);
  Printf.printf "  Attacks blocked:  %d / %d\n" attack_pass (List.length attacks);
  Printf.printf "  Avg check time:   %.1f us\n" avg_time;
  Printf.printf "  Max check time:   %.1f us\n" max_time;
  Printf.printf "  Total time:       %.1f us\n" total_time;
  Printf.printf "\n";
  if failed > 0 then begin
    Printf.printf "FAILED cases:\n";
    List.iter (fun r ->
      if not r.pass then
        Printf.printf "  %s: expected %s, got %s\n"
          r.name r.expected r.actual
    ) results
  end

let print_csv_header () =
  Printf.printf "name,category,expected,actual,pass,time_us\n"

let print_csv_row (r : case_result) =
  Printf.printf "%s,%s,%s,%s,%b,%.1f\n"
    r.name r.category r.expected r.actual r.pass r.time_us

let print_json_record (r : case_result) =
  Printf.printf
    {|{"name":"%s","category":"%s","expected":"%s","actual":"%s","pass":%b,"time_us":%.1f}|}
    r.name r.category r.expected r.actual r.pass r.time_us;
  Printf.printf "\n"

(* ================================================================== *)
(* Main                                                                *)
(* ================================================================== *)

let () =
  let args = Array.to_list Sys.argv |> List.tl in
  let csv_mode = List.mem "--csv" args in
  let json_mode = List.mem "--json" args in

  (* Run all cases *)
  let results = List.map run_case corpus in

  (* Output *)
  if csv_mode then begin
    print_csv_header ();
    List.iter print_csv_row results
  end else if json_mode then
    List.iter print_json_record results
  else begin
    print_text_header ();
    List.iter print_text_row results;
    print_text_summary results
  end;

  (* Exit code *)
  let failed = List.exists (fun r -> not r.pass) results in
  if failed then exit 1
