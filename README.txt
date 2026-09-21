AI CYBERSECURITY AUDITOR - VERSION 3
====================================

FILES
  audit.py              audit logic + interactive window (uses the evidence files in this folder)
  run_experiments.py    batch experiments across all scenarios
  make_scenarios.py     rebuilds the scenarios folder (already built; only rerun if you change it)
  scenarios/            5 test sets, each with expected.json (the correct verdicts and why)
  *.json *.csv *.txt    the original Contoso evidence used by the window
  results/              created by run_experiments.py

1. QUICK CHECK (no model, a few seconds)
   python run_experiments.py --dry-run
   Every line should end in "ok" except the 4_rules_blind_spot questions, which the rules
   are expected to get wrong.

2. FULL EXPERIMENT (150 model calls; roughly 30-90 minutes on an RTX 3070 Ti)
   python run_experiments.py
   Leave it running. Results appear in results/run_<date_time>/
     summary.txt               the numbers for the results chapter
     results.csv               every decision (open in Excel)
     run_log.json              prompts, replies, evidence hashes, model details
     accuracy_by_scenario.png  chart (only if matplotlib is installed: pip install matplotlib)

   Faster test first:  python run_experiments.py --repeats 1 --scenarios 3_tampered

3. INTERACTIVE DEMO (for screenshots and the viva)
   python audit.py

THE THREE AUDITORS COMPARED
  rules      deterministic code checks only
  llm_blind  the model sees only the evidence
  llm_hints  the model sees the evidence plus the code's findings and verdict

THE FIVE SCENARIOS (audit date fixed at 2026-09-16)
  1_compliant         everything meets the policy                       all Pass
  2_non_compliant     clear, consistent violations                      all Fail
  3_tampered          files look fine but contain impossible values     all Flag
  4_rules_blind_spot  problems in free text / MFA method names          Fail, Fail, Pass, Flag, Flag
  5_original_demo     the original Contoso evidence                     Fail, Flag, Flag, Flag, Flag

REVIEW THE EXPECTED VERDICTS
  The expected verdicts in each expected.json are the ground truth. Read them and the
  "reason" lines, and change any you disagree with before running the experiment.

LIMITATIONS TO REPORT
  - Scenarios and rules were designed together, so the rules' score on scenarios 1-3 and 5
    is not independent evidence. Scenario 4 was built to contain what the rules ignore.
  - Rules deliberately do not interpret free text (backup notes, exercise outcome, course
    title) or MFA method names.
  - All evidence is synthetic; the tool reads exported files rather than connecting to live
    systems, so hashes prove files were unchanged after collection, not that they are genuine.
  - 25 cases is a small sample.
