"""
Batch experiments for the AI auditor.

For every scenario in ./scenarios and every audit question, three auditors are compared
against the expected verdict in that scenario's expected.json:

  rules       the deterministic rule checks only
  llm_blind   the model sees the evidence only
  llm_hints   the model sees the evidence AND the rule checks' findings and verdict

Each model condition is repeated (default 3 times) to measure consistency.

Examples
  python run_experiments.py                     full run (5 scenarios x 5 questions x 2 x 3 = 150 model calls)
  python run_experiments.py --dry-run           rule checks only, no model (quick setup test)
  python run_experiments.py --repeats 1         faster
  python run_experiments.py --temperature 0.7   test how stable verdicts are with sampling
  python run_experiments.py --scenarios 3_tampered 4_rules_blind_spot

Output goes to results/run_<date_time>/:
  results.csv   one row per auditor decision (open in Excel)
  run_log.json  settings, model details, evidence hashes, full prompts and replies
  summary.txt   accuracy, confusion matrices, consistency and the effect of the hints
"""

import argparse
import csv
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path

import audit

LABELS = ["Pass", "Fail", "Flag"]
CONDITIONS = ["rules", "llm_blind", "llm_hints"]


def load_scenarios(names):
    root = audit.BASE_DIR / "scenarios"
    if not root.exists():
        sys.exit("No scenarios folder found. Run:  python make_scenarios.py")
    folders = sorted(p for p in root.iterdir() if (p / "expected.json").exists())
    if names:
        folders = [p for p in folders if p.name in names]
    return [(p, json.loads((p / "expected.json").read_text(encoding="utf-8"))) for p in folders]


def majority(verdicts):
    counts = Counter(verdicts)
    top, n = counts.most_common(1)[0]
    return top if list(counts.values()).count(n) == 1 else "Tie"


def confusion(rows):
    m = defaultdict(Counter)
    for r in rows:
        m[r["expected"]][r["verdict"] or "None"] += 1
    cols = LABELS + ["None"]
    lines = ["expected \\ got  " + "".join(f"{c:>7}" for c in cols)]
    for e in LABELS:
        lines.append(f"{e:<16}" + "".join(f"{m[e][c]:>7}" for c in cols))
    return "\n".join(lines)


def pct(a, b):
    return f"{a}/{b} ({100 * a / b:.0f}%)" if b else "n/a"


def summarise(rows, settings):
    out = [f"AI auditor experiment summary  ({settings['started']})",
           f"Model: {settings['model']}", f"Temperature: {settings['temperature']}   "
           f"Repeats: {settings['repeats']}   Scenarios: {', '.join(settings['scenarios'])}", ""]
    conds = [c for c in CONDITIONS if any(r["condition"] == c for r in rows)]

    out.append("1. ACCURACY (all decisions)")
    for c in conds:
        rs = [r for r in rows if r["condition"] == c]
        out.append(f"   {c:<10} {pct(sum(r['correct'] for r in rs), len(rs))}")
    out.append("")

    out.append("2. ACCURACY BY SCENARIO")
    scen = sorted({r["scenario"] for r in rows})
    out.append("   " + f"{'scenario':<22}" + "".join(f"{c:>14}" for c in conds))
    for s in scen:
        cells = []
        for c in conds:
            rs = [r for r in rows if r["condition"] == c and r["scenario"] == s]
            cells.append(f"{sum(r['correct'] for r in rs)}/{len(rs)}")
        out.append("   " + f"{s:<22}" + "".join(f"{x:>14}" for x in cells))
    out.append("")

    out.append("3. CONFUSION MATRICES (rows = expected, columns = auditor's verdict)")
    for c in conds:
        out.append(f"   [{c}]")
        out.extend("   " + line for line in confusion([r for r in rows if r["condition"] == c]).splitlines())
    out.append("")

    cases = defaultdict(lambda: defaultdict(list))
    for r in rows:
        cases[(r["scenario"], r["question_no"])][r["condition"]].append(r["verdict"] or "None")
    expected = {(r["scenario"], r["question_no"]): r["expected"] for r in rows}
    llm_conds = [c for c in conds if c != "rules"]

    if llm_conds and settings["repeats"] > 1:
        out.append("4. CONSISTENCY (cases where every repeat gave the same verdict)")
        for c in llm_conds:
            same = sum(len(set(v[c])) == 1 for v in cases.values())
            out.append(f"   {c:<10} {pct(same, len(cases))}")
        out.append("")

    if {"llm_blind", "llm_hints"} <= set(conds):
        out.append("5. EFFECT OF SHOWING THE RULE FINDINGS (majority verdict per case)")
        helped, hurt, both_ok, both_wrong = [], [], 0, 0
        agree_blind = agree_hints = 0
        for key, v in sorted(cases.items()):
            b, h, rule = majority(v["llm_blind"]), majority(v["llm_hints"]), v["rules"][0]
            ok_b, ok_h = b == expected[key], h == expected[key]
            agree_blind += b == rule
            agree_hints += h == rule
            if ok_h and not ok_b:
                helped.append(f"{key[0]} Q{key[1]}: blind={b}, hints={h}, expected={expected[key]}")
            elif ok_b and not ok_h:
                hurt.append(f"{key[0]} Q{key[1]}: blind={b}, hints={h}, expected={expected[key]}")
            elif ok_b:
                both_ok += 1
            else:
                both_wrong += 1
        out.append(f"   Hints fixed a wrong verdict:  {len(helped)}")
        out.extend("     - " + x for x in helped)
        out.append(f"   Hints caused a wrong verdict: {len(hurt)}")
        out.extend("     - " + x for x in hurt)
        out.append(f"   Correct either way: {both_ok}    Wrong either way: {both_wrong}")
        out.append(f"   Agreement with the rules: blind {pct(agree_blind, len(cases))}, "
                   f"with hints {pct(agree_hints, len(cases))}")
        out.append("   (A large rise in agreement suggests the model defers to the rules.)")
        out.append("")

    out.append("6. CASE-BY-CASE (majority verdicts)")
    out.append("   " + f"{'case':<28}{'expected':>9}" + "".join(f"{c:>11}" for c in conds))
    for key, v in sorted(cases.items()):
        cells = [majority(v[c]) for c in conds]
        out.append("   " + f"{key[0] + ' Q' + str(key[1]):<28}{expected[key]:>9}"
                   + "".join(f"{x:>11}" for x in cells))
    none = sum(1 for r in rows if r["condition"] != "rules" and r["verdict"] is None)
    out += ["", f"Model replies with no readable verdict: {none}",
            "", "Note: the rule checks and the scenarios were designed together, so the rules' score on",
            "scenarios 1-3 and 5 is not independent evidence of their quality. Scenario 4 contains",
            "problems the rules deliberately do not interpret."]
    return "\n".join(out)


def save_chart(rows, folder):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return None
    scen = sorted({r["scenario"] for r in rows})
    conds = [c for c in CONDITIONS if any(r["condition"] == c for r in rows)]
    width = 0.8 / len(conds)
    fig, ax = plt.subplots(figsize=(10, 5))
    for i, c in enumerate(conds):
        vals = []
        for s in scen:
            rs = [r for r in rows if r["condition"] == c and r["scenario"] == s]
            vals.append(100 * sum(r["correct"] for r in rs) / len(rs) if rs else 0)
        ax.bar([x + i * width for x in range(len(scen))], vals, width, label=c)
    ax.set_xticks([x + width * (len(conds) - 1) / 2 for x in range(len(scen))])
    ax.set_xticklabels(scen, rotation=15)
    ax.set_ylabel("Correct verdicts (%)")
    ax.set_ylim(0, 105)
    ax.set_title("Auditor accuracy by scenario")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), ncol=len(conds), frameon=False)
    fig.tight_layout()
    path = folder / "accuracy_by_scenario.png"
    fig.savefig(path, dpi=150)
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--temperature", type=float, default=0)
    ap.add_argument("--scenarios", nargs="*")
    ap.add_argument("--dry-run", action="store_true", help="rule checks only, no model calls")
    args = ap.parse_args()

    scenarios = load_scenarios(args.scenarios)
    if not scenarios:
        sys.exit("No matching scenarios.")
    folder = audit.BASE_DIR / "results" / f"run_{datetime.now():%Y%m%d_%H%M%S}"
    folder.mkdir(parents=True)

    conditions = ["rules"] if args.dry_run else CONDITIONS
    settings = {"started": datetime.now().isoformat(timespec="seconds"),
                "model": "none (dry run)" if args.dry_run else audit.model_info(),
                "num_ctx": audit.NUM_CTX,
                "temperature": args.temperature, "repeats": 0 if args.dry_run else args.repeats,
                "scenarios": [p.name for p, _ in scenarios], "conditions": conditions}
    if not args.dry_run and "error" in settings["model"]:
        sys.exit(f"Model problem: {settings['model']['error']}. Is Ollama running and is '{audit.MODEL_NAME}' pulled?")

    total_calls = 0 if args.dry_run else len(scenarios) * len(audit.QUESTIONS) * 2 * args.repeats
    print(f"Writing to {folder}\nModel calls planned: {total_calls}\n")

    rows, log = [], {"settings": settings, "cases": []}
    csv_path = folder / "results.csv"
    fields = ["scenario", "question_no", "condition", "repeat", "expected", "verdict", "correct",
              "seconds", "prompt_tokens", "rule_verdict"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        calls, t0 = 0, time.time()

        for path, meta in scenarios:
            audit.AUDIT_DATE = date.fromisoformat(meta["audit_date"])
            for qi, q in enumerate(audit.QUESTIONS):
                qno = str(qi + 1)
                expected = meta["expected"][qno]
                evidence = audit.load_evidence(q, path)
                rule_verdict, findings = audit.RULE_CHECKS[qi](evidence)
                case = {"scenario": path.name, "question_no": qi + 1, "expected": expected,
                        "reason": meta.get("reason", {}).get(qno),
                        "evidence": {k: {"file": v["file"], "sha256": v["sha256"]} for k, v in evidence.items()},
                        "rule_verdict": rule_verdict, "rule_findings": findings, "runs": []}

                def record(condition, repeat, verdict, seconds, tokens=None):
                    row = {"scenario": path.name, "question_no": qi + 1, "condition": condition,
                           "repeat": repeat, "expected": expected, "verdict": verdict,
                           "correct": verdict == expected, "seconds": seconds,
                           "prompt_tokens": (tokens or {}).get("prompt"), "rule_verdict": rule_verdict}
                    rows.append(row)
                    writer.writerow(row)
                    fh.flush()

                record("rules", 0, rule_verdict, 0)
                for condition in conditions[1:]:
                    prompt = audit.build_prompt(q, evidence, rule_verdict, findings,
                                                show_rules=(condition == "llm_hints"))
                    case.setdefault("prompts", {})[condition] = prompt[0]["content"]
                    for rep in range(1, args.repeats + 1):
                        reply, secs, tokens = audit.chat(prompt, temperature=args.temperature)
                        if reply.startswith("ERROR: cannot reach Ollama"):
                            sys.exit(reply)
                        verdict = audit.extract_verdict(reply)
                        record(condition, rep, verdict, secs, tokens)
                        case["runs"].append({"condition": condition, "repeat": rep, "verdict": verdict,
                                             "seconds": secs, "tokens": tokens, "reply": reply})
                        calls += 1
                        eta = (time.time() - t0) / calls * (total_calls - calls)
                        print(f"[{calls}/{total_calls}] {path.name} Q{qi + 1} {condition} #{rep}: "
                              f"{verdict} (expected {expected}, {secs}s)  ~{eta / 60:.0f} min left")
                if args.dry_run:
                    mark = "ok" if rule_verdict == expected else "MISMATCH"
                    print(f"{path.name} Q{qi + 1}: rules={rule_verdict} expected={expected}  {mark}")
                log["cases"].append(case)
                (folder / "run_log.json").write_text(json.dumps(log, indent=2), encoding="utf-8")

    settings["finished"] = datetime.now().isoformat(timespec="seconds")
    (folder / "run_log.json").write_text(json.dumps(log, indent=2), encoding="utf-8")
    summary = summarise(rows, settings)
    (folder / "summary.txt").write_text(summary, encoding="utf-8")
    chart = save_chart(rows, folder)
    print("\n" + summary)
    print(f"\nSaved: {csv_path.name}, run_log.json, summary.txt" + (f", {chart.name}" if chart else ""))


if __name__ == "__main__":
    main()
