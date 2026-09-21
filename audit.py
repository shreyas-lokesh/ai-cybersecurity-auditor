"""
AI Cybersecurity Auditor (local LLM via Ollama) - version 3

This file holds the audit logic (evidence loading, rule checks, prompts, model calls)
and the interactive window. run_experiments.py imports the same logic for batch tests.

Run the window:      python audit.py
Run the experiments: python run_experiments.py
"""

import csv
import hashlib
import json
import queue
import re
import threading
import time
from datetime import date, datetime
from pathlib import Path

import requests

MODEL_NAME = "mistral"
OLLAMA = "http://localhost:11434"
BASE_DIR = Path(__file__).resolve().parent
MAX_FOLLOW_UPS = 2
TEMPERATURE = 0
NUM_CTX = 8192
NUM_PREDICT = 800
AUDIT_DATE = date.today()          # run_experiments.py fixes this per scenario

# ---------------------------------------------------------------------------
# Questions, evidence files and verdict criteria (from the Evidence Framework)
# Files marked optional may be absent without being reported as an error;
# the rule check decides what their absence means.
# ---------------------------------------------------------------------------
QUESTIONS = [
    {
        "text": "Do you enforce multi-factor authentication (MFA) for privileged accounts?",
        "files": {
            "Security policy": "security_policy.txt",
            "Entra ID Conditional Access config": "entra_id_config.json",
            "Privileged account roster": "privileged_accounts.csv",
            "Azure sign-in logs": "azure_signin_logs.json",
        },
        "optional": [],
        "criteria": "Pass = every privileged account is covered by an enforced policy AND every privileged "
                    "sign-in used an MFA method allowed by the written policy; "
                    "Fail = any privileged sign-in without MFA or with a method the policy does not allow, "
                    "or the policy is not enforced; "
                    "Flag = scope or enforcement cannot be confirmed, or the evidence is internally inconsistent.",
    },
    {
        "text": "Are backups performed and tested regularly?",
        "files": {"Backup schedule and job log": "backup_jobs.json"},
        "optional": [],
        "criteria": "Pass = a defined backup schedule AND recent successful restoration tests with intact data; "
                    "Fail = no backups, failed backups, or restoration tests that failed or were not done; "
                    "Flag = no schedule, unclear frequency, or internally inconsistent records.",
    },
    {
        "text": "Is sensitive data encrypted at rest?",
        "files": {"Storage encryption config": "encryption_config.json"},
        "optional": [],
        "criteria": "Pass = a named encryption standard applied to every sensitive data store listed; "
                    "Fail = any sensitive data store without encryption; "
                    "Flag = scope not shown, vague, or inconsistent configuration.",
    },
    {
        "text": "Do you maintain and test an incident response plan?",
        "files": {
            "Incident response plan register": "irp_register.csv",
            "Incident response plan document": "irp_document.txt",
            "Tabletop exercise report": "tabletop_report.txt",
        },
        "optional": ["Incident response plan document", "Tabletop exercise report"],
        "criteria": "Pass = a current, versioned plan AND a completed test within the last 12 months, "
                    "each supported by the document itself; "
                    "Fail = no plan exists; "
                    "Flag = plan or test claimed but not supported, out of date, or not completed.",
    },
    {
        "text": "Do employees receive regular security awareness training?",
        "files": {"Training completion records": "training_records.csv"},
        "optional": [],
        "criteria": "Pass = dated records showing all staff completed SECURITY awareness training in the last "
                    "12 months; Fail = no staff have completed it; "
                    "Flag = records missing, partial coverage, wrong course, or inconsistent records.",
    },
]

# ---------------------------------------------------------------------------
# Evidence loading (with integrity hashes)
# ---------------------------------------------------------------------------
def load_evidence(question, folder=BASE_DIR):
    """Return {label: {"file", "sha256", "text", "error", "optional"}}."""
    folder = Path(folder)
    evidence = {}
    for label, filename in question["files"].items():
        path = folder / filename
        item = {"file": filename, "sha256": None, "text": None, "error": None,
                "optional": label in question["optional"]}
        try:
            raw = path.read_bytes()
            item["sha256"] = hashlib.sha256(raw).hexdigest()
            item["text"] = raw.decode("utf-8-sig").replace("\r\n", "\n").strip()
        except FileNotFoundError:
            present = ", ".join(sorted(p.name for p in folder.iterdir() if p.is_file()))
            item["error"] = f"File not found: {filename}. Files in folder: {present}"
        except Exception as exc:
            item["error"] = f"Could not read {filename}: {exc}"
        evidence[label] = item
    return evidence


def parse_json(evidence, label):
    item = evidence.get(label, {})
    if not item.get("text"):
        return None
    try:
        return json.loads(item["text"])
    except json.JSONDecodeError as exc:
        item["error"] = f"Invalid JSON in {item['file']}: {exc}"
        return None


def parse_csv(evidence, label):
    item = evidence.get(label, {})
    if item.get("text") is None:
        return None
    return list(csv.DictReader(item["text"].splitlines()))


def to_date(value):
    try:
        return date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


def days_old(value):
    d = to_date(value)
    return None if d is None else (AUDIT_DATE - d).days


def missing_required(evidence):
    return [f"MISSING EVIDENCE: {i['error']}" for i in evidence.values()
            if i["error"] and not i["optional"]]


def decide(fail, flag):
    """Evidence of a violation -> Fail. Otherwise any doubt -> Flag. Otherwise Pass."""
    return "Fail" if fail else ("Flag" if flag else "Pass")


# ---------------------------------------------------------------------------
# Deterministic rule checks: each returns (verdict, [findings])
# Findings are prefixed: FAIL (violation), FLAG (doubt), TAMPER (inconsistent
# evidence, treated as doubt), NOTE (information only).
# ---------------------------------------------------------------------------
def check_mfa(ev):
    findings = missing_required(ev)
    config = parse_json(ev, "Entra ID Conditional Access config")
    logs = parse_json(ev, "Azure sign-in logs")
    roster = parse_csv(ev, "Privileged account roster")
    policy = ev["Security policy"]["text"] or ""
    if findings or config is None or logs is None or roster is None:
        return "Flag", findings

    fail = flag = False
    grant = config.get("grantControls", {})
    covered = set(config.get("conditions", {}).get("users", {}).get("includeRoles", []))
    enforced = config.get("state") == "enabled" and (
        "mfa" in grant.get("builtInControls", []) or "authenticationStrength" in grant)

    if config.get("state") != "enabled":
        findings.append(f"FAIL: MFA policy state is '{config.get('state')}', so it is not enforced.")
        fail = True
    if "TOTP" in policy and "authenticationStrength" not in grant:
        findings.append("FLAG: the policy allows only TOTP, but the config accepts any MFA method "
                        "(no authentication strength set).")
        flag = True

    roster_by_user = {r["username"].lower(): r for r in roster}
    for r in roster:
        if r["role"] not in covered:
            findings.append(f"FAIL: role '{r['role']}' ({r['username']}) is outside the MFA policy scope.")
            fail = True
        if r["mfa_enabled"].strip().lower() != "yes" and r["account_status"].lower() == "active":
            findings.append(f"FAIL: active privileged account {r['username']} has MFA disabled in the roster.")
            fail = True

    seen_ids, no_mfa = set(), {}
    for s in logs:
        user = s.get("userPrincipalName", "").lower()
        who = f"{s.get('displayName')} ({s.get('role')}) at {s.get('timestamp')}"
        ts = to_date(s.get("timestamp"))
        if s.get("id") in seen_ids:
            findings.append(f"TAMPER: duplicate sign-in id {s.get('id')}.")
            flag = True
        seen_ids.add(s.get("id"))
        if ts and ts > AUDIT_DATE:
            findings.append(f"TAMPER: sign-in by {who} is dated after the audit date.")
            flag = True
        if s.get("mfaSucceeded") and not s.get("mfaChallenged"):
            findings.append(f"TAMPER: sign-in by {who} records MFA success without an MFA challenge.")
            flag = True
        if user not in roster_by_user:
            findings.append(f"FLAG: {user} signed in with role '{s.get('role')}' but is not on the roster.")
            flag = True
        elif (roster_by_user[user]["account_status"].lower() != "active"
              and s.get("status") == "Success"):
            findings.append(f"TAMPER: {user} is '{roster_by_user[user]['account_status']}' in the roster "
                            f"but has a successful sign-in.")
            flag = True
        if s.get("status") == "Success" and not s.get("mfaSucceeded"):
            no_mfa.setdefault((s.get("displayName"), s.get("role"), s.get("authenticationMethod")),
                              []).append(s.get("timestamp", "")[:10])
            fail = True
    for (name, role, method), dates in no_mfa.items():
        findings.append(f"FAIL: {name} ({role}) signed in successfully without MFA ('{method}') "
                        f"{len(dates)} time(s): {', '.join(dates)}.")
        if enforced and role in covered:
            findings.append(f"NOTE: the config says MFA is enforced for '{role}', yet these sign-ins "
                            f"bypassed it (report-only mode, an exclusion, legacy authentication, "
                            f"or evidence that does not match the live system).")
    # Deliberate limitation: MFA *method* names are free text that varies by provider,
    # so these rules check whether MFA happened, not which method was used.

    m = re.search(r"Last Updated:\s*(.+)", policy)
    if m and logs:
        findings.append(f"NOTE: policy last updated '{m.group(1).strip()}'; logs cover "
                        f"{min(s['timestamp'] for s in logs)[:10]} to {max(s['timestamp'] for s in logs)[:10]}.")
    if len(logs) < 30:
        findings.append(f"NOTE: only {len(logs)} sign-in events supplied.")
    return decide(fail, flag), findings


def check_backups(ev):
    findings = missing_required(ev)
    data = parse_json(ev, "Backup schedule and job log")
    if findings or data is None:
        return "Flag", findings
    schedule = data.get("schedule") if isinstance(data, dict) else None
    jobs = data.get("jobs", []) if isinstance(data, dict) else data
    if not jobs:
        return "Fail", findings + ["FAIL: no backup jobs recorded."]

    fail = flag = False
    seen = set()
    for j in jobs:
        jid = j.get("job_id")
        if jid in seen:
            findings.append(f"TAMPER: duplicate job id {jid}.")
            flag = True
        seen.add(jid)
        if j.get("status") != "Success":
            findings.append(f"FAIL: job {jid} on {j.get('server')} status '{j.get('status')}'.")
            fail = True
        if not j.get("restoration_tested"):
            findings.append(f"FAIL: job {jid} on {j.get('server')} has no restoration test.")
            fail = True
            continue
        test, backup = to_date(j.get("test_date")), to_date(j.get("backup_date"))
        if test and test > AUDIT_DATE:
            findings.append(f"TAMPER: job {jid} restore test is dated after the audit date.")
            flag = True
        if test and backup and test < backup:
            findings.append(f"TAMPER: job {jid} restore test ({test}) predates the backup ({backup}).")
            flag = True
        age = days_old(j.get("test_date"))
        if age is None:
            findings.append(f"FLAG: job {jid} restore test has no valid date.")
            flag = True
        elif age > 365:
            findings.append(f"FAIL: job {jid} restore test is over 12 months old.")
            fail = True
    # Deliberate limitation: free-text notes on restore quality are not interpreted.

    if not schedule:
        findings.append(f"FLAG: {len(jobs)} job(s) supplied but no backup schedule, "
                        f"so 'regularly' cannot be confirmed.")
        flag = True
    else:
        findings.append(f"NOTE: schedule: backups {schedule.get('backup_frequency')}, "
                        f"restore tests {schedule.get('restore_test_frequency')}.")
    return decide(fail, flag), findings


def check_encryption(ev):
    findings = missing_required(ev)
    data = parse_json(ev, "Storage encryption config")
    if findings or data is None:
        return "Flag", findings
    if isinstance(data, dict) and "resources" in data:
        resources, inventory = data["resources"], data.get("data_store_inventory")
    else:
        resources, inventory = (data if isinstance(data, list) else [data]), None

    fail = flag = False
    configured = set()
    for res in resources:
        rid = res.get("resourceId")
        configured.add(rid)
        rules = res.get("serverSideEncryptionConfiguration", {}).get("rules", [])
        if not rules:
            findings.append(f"FAIL: {rid} has no encryption at rest configured.")
            fail = True
        for rule in rules:
            d = rule.get("applyServerSideEncryptionByDefault", {})
            algo, key = d.get("sseAlgorithm"), d.get("kmsMasterKeyId")
            if algo not in ("AES256", "aws:kms", "aws:kms:dsse"):
                findings.append(f"FAIL: {rid} uses unrecognised algorithm '{algo}'.")
                fail = True
            elif algo == "AES256" and key:
                findings.append(f"TAMPER: {rid} pairs 'AES256' with a KMS key ID, which AWS only accepts "
                                f"with 'aws:kms'. The export may have been edited; request a fresh one.")
                flag = True
            else:
                findings.append(f"NOTE: {rid} encrypted with {algo}.")

    if inventory is None:
        findings.append("FLAG: no data store inventory, so the scope of encryption cannot be confirmed.")
        flag = True
    else:
        for store in inventory:
            if store not in configured:
                findings.append(f"FLAG: inventoried data store {store} has no encryption evidence.")
                flag = True
    return decide(fail, flag), findings


def check_irp(ev):
    findings = missing_required(ev)
    rows = parse_csv(ev, "Incident response plan register")
    if findings or rows is None:
        return "Flag", findings
    if not rows:
        return "Fail", findings + ["FAIL: the register lists no incident response plan."]

    fail = flag = False
    doc = ev["Incident response plan document"]["text"]
    report = ev["Tabletop exercise report"]["text"]
    for r in rows:
        name, version = r.get("Document_Name"), r.get("Version")
        updated, tested = r.get("Last_Updated"), r.get("Last_Tabletop_Test_Date")
        findings.append(f"NOTE: register: {name} {version}, updated {updated}, tested {tested}, "
                        f"status '{r.get('Status')}' (vendor's own assertion).")
        for label, value in (("update", updated), ("test", tested)):
            d = to_date(value) if value else None
            if d is None:
                findings.append(f"FLAG: no valid {label} date in the register.")
                flag = True
            elif d > AUDIT_DATE:
                findings.append(f"TAMPER: {label} date {d} is after the audit date.")
                flag = True
            elif (AUDIT_DATE - d).days > 365:
                findings.append(f"FLAG: last {label} is over 12 months old.")
                flag = True

        if not doc:
            findings.append("FLAG: the plan document itself was not supplied.")
            flag = True
        else:
            m = re.search(r"Version:\s*(\S+)", doc)
            if not m or m.group(1) != version:
                findings.append(f"TAMPER: plan document version '{m.group(1) if m else 'missing'}' "
                                f"does not match register version '{version}'.")
                flag = True
        if not report:
            findings.append("FLAG: no tabletop exercise report was supplied.")
            flag = True
        else:
            m = re.search(r"Date conducted:\s*(\d{4}-\d{2}-\d{2})", report)
            if not m:
                findings.append("FLAG: the exercise report has no date conducted.")
                flag = True
            elif m.group(1) != tested:
                findings.append(f"TAMPER: report says the exercise was on {m.group(1)}, "
                                f"register says {tested}.")
                flag = True
    # Deliberate limitation: the report's free-text outcome is not interpreted.
    return decide(fail, flag), findings


def check_training(ev):
    findings = missing_required(ev)
    rows = parse_csv(ev, "Training completion records")
    if findings or rows is None:
        return "Flag", findings
    if not rows:
        return "Flag", findings + ["FLAG: the training file contains no staff records."]

    flag = False
    ids = [r.get("employee_id") for r in rows]
    if len(ids) != len(set(ids)):
        findings.append("TAMPER: duplicate employee IDs in the training records.")
        flag = True
    current = 0
    for r in rows:
        done = r.get("completed", "").strip().lower() in ("yes", "true")
        d = to_date(r.get("completion_date", ""))
        if done and d is None:
            findings.append(f"FLAG: {r.get('employee_id')} marked complete with no valid date.")
            flag = True
        elif done and d > AUDIT_DATE:
            findings.append(f"TAMPER: {r.get('employee_id')} completion date {d} is after the audit date.")
            flag = True
        elif done and (AUDIT_DATE - d).days <= 365:
            current += 1
    # Deliberate limitation: the course title is not interpreted.
    findings.append(f"NOTE: {current} of {len(rows)} staff completed training in the last 12 months.")
    if current == 0:
        return "Fail", findings + ["FAIL: no staff have completed training in the last 12 months."]
    if current < len(rows):
        findings.append("FLAG: training coverage is below 100%.")
        flag = True
    return decide(False, flag), findings


RULE_CHECKS = [check_mfa, check_backups, check_encryption, check_irp, check_training]

# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
VERDICT_RE = re.compile(r"final\s*verdict\W*(pass|fail|flag)", re.IGNORECASE)


def extract_verdict(text):
    matches = VERDICT_RE.findall(text or "")
    return matches[-1].capitalize() if matches else None


def build_prompt(q, evidence, rule_verdict=None, findings=None, show_rules=True):
    blocks = []
    for label, item in evidence.items():
        body = item["text"] if item["text"] is not None else "[NOT PROVIDED]"
        blocks.append(f"### {label} ({item['file']})\n{body}")
    rules_block = ""
    if show_rules:
        rules_block = ("\nAUTOMATED CHECKS (computed by code from the same files; confirm or challenge them):\n"
                       f"Rule-based verdict: {rule_verdict}\n"
                       + ("\n".join("- " + f for f in findings) or "- none") + "\n")
    system = f"""You are an ISO 27001 lead auditor assessing a third-party vendor.
Audit date: {AUDIT_DATE.isoformat()}.
Use ONLY the evidence below. Treat vendor statements and self-declared status fields as claims, not proof.
Read every field, including free-text notes, and cross-check the evidence sources against each other.
Report contradictions, impossible values, and anything that suggests the evidence was edited.

AUDIT QUESTION: {q['text']}
VERDICT CRITERIA: {q['criteria']}

EVIDENCE:
{chr(10).join(blocks)}
{rules_block}
Respond in exactly this format:
Reasoning: <how the evidence sources support or contradict each other>
Gaps Found: <specific accounts, systems, records or missing evidence, or 'None'>
Evidence Requested: <the documents or data you would ask the vendor for, described in plain words, or 'None'>
Final Verdict: <Pass, Fail or Flag>"""
    return [{"role": "system", "content": system},
            {"role": "user", "content": f"Audit this control: {q['text']}"}]


def chat(messages, temperature=None):
    """Return (reply_text, seconds_taken, token_counts)."""
    start = time.time()
    tokens = {"prompt": None, "reply": None}
    try:
        r = requests.post(f"{OLLAMA}/api/chat", timeout=900, json={
            "model": MODEL_NAME,
            "messages": messages,
            "stream": False,
            "options": {"temperature": TEMPERATURE if temperature is None else temperature,
                        "num_predict": NUM_PREDICT, "num_ctx": NUM_CTX},
        })
        r.raise_for_status()
        data = r.json()
        text = data.get("message", {}).get("content") or f"ERROR: unexpected reply {data}"
        tokens = {"prompt": data.get("prompt_eval_count"), "reply": data.get("eval_count")}
    except requests.exceptions.ConnectionError:
        text = "ERROR: cannot reach Ollama. Is it running? (try: ollama serve)"
    except Exception as exc:
        text = f"ERROR: {exc}"
    if tokens["prompt"] and tokens["prompt"] + NUM_PREDICT > NUM_CTX:
        text = ("WARNING: prompt + reply may exceed the context window; evidence could have been cut off.\n"
                + text)
    return text, round(time.time() - start, 1), tokens


def model_info():
    """Name and digest of the local model, for the log."""
    try:
        for m in requests.get(f"{OLLAMA}/api/tags", timeout=10).json().get("models", []):
            if m.get("name", "").split(":")[0] == MODEL_NAME.split(":")[0]:
                return {"name": m.get("name"), "digest": m.get("digest"),
                        "parameter_size": m.get("details", {}).get("parameter_size"),
                        "quantization": m.get("details", {}).get("quantization_level")}
    except Exception as exc:
        return {"name": MODEL_NAME, "error": str(exc)}
    return {"name": MODEL_NAME, "error": "model not found in ollama list"}


# ---------------------------------------------------------------------------
# Interactive window
# ---------------------------------------------------------------------------
def main():
    import tkinter as tk
    from tkinter import scrolledtext

    state = {"index": 0, "messages": [], "follow_ups": 0, "busy": False, "log": None}
    results = queue.Queue()
    log_path = BASE_DIR / f"audit_log_{datetime.now():%Y%m%d_%H%M%S}.json"

    root = tk.Tk()
    root.title("AI Cybersecurity Auditor")
    root.geometry("950x750")
    question_label = tk.Label(root, text="Click Start Audit", wraplength=900,
                              font=("Arial", 12, "bold"), justify="left")
    question_label.pack(pady=10)
    chat_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
    chat_box.pack(pady=5, padx=10, fill="both", expand=True)
    entry = tk.Entry(root, width=110)
    entry.pack(pady=5)
    status = tk.Label(root, text="", fg="blue", font=("Arial", 10, "italic"))
    status.pack()
    buttons = tk.Frame(root)
    buttons.pack(pady=5)

    def write(text):
        chat_box.insert(tk.END, text)
        chat_box.yview(tk.END)

    def save_log():
        log_path.write_text(json.dumps(state["log"], indent=2), encoding="utf-8")

    def ask_model():
        state["busy"] = True
        status.config(text="⏳ Model is analysing the evidence (this can take a minute)...")
        msgs = list(state["messages"])
        threading.Thread(target=lambda: results.put(chat(msgs)), daemon=True).start()
        root.after(200, poll)

    def poll():
        try:
            reply, seconds, tokens = results.get_nowait()
        except queue.Empty:
            root.after(200, poll)
            return
        state["busy"] = False
        status.config(text="")
        handle_reply(reply, seconds, tokens)

    def start_audit():
        if state["busy"]:
            return
        state["index"] = 0
        state["log"] = {"started": datetime.now().isoformat(timespec="seconds"),
                        "audit_date": AUDIT_DATE.isoformat(), "evidence_folder": str(BASE_DIR),
                        "model": model_info(), "temperature": TEMPERATURE, "questions": []}
        chat_box.delete("1.0", tk.END)
        write(f"Evidence folder: {BASE_DIR}\nModel: {state['log']['model']}\nLog file: {log_path.name}\n")
        run_question()

    def run_question():
        i = state["index"]
        if i >= len(QUESTIONS):
            question_label.config(text="Audit completed")
            write("\n=== AUDIT COMPLETE ===\n")
            for rec in state["log"]["questions"]:
                write(f"Q{rec['question_no']}: rules={rec['rule_verdict']}  llm={rec['llm_verdict']}  "
                      f"agree={rec['rule_verdict'] == rec['llm_verdict']}\n")
            state["log"]["finished"] = datetime.now().isoformat(timespec="seconds")
            save_log()
            return
        q = QUESTIONS[i]
        state["follow_ups"] = 0
        question_label.config(text=f"Question {i + 1}: {q['text']}")
        write(f"\n\n--- Question {i + 1} ---\n{q['text']}\n\nEvidence loaded:\n")

        evidence = load_evidence(q)
        for label, item in evidence.items():
            if item["error"]:
                mark = "–" if item["optional"] else "✗"
                write(f"  {mark} {label}: not provided ({item['file']})\n")
            else:
                write(f"  ✓ {label} ({item['file']})  sha256={item['sha256'][:16]}…\n")

        rule_verdict, findings = RULE_CHECKS[i](evidence)
        write(f"\nAutomated checks → {rule_verdict}\n" + "".join(f"  • {f}\n" for f in findings))
        state["messages"] = build_prompt(q, evidence, rule_verdict, findings)
        state["log"]["questions"].append({
            "question_no": i + 1, "question": q["text"],
            "evidence": {k: {"file": v["file"], "sha256": v["sha256"], "error": v["error"]}
                         for k, v in evidence.items()},
            "rule_verdict": rule_verdict, "rule_findings": findings,
            "prompt": state["messages"][0]["content"],
            "llm_replies": [], "llm_seconds": [], "llm_tokens": [], "llm_verdict": None, "follow_up_evidence": [],
        })
        ask_model()

    def handle_reply(reply, seconds, tokens):
        rec = state["log"]["questions"][-1]
        rec["llm_replies"].append(reply)
        rec["llm_seconds"].append(seconds)
        rec["llm_tokens"].append(tokens)
        verdict = extract_verdict(reply)
        rec["llm_verdict"] = verdict
        state["messages"].append({"role": "assistant", "content": reply})
        write(f"\nLLM Auditor ({seconds}s):\n{reply}\n\n→ Parsed verdict: {verdict or 'NOT FOUND'}\n")
        save_log()
        if verdict in ("Pass", "Fail"):
            next_question()
        elif state["follow_ups"] < MAX_FOLLOW_UPS:
            write("Submit more evidence below, or click 'Next question'.\n")
        else:
            write("Follow-up limit reached. Moving on.\n")
            next_question()

    def submit_evidence():
        text = entry.get().strip()
        if not text or state["busy"] or not state["log"] or not state["log"]["questions"]:
            return
        entry.delete(0, tk.END)
        state["follow_ups"] += 1
        state["log"]["questions"][-1]["follow_up_evidence"].append(text)
        write(f"\nYou (additional evidence):\n{text}\n")
        state["messages"].append({"role": "user", "content":
            f"Additional evidence from the vendor (an unverified claim unless it includes data):\n{text}\n"
            f"Re-assess and answer in the same format."})
        ask_model()

    def next_question():
        if state["busy"] or not state["log"] or state["index"] >= len(QUESTIONS):
            return
        state["index"] += 1
        run_question()

    tk.Button(buttons, text="Start Audit", command=start_audit).pack(side="left", padx=5)
    tk.Button(buttons, text="Submit Evidence", command=submit_evidence).pack(side="left", padx=5)
    tk.Button(buttons, text="Next question", command=next_question).pack(side="left", padx=5)
    root.mainloop()


if __name__ == "__main__":
    main()
