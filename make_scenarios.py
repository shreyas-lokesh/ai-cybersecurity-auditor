"""
Builds the synthetic test scenarios in ./scenarios, each with expected.json
(the human ground-truth verdict and the reason for it, per question).

Scenarios
  1_compliant         everything genuinely meets the policy           -> all Pass
  2_non_compliant     clear, consistent violations                    -> all Fail
  3_tampered          each file looks fine, but the evidence contains
                      impossible or contradictory values              -> all Flag
  4_rules_blind_spot  problems hidden in free text or method names
                      that the rule checks do not interpret           -> mixed
  5_original_demo     the original Contoso evidence                   -> mixed

Run:  python make_scenarios.py   (overwrites ./scenarios)
"""

import csv
import io
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT = BASE / "scenarios"
AUDIT_DATE = "2026-09-16"

USERS = [
    ("admin@contoso.com", "Alice Johnson", "Global Administrator"),
    ("j.smith@contoso.com", "John Smith", "Server Administrator"),
    ("m.patel@contoso.com", "Maya Patel", "Database Administrator"),
    ("r.chen@contoso.com", "Robert Chen", "Network Administrator"),
    ("s.williams@contoso.com", "Sarah Williams", "Security Administrator"),
]
ROLES = [u[2] for u in USERS]
TOTP = "Password + TOTP (Microsoft Authenticator)"

POLICY = """COMPANY INFORMATION SECURITY POLICY
Reference: ISO 27001 Annex A 5.17 (Authentication Information)
Version: 3.0
Last Updated: {updated}

1. OVERVIEW
This policy sets the access control and authentication requirements for all internal infrastructure and cloud environments.

2. PRIVILEGED ACCESS RULES
2.1. Multi-Factor Authentication (MFA) is REQUIRED for all users holding administrative or privileged roles (Global Administrator, Server Administrator, Database Administrator, Network Administrator, Security Administrator).
2.2. The only approved MFA method is a Time-Based One-Time Password (TOTP) app (e.g. Microsoft Authenticator). SMS and voice call are NOT approved.
2.3. Password-only authentication is prohibited for any account with privileged access rights.
"""

IRP_DOC = """INCIDENT RESPONSE PLAN
Document: Incident_Response_Plan_Master
Version: {version}
Approved by: Chief Information Security Officer
Approval date: 2025-11-10

Scope: all production systems and customer data.
Roles: Incident Manager, Technical Lead, Communications Lead, Legal.
Phases: Preparation, Detection and Analysis, Containment, Eradication, Recovery, Lessons Learned.
Escalation: severity 1 incidents escalated to the CISO within 1 hour.
Customer notification: within 72 hours of confirming a personal data breach.
"""

TABLETOP = """TABLETOP EXERCISE REPORT
Plan tested: Incident_Response_Plan_Master v4.2
Scenario: ransomware on the customer database cluster
Date conducted: {date}
Participants: 11 (IT, Security, Legal, Communications)
Outcome: {outcome}
Actions: {actions}
"""


def config(state="enabled", roles=ROLES, strength=True):
    grant = {"operator": "AND"}
    if strength:
        grant["authenticationStrength"] = {"displayName": "TOTP only",
                                           "allowedCombinations": ["password,softwareOath"]}
    else:
        grant = {"operator": "OR", "builtInControls": ["mfa"]}
    return {"tenantId": "contoso.onmicrosoft.com", "policyName": "Require_MFA_Privileged_Roles",
            "state": state, "conditions": {"users": {"includeRoles": list(roles)},
                                           "clientAppTypes": ["all"]},
            "grantControls": grant}


def roster(overrides=None):
    overrides = overrides or {}
    rows = []
    for upn, name, role in USERS:
        row = {"username": upn, "display_name": name, "role": role, "mfa_enabled": "Yes",
               "mfa_method": "Microsoft Authenticator (TOTP)", "account_status": "Active"}
        row.update(overrides.get(upn, {}))
        rows.append(row)
    return rows


def signins(method_for=None, n=30):
    """n sign-ins spread from March to August 2026, cycling through the admins."""
    method_for = method_for or {}
    start = datetime(2026, 3, 2, 8, 0, 0)
    events = []
    for i in range(n):
        upn, name, role = USERS[i % len(USERS)]
        method = method_for.get(upn, TOTP)
        mfa = method != "Password Only"
        events.append({
            "id": f"signin_{i + 1:03d}",
            "timestamp": (start + timedelta(days=i * 6, minutes=i * 37)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "userPrincipalName": upn, "displayName": name, "role": role,
            "ipAddress": f"51.140.{20 + i % 5}.{10 + i}",
            "authenticationMethod": method,
            "mfaChallenged": mfa, "mfaSucceeded": mfa, "status": "Success",
            "location": "London, UK"})
    return events


def backups(jobs, schedule=True):
    data = {"jobs": jobs}
    if schedule:
        data = {"schedule": {"backup_frequency": "daily incremental, weekly full",
                             "restore_test_frequency": "quarterly",
                             "servers": ["DB-Prod-01", "DB-Prod-02", "App-Prod-01"]}, "jobs": jobs}
    return data


def job(jid, server, backup_date, test_date, status="Success", tested=True, **extra):
    j = {"job_id": jid, "server": server, "status": status, "backup_type": "Full",
         "backup_date": backup_date, "restoration_tested": tested,
         "test_date": test_date if tested else None, "test_result": "Completed" if tested else None}
    j.update(extra)
    return j


GOOD_JOBS = [job("BKP-1001", "DB-Prod-01", "2026-08-30", "2026-09-01"),
             job("BKP-1002", "DB-Prod-02", "2026-08-30", "2026-09-02"),
             job("BKP-1003", "App-Prod-01", "2026-08-30", "2026-09-03")]


def bucket(name, algo="aws:kms", key=True, encrypted=True):
    res = {"resourceId": f"arn:aws:s3:::{name}", "status": "Active", "publicAccessBlock": True,
           "serverSideEncryptionConfiguration": {"rules": []}}
    if encrypted:
        d = {"sseAlgorithm": algo}
        if key:
            d["kmsMasterKeyId"] = "arn:aws:kms:eu-west-2:111122223333:key/1234-abcd"
        res["serverSideEncryptionConfiguration"]["rules"].append({"applyServerSideEncryptionByDefault": d})
    return res


STORES = ["customer-financial-data", "customer-pii", "backup-archive"]


def encryption(resources):
    return {"data_store_inventory": [f"arn:aws:s3:::{s}" for s in STORES], "resources": resources}


def register(rows):
    return [{"Document_Name": "Incident_Response_Plan_Master", "Version": v, "Last_Updated": u,
             "Last_Tabletop_Test_Date": t, "Status": "Compliant"} for v, u, t in rows]


def training(rows):
    return [{"employee_id": f"E{i + 1:03d}", "name": n, "department": d, "course": c,
             "completed": done, "completion_date": dt} for i, (n, d, c, done, dt) in enumerate(rows)]


STAFF = [("Alice Johnson", "IT"), ("John Smith", "IT"), ("Maya Patel", "IT"), ("Robert Chen", "IT"),
         ("Sarah Williams", "Security"), ("Tom Evans", "Finance"), ("Priya Shah", "Finance"),
         ("Liam Brown", "Sales"), ("Emma Wilson", "Sales"), ("Omar Ali", "HR")]
SEC_COURSE = "Security Awareness and Phishing 2026"


def write_csv(path, rows, header=None):
    header = header or list(rows[0].keys())
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=header, lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
    path.write_text(buf.getvalue(), encoding="utf-8")


def build(name, files, expected, description):
    folder = OUT / name
    folder.mkdir(parents=True)
    for fname, content in files.items():
        path = folder / fname
        if fname.endswith(".json"):
            path.write_text(json.dumps(content, indent=2), encoding="utf-8")
        elif fname.endswith(".csv"):
            rows, header = content if isinstance(content, tuple) else (content, None)
            write_csv(path, rows, header)
        else:
            path.write_text(content, encoding="utf-8")
    (folder / "expected.json").write_text(json.dumps(
        {"scenario": name, "audit_date": AUDIT_DATE, "description": description,
         "expected": {k: v[0] for k, v in expected.items()},
         "reason": {k: v[1] for k, v in expected.items()}}, indent=2), encoding="utf-8")


def main():
    if OUT.exists():
        shutil.rmtree(OUT)

    good_tabletop = TABLETOP.format(date="2026-04-05", outcome="Exercise completed. All objectives met.",
                                    actions="Update the on-call contact list (done 2026-04-20).")
    good_training = training([(n, d, SEC_COURSE, "Yes", f"2026-0{2 + i % 6}-1{i % 9}")
                              for i, (n, d) in enumerate(STAFF)])
    common = {
        "security_policy.txt": POLICY.format(updated="January 2026"),
        "entra_id_config.json": config(),
        "privileged_accounts.csv": roster(),
        "azure_signin_logs.json": signins(),
        "backup_jobs.json": backups(GOOD_JOBS),
        "encryption_config.json": encryption([bucket(s) for s in STORES]),
        "irp_register.csv": register([("v4.2", "2025-11-10", "2026-04-05")]),
        "irp_document.txt": IRP_DOC.format(version="v4.2"),
        "tabletop_report.txt": good_tabletop,
        "training_records.csv": good_training,
    }

    # 1. Compliant
    build("1_compliant", dict(common), {
        "1": ("Pass", "All five admins covered by an enforced TOTP-only policy; all 30 sign-ins used TOTP."),
        "2": ("Pass", "Schedule defined; recent successful restore tests on every server."),
        "3": ("Pass", "All three inventoried stores encrypted with aws:kms."),
        "4": ("Pass", "Current v4.2 plan supplied; tabletop completed 2026-04-05 and report matches."),
        "5": ("Pass", "All 10 staff completed security awareness training in 2026."),
    }, "Every control genuinely meets the policy.")

    # 2. Non-compliant
    nc = dict(common)
    nc["entra_id_config.json"] = config(state="enabledForReportingButNotEnforced")
    nc["privileged_accounts.csv"] = roster({
        "j.smith@contoso.com": {"mfa_enabled": "No", "mfa_method": "None"},
        "r.chen@contoso.com": {"mfa_enabled": "No", "mfa_method": "None"}})
    nc["azure_signin_logs.json"] = signins({"j.smith@contoso.com": "Password Only",
                                            "r.chen@contoso.com": "Password Only"})
    nc["backup_jobs.json"] = backups([
        job("BKP-2001", "DB-Prod-01", "2026-08-30", "2026-09-01"),
        job("BKP-2002", "DB-Prod-02", "2026-08-30", None, status="Failed", tested=False),
        job("BKP-2003", "App-Prod-01", "2026-08-30", None, tested=False)])
    nc["encryption_config.json"] = encryption([bucket("customer-financial-data"),
                                               bucket("customer-pii", encrypted=False),
                                               bucket("backup-archive")])
    nc["irp_register.csv"] = ([], ["Document_Name", "Version", "Last_Updated",
                                   "Last_Tabletop_Test_Date", "Status"])
    del nc["irp_document.txt"], nc["tabletop_report.txt"]
    nc["training_records.csv"] = training([(n, d, SEC_COURSE, "No", "") for n, d in STAFF])
    build("2_non_compliant", nc, {
        "1": ("Fail", "Policy is report-only; two admins sign in with password only."),
        "2": ("Fail", "One backup failed and two servers have no restore test."),
        "3": ("Fail", "customer-pii has no encryption at rest."),
        "4": ("Fail", "The register lists no incident response plan and none was supplied."),
        "5": ("Fail", "No staff have completed training."),
    }, "Clear, consistent violations.")

    # 3. Tampered
    tp = dict(common)
    logs = signins()
    logs[7]["mfaChallenged"] = False                      # success without a challenge
    logs[12]["timestamp"] = "2026-11-03T09:15:00Z"        # after the audit date
    logs[20]["id"] = logs[19]["id"]                       # duplicated record
    tp["azure_signin_logs.json"] = logs
    tp["backup_jobs.json"] = backups([
        job("BKP-3001", "DB-Prod-01", "2026-08-30", "2026-08-12"),   # tested before it existed
        job("BKP-3002", "DB-Prod-02", "2026-08-30", "2026-09-02"),
        job("BKP-3003", "App-Prod-01", "2026-08-30", "2026-09-03")])
    tp["encryption_config.json"] = encryption([bucket("customer-financial-data", algo="AES256"),
                                               bucket("customer-pii"), bucket("backup-archive")])
    tp["tabletop_report.txt"] = TABLETOP.format(date="2025-02-10", outcome="Exercise completed.",
                                                actions="None recorded.")
    rows = training([(n, d, SEC_COURSE, "Yes", f"2026-0{2 + i % 6}-1{i % 9}")
                     for i, (n, d) in enumerate(STAFF)])
    rows[9]["employee_id"] = rows[8]["employee_id"]        # duplicate person
    rows[3]["completion_date"] = "2026-12-01"              # future completion
    tp["training_records.csv"] = rows
    build("3_tampered", tp, {
        "1": ("Flag", "Logs contain an MFA success with no challenge, a future-dated sign-in and a duplicate record."),
        "2": ("Flag", "BKP-3001 restore test is dated before the backup was taken."),
        "3": ("Flag", "customer-financial-data pairs AES256 with a KMS key ID, which AWS does not accept."),
        "4": ("Flag", "Report says the exercise was 2025-02-10; the register says 2026-04-05."),
        "5": ("Flag", "Duplicate employee ID and a completion date after the audit date."),
    }, "Each file looks compliant, but the evidence contains impossible or contradictory values.")

    # 4. Rules blind spot
    bs = dict(common)
    bs["azure_signin_logs.json"] = signins({"r.chen@contoso.com": "Password + SMS (text message)"})
    bs["backup_jobs.json"] = backups([
        job("BKP-4001", "DB-Prod-01", "2026-08-30", "2026-09-01",
            notes="Restore finished but checksum verification failed on 212 files; ticket INC-4471 open."),
        job("BKP-4002", "DB-Prod-02", "2026-08-30", "2026-09-02", notes="Restore verified."),
        job("BKP-4003", "App-Prod-01", "2026-08-30", "2026-09-03", notes="Restore verified.")])
    bs["tabletop_report.txt"] = TABLETOP.format(
        date="2026-04-05",
        outcome="Exercise abandoned after 30 minutes because key participants were unavailable. "
                "Objectives not met; to be rescheduled.",
        actions="Reschedule the exercise (no date set).")
    bs["training_records.csv"] = training([(n, d, "Fire Safety Induction", "Yes",
                                            f"2026-0{2 + i % 6}-1{i % 9}") for i, (n, d) in enumerate(STAFF)])
    build("4_rules_blind_spot", bs, {
        "1": ("Fail", "Robert Chen signs in with SMS, which policy 2.2 does not allow."),
        "2": ("Fail", "BKP-4001 restore failed checksum verification (notes field)."),
        "3": ("Pass", "Unchanged from the compliant scenario; checks for false alarms."),
        "4": ("Flag", "The exercise was abandoned, so the plan was not actually tested."),
        "5": ("Flag", "Records are for fire safety, not security awareness training."),
    }, "Problems that sit in free text or method names, which the rule checks do not interpret.")

    # 5. Original demo evidence (copied from the main folder)
    demo = {f: (BASE / f).read_text(encoding="utf-8") for f in
            ["security_policy.txt", "entra_id_config.json", "privileged_accounts.csv",
             "azure_signin_logs.json", "backup_jobs.json", "encryption_config.json", "irp_register.csv"]}
    folder = OUT / "5_original_demo"
    folder.mkdir(parents=True)
    for f, text in demo.items():
        (folder / f).write_text(text, encoding="utf-8")
    (folder / "expected.json").write_text(json.dumps({
        "scenario": "5_original_demo", "audit_date": AUDIT_DATE,
        "description": "The original Contoso evidence used in the first demo.",
        "expected": {"1": "Fail", "2": "Flag", "3": "Flag", "4": "Flag", "5": "Flag"},
        "reason": {"1": "John Smith and Robert Chen signed in with password only.",
                   "2": "Two tested backups but no schedule.",
                   "3": "AES256 paired with a KMS key ID; one bucket only; no inventory.",
                   "4": "Only a register entry; no plan or test report.",
                   "5": "No training evidence supplied."}}, indent=2), encoding="utf-8")

    print(f"Scenarios written to {OUT}")


if __name__ == "__main__":
    main()
