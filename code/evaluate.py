#!/usr/bin/env python3
"""Evaluation workflow: public sample benchmark, synthetic policy checks, output contract."""
import csv, json, os, subprocess, sys, tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/"dataset"
sys.path.insert(0,str(ROOT/"code"))
import main as agent


def readcsv(path):
    with path.open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))

def validate_submission(path):
    requests=readcsv(DATA/"deletion_requests.csv")
    rows=readcsv(path)
    with path.open(encoding="utf-8-sig",newline="") as f:
        header=next(csv.reader(f))
    assert header==["case_id","deletion_status","steps_json"], f"unexpected header: {header}"
    assert len(rows)==len(requests)==518, f"expected 518 rows; got {len(rows)}"
    expected=sorted(x["case_id"] for x in requests)
    assert [x["case_id"] for x in rows]==expected, "case IDs missing, duplicated, or unsorted"
    allowed_evidence={r["file_id"] for r in readcsv(DATA/"evidence_files.csv")}
    allowed_evidence.update(r["activity_id"] for r in readcsv(DATA/"system_activity.csv"))
    allowed_evidence.update(r["audit_id"] for r in readcsv(DATA/"user_audit_log.csv"))
    for row in rows:
        assert row["deletion_status"] in {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"}
        steps=json.loads(row["steps_json"])
        assert isinstance(steps,list)
        if row["deletion_status"]=="NOT_APPLICABLE": assert steps==[]
        assert row["deletion_status"]!="COMPLETE" or all(x["phase"]=="VERIFICATION" for x in steps)
        assert row["deletion_status"]!="COMPLETE" or any(x["system_id"]=="account_service" and x["operation"]=="VERIFY_RECORD_ABSENT" for x in steps), "complete status requires evidence that the account profile is absent"
        assert [agent.ORDER[x["operation"]] for x in steps]==sorted(agent.ORDER[x["operation"]] for x in steps), "phase/operation order invalid"
        for i,step in enumerate(steps,1):
            assert step["step_no"]==i
            assert step["phase"] in {"FINDING","REMEDIATION","VERIFICATION"}
            assert step["operation"] in agent.ORDER
            assert all(k in step for k in ("system_id","resource_id","state","evidence_id"))
            if step["phase"]=="REMEDIATION" or (row["deletion_status"]=="INCOMPLETE" and step["phase"]=="VERIFICATION"):
                assert step["evidence_id"]==""
            elif step["phase"]=="FINDING" or row["deletion_status"]=="COMPLETE":
                assert step["evidence_id"], "observed finding/complete verification must cite evidence"
                assert step["evidence_id"] in allowed_evidence, "citation is not in participant evidence manifests"
    return len(rows)

def public_benchmark():
    # Keep temporary outputs inside the repository: Windows Controlled Folder
    # Access may block writes to the system temp directory for this process.
    with tempfile.TemporaryDirectory(prefix=".orchestrate-eval-",dir=ROOT) as td:
        sample_out=Path(td)/"sample-output.csv"
        env=os.environ.copy();env["ORCHESTRATE_OUTPUT_PATH"]=str(sample_out)
        subprocess.run([sys.executable,str(ROOT/"code/main.py"),"sample_deletion_requests.csv"],cwd=ROOT,env=env,check=True)
        got={x["case_id"]:x for x in readcsv(sample_out)}
    gold={x["case_id"]:x for x in readcsv(DATA/"sample_output.csv")}
    n=len(gold); status_correct=sum(got[k]["deletion_status"]==v["deletion_status"] for k,v in gold.items())
    exact=0;field_correct=0;field_total=0;gold_steps=0;predicted_steps=0;exact_step_matches=0
    fields=("step_no","phase","system_id","resource_id","operation","state","evidence_id")
    for case,g in gold.items():
        pred=json.loads(got[case]["steps_json"]); target=json.loads(g["steps_json"])
        exact += pred==target;gold_steps+=len(target);predicted_steps+=len(pred)
        predicted_by_no={x["step_no"]:x for x in pred}
        for expected in target:
            actual=predicted_by_no.get(expected["step_no"],{})
            exact_step_matches += actual==expected
            for field in fields:
                field_total+=1;field_correct += actual.get(field)==expected.get(field)
    step_precision=exact_step_matches/predicted_steps if predicted_steps else 0
    step_recall=exact_step_matches/gold_steps if gold_steps else 0
    step_f1=2*step_precision*step_recall/(step_precision+step_recall) if step_precision+step_recall else 0
    return {"cases":n,"status_correct":status_correct,"status_accuracy":status_correct/n,"exact_sequences":exact,"sequence_accuracy":exact/n,"exact_step_matches":exact_step_matches,"predicted_steps":predicted_steps,"gold_steps":gold_steps,"step_precision":step_precision,"step_recall":step_recall,"step_f1":step_f1,"correct_fields_at_step":field_correct,"gold_fields":field_total,"field_accuracy":field_correct/field_total if field_total else 0}

def synthetic_checks():
    rules=readcsv(DATA/"deletion_rules.csv")
    checks=[]
    checks.append(("no deletion intent",not agent.intent_is_deletion("Please stop promotional emails only. I still need the account and order history.")))
    checks.append(("policy retains security audit",agent.category_action("security_service",{"resource_id":"audit_record_synthetic","record_type":"SECURITY_AUDIT_LOG","retention_until":"2030-01-01T00:00:00Z","observed_at":"2026-01-01T00:00:00Z"},(),rules)==("VERIFY_RECORD_PRESENT","PRESENT")))
    checks.append(("policy flags support PII",agent.category_action("support_platform",{"resource_id":"support_synthetic","record_type":"SUPPORT_MESSAGE","email":"person@example.test"},(),rules)==("REPORT_EXPOSED_PII","PRESENT")))
    checks.append(("policy flags restore access",agent.category_action("backup_service",{"resource_id":"backup_synthetic","record_type":"BACKUP_ARCHIVE","restore_allowed":True},(),rules)==("REPORT_RESTORE_RISK","ACTIVE")))
    plan=agent.make_steps([agent.obs("evidence_synthetic","search_service","search_synthetic","REPORT_REMAINING_RECORD","PRESENT"),agent.obs("evidence_synthetic","integration_service","flow_synthetic","REPORT_ACTIVE_DATA_FLOW","ACTIVE")],[],True)
    ordered=[x["operation"] for x in plan]
    checks.append(("ordered complete remediation and verification",ordered==["REPORT_REMAINING_RECORD","REPORT_ACTIVE_DATA_FLOW","DISABLE_DATA_FLOW","DELETE_RECORD","VERIFY_RECORD_ABSENT","VERIFY_DATA_FLOW_DISABLED"]))
    return checks

def main():
    if len(sys.argv)>1 and sys.argv[1]=="--generate":
        subprocess.run([sys.executable,str(ROOT/"code/main.py")],cwd=ROOT,check=True)
    count=validate_submission(ROOT/"output.csv")
    benchmark=public_benchmark()
    checks=synthetic_checks()
    if not all(ok for _,ok in checks):raise SystemExit("synthetic contract check failed: "+repr(checks))
    print(json.dumps({"submission_rows":count,"public_sample":benchmark,"synthetic_checks":checks},indent=2))

if __name__=="__main__":main()
