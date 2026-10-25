#!/usr/bin/env python3
"""Evidence-grounded deterministic deletion audit agent."""
import csv, json, re, sys, os, sqlite3
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"


def read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def values_in(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k), v
            yield from values_in(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from values_in(v)


def scalar_values(obj):
    if isinstance(obj,dict):
        for value in obj.values():
            yield from scalar_values(value)
    elif isinstance(obj,list):
        for value in obj:
            yield from scalar_values(value)
    elif isinstance(obj,(str,int,float)):
        yield str(obj).strip().casefold()


def records_in(obj, path=()):
    if isinstance(obj, dict):
        yield obj, path
        for key, value in obj.items():
            yield from records_in(value, path + (str(key),))
    elif isinstance(obj, list):
        for value in obj:
            yield from records_in(value, path)


def is_future(obj, audit_at):
    for key in ("observed_at", "captured_at", "recorded_at", "event_time", "snapshot_at"):
        value = obj.get(key)
        when = parse_time(value) if value else None
        if when and when > audit_at:
            return True
    return False


def id_match(text, identifiers):
    norm = str(text).casefold()
    for item in identifiers:
        item = str(item).strip().casefold()
        if not item:
            continue
        # Token boundaries stop e.g. "Jonas Berg" matching "Jonas Berglund".
        if re.search(r"(?<![a-z0-9])" + re.escape(item) + r"(?![a-z0-9])", norm):
            return True
    return False


def systems_for(path, record):
    rid=str(record.get("resource_id") or record.get("record_id") or record.get("id") or "").casefold()
    # Resource identifiers take precedence over container names such as service_exports.
    prefix_map=(("account_","account_service"),("search_","search_service"),("analytics_","analytics_platform"),("support_","support_platform"),("export_","export_service"),("backup_","backup_service"),("data_flow_","integration_service"),("audit_record_","security_service"),("tombstone_","identity_service"),("marketing_","marketing_service"),("cache_","cache_service"))
    for prefix,system in prefix_map:
        if rid.startswith(prefix):return system
    names=" ".join([*path,*(str(record.get(k,"")) for k in ("system","record_type","collection","data_store","table"))]).casefold()
    if "account_service" in names or "customer_profiles" in names:return "account_service"
    if "search" in names or "index" in names:return "search_service"
    if "analytics" in names:return "analytics_platform"
    if "support" in names or "ticket" in names or "attachment" in names:return "support_platform"
    if "export" in names:return "export_service"
    if "backup" in names or "restore" in names:return "backup_service"
    if "integration" in names or "connector" in names or "data_flow" in names:return "integration_service"
    if "security" in names or "audit" in names:return "security_service"
    if "tombstone" in names:return "identity_service"
    if "marketing" in names:return "marketing_service"
    if "cache" in names:return "cache_service"
    if "email_delivery" in names:return "email_service"
    return None


def text_from_file(path):
    suffix = path.suffix.casefold()
    try:
        if suffix in (".txt", ".log", ".sql", ".csv", ".md"):
            return path.read_text(encoding="utf-8-sig", errors="replace")
        if suffix == ".json":
            return path.read_text(encoding="utf-8-sig", errors="replace")
        if suffix in (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff"):
            try:
                from PIL import Image
                import pytesseract
                return pytesseract.image_to_string(Image.open(path))
            except Exception:
                return ""
        if suffix == ".pdf":
            try:
                import pdfplumber
                with pdfplumber.open(path) as pdf:
                    return "\n".join(page.extract_text() or "" for page in pdf.pages)
            except Exception:
                try:
                    from pypdf import PdfReader
                    return "\n".join(page.extract_text() or "" for page in PdfReader(str(path)).pages)
                except Exception:
                    return ""
    except OSError:
        return ""
    return ""


def load_evidence():
    result = []
    for row in read_csv(DATA / "evidence_files.csv"):
        path = DATA / row["file_path"]
        body = text_from_file(path) if path.exists() else ""
        obj = None
        if path.suffix.casefold() == ".json" and body:
            try: obj = json.loads(body)
            except json.JSONDecodeError: pass
        result.append({"id": row["file_id"], "captured": parse_time(row["captured_at"]), "path": path, "body": body, "json": obj})
    return result


def aliases_for(req, users, audits, evidence):
    email = req["email"].strip().casefold()
    matched = set()
    for row in users:
        if row["email"].strip().casefold() == email:
            matched.add(row["user_id"])
    for row in audits:
        if row["field_name"].casefold() == "email" and email in (row["old_value"].strip().casefold(), row["new_value"].strip().casefold()):
            matched.add(row["user_id"])
    # Use direct participant evidence only to bridge a request alias to a stable user id.
    if not matched:
        for file in evidence:
            body = file["body"]
            if not body or not id_match(email, [email]): continue
            if email in body.casefold():
                for uid in re.findall(r"\buser_\d+\b", body, re.I):
                    # Only accept a user id in a compact line/block that also contains the request email.
                    if any(email in line.casefold() and uid.casefold() in line.casefold() for line in body.splitlines()):
                        matched.add(uid)
    identifiers = {email}
    for row in users:
        if row["user_id"] in matched:
            identifiers.add(row["user_id"].casefold())
            identifiers.update(row[k].strip().casefold() for k in ("name", "email", "phone", "email_hash") if row.get(k))
    for row in audits:
        if row["user_id"] in matched and parse_time(row["event_time"]) <= parse_time(req["audit_at"]):
            for key in ("old_value", "new_value"):
                if row.get(key): identifiers.add(row[key].strip().casefold())
    return matched, identifiers


def intent_is_deletion(text):
    t = " ".join(text.casefold().split())
    # Non-deletion requests are identified by their requested outcome, not by status fields.
    no_delete = [
        r"\bnot asking for deletion\b", r"\bnot a request to erase\b", r"\binformation request\b",
        r"\bdo not close the account\b", r"\bdon't close the account\b", r"\bdo not delete or change\b",
        r"\bplease don't delete\b", r"\bkeep the account as it is\b", r"\bleave the account active\b",
        r"\bi still need the account\b", r"\bi still want (?:receipts|the account|my account|to continue)",
        r"\bi want to continue using the service\b", r"\bmarketing lists only\b", r"\bstop the promotional emails\b",
        r"\bchange the email address\b", r"\breplace it with the new one\b", r"\bcorrect it without removing\b",
        r"\bmisspelled\b", r"\bresetting the login\b", r"\bdownload my account information\b",
        r"\bsend me a copy of (?:the )?information\b", r"\bcopy of last year's invoices\b",
        r"\bhow to access my profile\b", r"\bchange (?:my|the) (?:email|phone|mobile number)\b",
    ]
    return not any(re.search(p, t) for p in no_delete)


def category_action(system, obj, path, rules):
    rid = str(obj.get("resource_id") or obj.get("record_id") or obj.get("id") or "")
    category = " ".join([*path, *(str(obj.get(k, "")) for k in ("record_type", "collection", "data_store", "table"))]).casefold()
    direct_fields = ("email", "phone", "email_hash", "name", "full_name", "customer_name", "requester_email", "requester_phone")
    pii = any(obj.get(k) not in (None, "", "null", "None") for k in direct_fields)
    if system=="support_platform":
        message=" ".join(str(obj.get(k,"")) for k in ("message_text","message_excerpt","body","content"))
        pii = pii or bool(re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\+?\d[\d ()-]{7,}\d",message))
    result = " ".join(str(obj.get(k, "")) for k in ("result", "status", "state", "status_code", "http_status", "lookup_result")).casefold()
    # The supplied deletion_rules.csv drives record treatment when a record category is explicit.
    rule_map = {row["data_category"].casefold(): row["required_action"].upper() for row in rules}
    category_text=category.casefold()
    category = next((name for name in rule_map if name in category_text or name+"s" in category_text), "")
    if not category:
        if system=="account_service": category="user_profile"
        elif system=="search_service": category="search_index_entry"
        elif system=="analytics_platform": category="analytics_profile"
        elif system=="support_platform": category="support_attachment" if "attachment" in category_text or obj.get("attachment_id") else "support_message"
        elif system=="export_service": category="user_export"
        elif system=="marketing_service": category="marketing_profile"
        elif system=="cache_service": category="cache_entry"
        elif system=="security_service": category="security_audit_log"
        elif system=="identity_service": category="account_tombstone"
        elif system=="backup_service": category="backup_archive"
    action=rule_map.get(category.casefold(),"")
    if action == "RETAIN" and system == "security_service":
        until = parse_time(obj.get("retention_until"))
        if not until or not parse_time(obj.get("observed_at")) or until >= parse_time(obj.get("observed_at")):
            return "VERIFY_RECORD_PRESENT", "PRESENT"
        action = "DELETE"
    if action == "DELETE":
        if any(x in result for x in ("not_found", "not found", "404", "absent", "deleted", "expired", "unavailable", "miss")):
            return "VERIFY_RECORD_ABSENT", "ABSENT"
        return "REPORT_REMAINING_RECORD", "PRESENT"
    if action == "REDACT":
        if pii: return "REPORT_EXPOSED_PII", "PRESENT"
        return "VERIFY_RECORD_REDACTED", "REDACTED"
    if action == "ANONYMIZE":
        attributable = pii or any(obj.get(k) not in (None, "", "null") for k in ("customer_reference", "user_id", "subject_reference"))
        if any(x in result for x in ("anonymized", "anonymised", "unlinked")) and not pii:
            return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
        if attributable: return "REPORT_EXPOSED_PII", "PRESENT"
        return "VERIFY_RECORD_ANONYMIZED", "ANONYMIZED"
    if system == "backup_service":
        allowed = obj.get("restore_allowed", obj.get("restore_access", obj.get("enabled")))
        if str(allowed).casefold() in ("true", "1", "yes", "allowed", "active", "enabled") or any(x in result for x in ("active", "allowed", "enabled")):
            return "REPORT_RESTORE_RISK", "ACTIVE"
        if str(allowed).casefold() in ("false", "0", "no", "blocked", "disabled") or any(x in result for x in ("blocked", "disabled")):
            return "VERIFY_RESTORE_BLOCKED", "BLOCKED"
    if system == "integration_service":
        enabled = obj.get("enabled", obj.get("active", obj.get("status")))
        if str(enabled).casefold() in ("true", "1", "yes", "active", "enabled", "healthy") or "active" in result:
            return "REPORT_ACTIVE_DATA_FLOW", "ACTIVE"
        if str(enabled).casefold() in ("false", "0", "no", "inactive", "disabled", "stopped") or "disabled" in result or "stopped" in result:
            return "VERIFY_DATA_FLOW_DISABLED", "DISABLED"
    return None


def line_observations(file, identifiers, audit_at, force_system=None):
    observations = []
    body = file["body"]
    for line in body.splitlines():
        if not id_match(line, identifiers): continue
        # One line can contain a record key and a linked source key. Prefer the first actual key.
        found = re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache)_\d+\b", line, re.I)
        if not found: continue
        rid = found[0]
        # Prefer named system in the line; otherwise infer from resource prefix.
        system = force_system
        lo = line.casefold()
        if not system:
            for name, token in (("account_service","account_service"),("search_service","search_service"),("analytics_platform","analytics_platform"),("support_platform","support_platform"),("export_service","export_service"),("backup_service","backup_service"),("integration_service","integration_service"),("security_service","security_service")):
                if token in lo: system = name; break
        if not system:
            system = systems_for((), {"resource_id":rid})
        if not system: continue
        if any(x in lo for x in ("http_status=404", "status_code=404", "not_found", "not found", "rows=0", " result=miss", "result=absent")):
            op = "VERIFY_RECORD_ABSENT" if system in ("account_service","search_service","export_service","support_platform") else None
            state = "ABSENT"
        elif system == "security_service": op,state="VERIFY_RECORD_PRESENT","PRESENT"
        elif system == "backup_service" and (re.search(r"restore_(?:allowed|access)=(?:true|1)|result=active|status=active|eligible=true|deletion_block=false",lo) or ("restore_candidate_evaluated" in lo and "eligible" in lo) or ("backup_archive" in lo and "active" in lo)): op,state="REPORT_RESTORE_RISK","ACTIVE"
        elif system == "backup_service" and re.search(r"restore_(?:allowed|access)=(?:false|0)|result=blocked|deletion_block=true|eligible=false",lo): op,state="VERIFY_RESTORE_BLOCKED","BLOCKED"
        elif system == "integration_service" and (re.search(r"(?:enabled|active)=(?:true|1)|status=active|result=active",lo) or ("data_flow" in lo and "active" in lo)): op,state="REPORT_ACTIVE_DATA_FLOW","ACTIVE"
        elif system == "integration_service" and re.search(r"(?:enabled|active)=(?:false|0)|status=disabled|result=disabled",lo): op,state="VERIFY_DATA_FLOW_DISABLED","DISABLED"
        elif system == "analytics_platform" and any(x in lo for x in ("identifiable", "email=", "phone=", "email_hash=", "pii_remains")): op,state="REPORT_EXPOSED_PII","PRESENT"
        elif system == "analytics_platform" and any(x in lo for x in ("anonymized", "anonymised", "unlinked", "no direct identifier")): op,state="VERIFY_RECORD_ANONYMIZED","ANONYMIZED"
        elif system == "analytics_platform" and re.search(r"rows[=:]1|result=found|contact_lookup_completed",lo): op,state="REPORT_REMAINING_RECORD","PRESENT"
        elif system == "support_platform" and any(x in lo for x in ("identifiable", "email=", "phone=", "requester_email", "requester_phone", "pii_remains", "customer_name", "matched_value=", "direct_identifier")): op,state="REPORT_EXPOSED_PII","PRESENT"
        elif system == "support_platform" and any(x in lo for x in ("attachment", "file_id=", "attachment_id=")): op,state="REPORT_REMAINING_RECORD","PRESENT"
        elif system == "identity_service" and any(x in lo for x in ("email=", "phone=", "name=", "identifiable")): op,state="REPORT_EXPOSED_PII","PRESENT"
        elif system == "identity_service" and any(x in lo for x in ("redacted", "no direct identifier")): op,state="VERIFY_RECORD_REDACTED","REDACTED"
        elif system in ("account_service","search_service","export_service","support_platform","marketing_service","cache_service") and any(x in lo for x in ("found", "present", "active", "rows=1", "result=hit", "identifiable", "insert into", "values(", "available=true", "still_present=true")):
            op,state="REPORT_REMAINING_RECORD","PRESENT"
        else: continue
        if op: observations.append(obs(file["id"],system,rid,op,state))
    return observations


def obs(evidence, system, rid, op, state):
    return {"system_id":system,"resource_id":rid,"operation":op,"state":state,"evidence_id":evidence}


def dedup(items):
    result = {}
    for item in items:
        key = (item["system_id"], item["resource_id"], item["operation"])
        # Keep the latest listed evidence observation where alternatives exist.
        result[key] = item
    return list(result.values())

ORDER = {"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3,"DISABLE_DATA_FLOW":4,"BLOCK_RESTORE":5,"DELETE_RECORD":6,"REDACT_RECORD":7,"ANONYMIZE_RECORD":8,"VERIFY_RECORD_ABSENT":9,"VERIFY_RECORD_PRESENT":10,"VERIFY_RECORD_REDACTED":11,"VERIFY_RECORD_ANONYMIZED":12,"VERIFY_DATA_FLOW_DISABLED":13,"VERIFY_RESTORE_BLOCKED":14}

def make_steps(findings, verified, incomplete, account_ids=(), planned_verifications=()):
    items=[]
    if incomplete:
        for f in findings:
            items.append(f)
            op=f["operation"]; system=f["system_id"]; rid=f["resource_id"]
            if op=="REPORT_REMAINING_RECORD": rem,ver,state="DELETE_RECORD","VERIFY_RECORD_ABSENT","ABSENT"
            elif op=="REPORT_EXPOSED_PII":
                if system=="analytics_platform":rem,ver,state="ANONYMIZE_RECORD","VERIFY_RECORD_ANONYMIZED","ANONYMIZED"
                elif system=="identity_service":rem,ver,state="REDACT_RECORD","VERIFY_RECORD_REDACTED","REDACTED"
                else:rem,ver,state="REDACT_RECORD","VERIFY_RECORD_REDACTED","REDACTED"
            elif op=="REPORT_ACTIVE_DATA_FLOW":rem,ver,state="DISABLE_DATA_FLOW","VERIFY_DATA_FLOW_DISABLED","DISABLED"
            elif op=="REPORT_RESTORE_RISK":rem,ver,state="BLOCK_RESTORE","VERIFY_RESTORE_BLOCKED","BLOCKED"
            else:continue
            remstate={"DELETE_RECORD":"ABSENT","REDACT_RECORD":"REDACTED","ANONYMIZE_RECORD":"ANONYMIZED","DISABLE_DATA_FLOW":"DISABLED","BLOCK_RESTORE":"BLOCKED"}[rem]
            items.append(obs("",system,rid,rem,remstate))
            items.append(obs("",system,rid,ver,state))
        # Every account link identified for this subject is included in the post-delete check plan.
        for rid in account_ids:
            items.append(obs("","account_service",rid,"VERIFY_RECORD_ABSENT","ABSENT"))
        # Records already checked must be rechecked after remediation.
        for v in verified:
            items.append(obs("",v["system_id"],v["resource_id"],v["operation"],v["state"]))
        # Identity-link events can justify a future check without proving current state.
        items.extend(planned_verifications)
    else:
        items.extend(verified)
    items=dedup(items)
    items.sort(key=lambda x:(ORDER.get(x["operation"],99),x["system_id"],x["resource_id"]))
    result=[]
    for i,item in enumerate(items,1):
        op=item["operation"]
        phase="FINDING" if op.startswith("REPORT_") else "REMEDIATION" if op in {"DISABLE_DATA_FLOW","BLOCK_RESTORE","DELETE_RECORD","REDACT_RECORD","ANONYMIZE_RECORD"} else "VERIFICATION"
        result.append({"step_no":i,"phase":phase,**item})
    return result


def index_corpus(files):
    """Build reusable postings so every request queries evidence rather than rescanning it."""
    records=[]; value_postings={}; resource_postings={}; resource_line_postings={}; trace_postings={}; lines=[]; token_postings={}
    token_re=re.compile(r"[\w.+%'-]+@[\w.-]+\.[A-Za-z]{2,}|user_\d+|(?:[a-f0-9]{40,})|[a-z0-9_]+",re.I)
    for file in files:
        if file["json"] is not None:
            for obj,path in records_in(file["json"]):
                rid=str(obj.get("resource_id") or obj.get("record_id") or "").casefold()
                if not rid: continue
                system=systems_for(path,obj)
                if not system: continue
                vals=set(scalar_values(obj))
                idx=len(records);records.append((file,obj,path,system,vals,rid))
                for value in vals:value_postings.setdefault(value,set()).add(idx)
                resource_postings.setdefault(rid,set()).add(idx)
        elif file["body"] and file["path"].suffix.casefold()==".sql":
            # SQL-compatible participant snapshots are queried in-memory; never modify the inputs.
            try:
                conn=sqlite3.connect(":memory:")
                conn.executescript(file["body"])
                tables=[r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")]
                for table in tables:
                    cur=conn.execute('SELECT * FROM "'+table.replace('"','""')+'"')
                    cols=[x[0] for x in cur.description]
                    for values in cur.fetchall():
                        obj=dict(zip(cols,values));obj["table"]=table
                        # Snapshot exports often store their logical row as a JSON payload column.
                        for raw in values:
                            if isinstance(raw,str) and raw.lstrip().startswith("{"):
                                try:
                                    nested=json.loads(raw)
                                    if isinstance(nested,dict): obj.update(nested)
                                except json.JSONDecodeError: pass
                        rid=str(obj.get("resource_id") or obj.get("record_id") or obj.get("id") or "").casefold()
                        if not rid:
                            rid=next((m.group(0).casefold() for raw in values if isinstance(raw,str) for m in [re.search(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache)_\d+\b",raw,re.I)] if m),"")
                        if not rid:continue
                        system=systems_for((table,),obj)
                        if not system:continue
                        vals=set(scalar_values(obj))
                        idx=len(records);records.append((file,obj,(table,),system,vals,rid))
                        for value in vals:value_postings.setdefault(value,set()).add(idx)
                        resource_postings.setdefault(rid,set()).add(idx)
                conn.close()
            except sqlite3.Error:
                pass
        elif file["body"]:
            for line in file["body"].splitlines():
                li=len(lines);lines.append((file,line))
                for token in set(t.casefold() for t in token_re.findall(line)):
                    token_postings.setdefault(token,set()).add(li)
                # Inputs use both keyed trace fields and bare request IDs in
                # the log prefix (for example "requestId=tr-123" or "| tr-123 |").
                traces = re.findall(r"(?:trace_id|trace|request_id)=([\w-]+)",line,re.I)
                traces.extend(re.findall(r"\b(?:tr|rb)-[\w-]+\b",line,re.I))
                for trace in traces:
                    trace_postings.setdefault(trace.casefold(),set()).add(li)
                for rid in re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache)_\d+\b",line,re.I):
                    resource_line_postings.setdefault(rid.casefold(),set()).add(li)
    return records,value_postings,resource_postings,resource_line_postings,trace_postings,lines,token_postings

def candidate_lines(aliases,token_postings):
    found=set()
    for alias in aliases:
        a=str(alias).strip().casefold()
        if not a:continue
        tokens=[a] if "@" in a or re.fullmatch(r"user_\d+|[a-f0-9]{40,}",a) else re.findall(r"[a-z0-9_]+",a)
        if not tokens:continue
        postings=[token_postings.get(t,set()) for t in tokens]
        seed=min(postings,key=len) if postings else set()
        # Confirm full phrase after using the rarest token as the retrieval key.
        found.update(seed)
    return found

def main():
    request_file = sys.argv[1] if len(sys.argv)>1 else "deletion_requests.csv"
    requests=read_csv(DATA/request_file)
    identities=read_csv(DATA/"user_identities.csv")
    audits=read_csv(DATA/"user_audit_log.csv")
    manifest=load_evidence()
    rules=read_csv(DATA/"deletion_rules.csv")
    activities=read_csv(DATA/"system_activity.csv")
    evidence_records,value_postings,resource_postings,resource_line_postings,trace_postings,text_lines,token_postings=index_corpus(manifest)
    answers=[]
    for req in requests:
        audit_at=parse_time(req["audit_at"])
        if not intent_is_deletion(req["request_text"]):
            answers.append((req["case_id"],"NOT_APPLICABLE",[])); continue
        user_ids, identifiers=aliases_for(req,identities,audits,manifest)
        # Activity provides identity-to-resource discovery only. Its result is never treated as state proof.
        candidate_resources=set()
        planned_verifications=[]
        for activity in activities:
            when=parse_time(activity["event_time"])
            if when and audit_at and when>audit_at: continue
            if id_match(activity.get("details", ""), identifiers) or any(id_match(activity.get("details", ""), [uid]) for uid in user_ids):
                rid=activity.get("resource_id", "").casefold()
                if rid: candidate_resources.add(rid)
                if activity.get("event_type", "").casefold()=="link_resource_identity" and rid:
                    details=activity.get("details", "").casefold()
                    system=systems_for((), {"resource_id":rid})
                    if not system and activity.get("target_system", "").casefold()=="object_storage" and "attachment" in details and "belongs only" in details:
                        system="support_platform"
                    # These resource types have unambiguous required treatment in deletion_rules.csv.
                    if system=="marketing_service":
                        planned_verifications.append(obs("",system,rid,"VERIFY_RECORD_ABSENT","ABSENT"))
                    elif system=="security_service":
                        planned_verifications.append(obs("",system,rid,"VERIFY_RECORD_PRESENT","PRESENT"))
                    elif system=="support_platform" and "attachment" in details and "belongs only" in details:
                        planned_verifications.append(obs("",system,rid,"VERIFY_RECORD_ABSENT","ABSENT"))
        findings=[]; verified=[]; linked_account_ids=set()
        # Resolve activity pointers first; activity outcomes are never accepted as state proof.
        for activity in activities:
            when=parse_time(activity["event_time"])
            if when and audit_at and when>audit_at: continue
            if id_match(activity.get("details", ""), identifiers):
                if activity.get("resource_id"): candidate_resources.add(activity["resource_id"].casefold())
        candidate_records=set()
        for alias in identifiers:
            candidate_records.update(value_postings.get(alias,set()))
        # Resource IDs found in identity-bearing evidence can be joined to later/earlier readbacks.
        candidate_resources.update(evidence_records[i][5] for i in candidate_records)
        for rid in candidate_resources:
            candidate_records.update(resource_postings.get(rid,set()))
        for idx in candidate_records:
            file,obj,path,system,vals,rid=evidence_records[idx]
            linked_account_ids.update(x.casefold() for v in obj.values() if isinstance(v,str) for x in re.findall(r"\baccount_\d+\b",v,re.I))
            if file["captured"] and audit_at and file["captured"]>audit_at: continue
            if is_future(obj,audit_at): continue
            if not vals.intersection(identifiers) and rid not in candidate_resources: continue
            result=category_action(system,obj,path,rules)
            if result:
                op,state=result
                target=verified if op.startswith("VERIFY_") else findings
                target.append(obs(file["id"],system,rid,op,state))
        candidate_text_ids=candidate_lines(identifiers,token_postings)
        identity_lines={i for i in candidate_text_ids if id_match(text_lines[i][1],identifiers)}
        # Correlate multi-line traces and then join every matching resource to its readback lines.
        traces=set();
        for line_id in identity_lines:
            line=text_lines[line_id][1]
            candidate_resources.update(x.casefold() for x in re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache)_\d+\b",line,re.I))
            linked_account_ids.update(x.casefold() for x in re.findall(r"\baccount_\d+\b",line,re.I))
            traces.update(x.casefold() for x in re.findall(r"(?:trace_id|trace|request_id)=([\w-]+)",line,re.I))
        for line_id in identity_lines:
            line=text_lines[line_id][1]
            traces.update(x.casefold() for x in re.findall(r"\b(?:tr|rb)-[\w-]+\b",line,re.I))
        for trace in traces: identity_lines.update(trace_postings.get(trace,set()))
        for line_id in identity_lines:
            line=text_lines[line_id][1]
            candidate_resources.update(x.casefold() for x in re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache)_\d+\b",line,re.I))
            linked_account_ids.update(x.casefold() for x in re.findall(r"\baccount_\d+\b",line,re.I))
        candidate_text_ids=identity_lines
        for rid in candidate_resources:
            candidate_text_ids.update(resource_line_postings.get(rid,set()))
        processed_trace_lines=set()
        # Correlate all records in a request/trace, since lookup keys and readback state often occupy separate log lines.
        for trace in traces:
            members=[i for i in trace_postings.get(trace,set()) if i in identity_lines]
            if not members: continue
            context=" ".join(text_lines[i][1] for i in members)
            resources=set(x.casefold() for x in re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache)_\d+\b",context,re.I))
            linked_account_ids.update(x for x in resources if x.startswith("account_"))
            candidate_resources.update(resources)
            processed_trace_lines.update(members)
            for rid in resources:
                synthetic=dict(text_lines[members[0]][0]); synthetic["body"]=rid+" "+context
                for item in line_observations(synthetic,identifiers | candidate_resources | {rid},audit_at,systems_for((),{"resource_id":rid})):
                    target=verified if item["operation"].startswith("VERIFY_") else findings
                    target.append(item)
        # PDFs are single-document records: correlate identifiers and resource keys within the extracted document text.
        for file in manifest:
            if file["path"].suffix.casefold()!=".pdf" or not file["body"]: continue
            if file["captured"] and audit_at and file["captured"]>audit_at: continue
            if not id_match(file["body"],identifiers): continue
            resources=set(x.casefold() for x in re.findall(r"\b(?:account|search|analytics|support|export|backup|data_flow|audit_record|tombstone|marketing|cache)_\d+\b",file["body"],re.I))
            linked_account_ids.update(x for x in resources if x.startswith("account_"))
            for rid in resources:
                synthetic=dict(file); synthetic["body"]=rid+" "+file["body"].replace("\n"," ")
                for item in line_observations(synthetic,identifiers | {rid},audit_at,systems_for((),{"resource_id":rid})):
                    target=verified if item["operation"].startswith("VERIFY_") else findings
                    target.append(item)
        for line_id in candidate_text_ids:
            if line_id in processed_trace_lines: continue
            file,line=text_lines[line_id]
            if file["captured"] and audit_at and file["captured"]>audit_at: continue
            if not id_match(line,identifiers) and not any(rid in line.casefold() for rid in candidate_resources): continue
            one=dict(file); one["body"]=line
            for item in line_observations(one,identifiers | candidate_resources,audit_at):
                target=verified if item["operation"].startswith("VERIFY_") else findings
                target.append(item)
        findings=dedup(findings); verified=dedup(verified)
        # Completion requires explicit account-profile absence and no confirmed residuals or risks.
        account_absence=any(x["system_id"]=="account_service" and x["operation"]=="VERIFY_RECORD_ABSENT" for x in verified)
        status="INCOMPLETE" if findings or not account_absence else "COMPLETE"
        # Claims in workflow and activity are deliberately not enough to declare completion.
        steps=make_steps(findings,verified,status=="INCOMPLETE",linked_account_ids,planned_verifications)
        answers.append((req["case_id"],status,steps))
    out=Path(os.environ.get("ORCHESTRATE_OUTPUT_PATH", str(ROOT/"output.csv")))
    with out.open("w",encoding="utf-8",newline="") as f:
        writer=csv.writer(f,lineterminator="\n")
        writer.writerow(["case_id","deletion_status","steps_json"])
        for case,status,steps in sorted(answers,key=lambda row:row[0]):
            writer.writerow([case,status,json.dumps(steps,separators=(",",":"),ensure_ascii=False)])

if __name__=="__main__": main()




