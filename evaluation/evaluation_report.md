# Evaluation report

## Workflow and metric definitions

`python code/evaluate.py --generate` generates all predictions from participant-facing data, validates the 518-row contract, compares the public sample with the provided answers, and runs five team-authored synthetic checks. The benchmark uses the 32 public sample requests.

- **Status accuracy:** exact status matches divided by 32 requests.
- **Exact sequence accuracy:** cases whose entire ordered step arrays match divided by 32.
- **Step precision/recall/F1:** a predicted step is correct only when every required field matches the gold step at the same `step_no`; denominators are total predicted and gold steps.
- **Field accuracy:** matching step fields divided by all fields in gold steps, aligned by `step_no`.

## Public sample results

- Status: **25/32 (78.1%)**.
- Exact ordered sequences: **8/32 (25.0%)**.
- Exact step matches: **123/164 predicted steps**, against **193 gold steps**.
- Step precision: **75.0%**; recall: **63.7%**; F1: **68.9%**.
- Field accuracy: **996/1,351 (73.7%)** across step number, phase, system, resource, operation, state, and evidence ID.

These are calibration scores on public answers and do not establish accuracy on the remaining requests or hidden evaluation data.

## Team-authored synthetic evaluation cases

Five policy checks run in `code/evaluate.py`:

1. A marketing-only opt-out that keeps the account is `NOT_APPLICABLE`.
2. A security audit record within its retention period remains available.
3. A support message containing a direct identifier is flagged for redaction.
4. A backup archive with restore access is reported as a restore risk.
5. A remaining search record and active integration flow produce ordered findings, remediation, and verification steps.

All five checks pass.

## Failures found and improvements made

Initial parsing missed cross-line logs using bare `tr-`/`rb-` request IDs, nested JSON values in SQL snapshots, and line-level export availability signals. The parser now joins those traces, expands nested JSON, and recognizes explicit `available=true` evidence. PDF extraction was previously skipped when run under a Python interpreter without the declared PDF libraries; final generation used the bundled runtime with PDF dependencies installed. The evaluator's temporary sample output now stays inside the repository, avoiding Windows Controlled Folder Access blocks on the system temp directory.

The public benchmark still has seven status mismatches and only eight exact sequences. Several sample resources have no direct identity link in the supplied evidence; guesses based only on case IDs or nearby activity would risk attributing another person's record. `case_53` remains `INCOMPLETE` with an empty sequence because its pre-cutoff evidence establishes a resource link but not the resource's state; later state evidence is excluded by the time contract.

## Full dataset run

The final `output.csv` has 518 rows: 39 COMPLETE, 469 INCOMPLETE, and 10 NOT_APPLICABLE. Only 32 rows have supplied reference answers; accuracy for the other 486 cannot be calculated from the provided materials. Ten `NOT_APPLICABLE` rows correctly have empty step arrays. One `INCOMPLETE` row has no grounded steps for the cutoff reason above.
