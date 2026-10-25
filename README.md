# Ghost Data Still Exists

A deterministic deletion audit agent for the HackerRank Orchestrate October 2026 challenge. It reads the participant-facing request, identity, policy, activity, and evidence files; reconstructs the state at each request's `audit_at`; and writes the required `output.csv` schema.

## Requirements

- Python 3.10 or newer
- Dependencies in `code/requirements.txt`
- For image OCR, install the Tesseract executable separately. PDF text extraction uses `pdfplumber` when installed, with `pypdf` as a fallback.

## Run

From the repository root, install dependencies and generate all 518 predictions:

```powershell
python -m pip install -r code/requirements.txt
python code/main.py
```

The command writes `output.csv` at the repository root. The input files must be present under `dataset/`.

## Evaluate

```powershell
python code/evaluate.py
```

This checks the existing `output.csv`, compares the 32 public sample requests with their provided answers, and runs five synthetic policy checks. To regenerate the full output first:

```powershell
python code/evaluate.py --generate
```

On Windows, run with the same Python environment where the requirements were installed. The evaluator creates its temporary sample output inside the repository so Controlled Folder Access does not block writes to the system temp folder.

## Design

- Resolves current and historical email, phone, name, hash, and stable user identifiers.
- Indexes structured JSON, SQLite-compatible SQL exports, text logs, PDFs, and optional OCR text.
- Uses activity as a resource-discovery hint, not as proof of record state.
- Applies `dataset/deletion_rules.csv` and ignores evidence captured after `audit_at`.
- Produces ordered findings, remediation, and verification steps with participant-visible evidence citations.
- Uses no external model provider; behavior is deterministic Python.

## Current evaluation and limits

The public calibration results and metric definitions are in [`evaluation/evaluation_report.md`](evaluation/evaluation_report.md). The latest measured scores are 25/32 statuses correct, 8/32 exact sequences, and 996/1,351 matching fields. There is no answer key for the other 486 requests, so their accuracy is unknown. One incomplete request, `case_53`, has no grounded finding because the evidence available by its cutoff identifies a related support resource but does not establish its state. The agent leaves it incomplete instead of treating later evidence as proof.

## Submission files

- `output.csv`: prediction file for all requests.
- `code.zip`: runnable source and the required `evaluation/` reports; the dataset and caches are excluded.
- `log.txt`: local development transcript, available separately for the challenge upload and excluded from Git by `.gitignore`.

