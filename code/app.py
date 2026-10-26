"""Local Streamlit interface for the Ghost Data Still Exists audit agent."""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
REQUESTS_PATH = ROOT / "dataset" / "deletion_requests.csv"
OUTPUT_PATH = ROOT / "output.csv"

st.set_page_config(page_title="Ghost Data Audit", page_icon="🔎", layout="wide")
st.title("🔎 Ghost Data Still Exists")
st.caption("Local deletion audit console · evidence-grounded batch analysis")

if not REQUESTS_PATH.is_file():
    st.error(f"Could not find the request data at `{REQUESTS_PATH}`. Start the app from this project checkout.")
    st.stop()

with REQUESTS_PATH.open(encoding="utf-8-sig", newline="") as source:
    requests = list(csv.DictReader(source))

st.info("This interface runs on your computer and reads the project’s `dataset/` files. It does not send data to a hosted service.")

left, right = st.columns([1, 3])
with left:
    st.subheader("Run")
    st.write(f"**Requests loaded:** {len(requests)}")
    if st.button("Run full audit", type="primary", use_container_width=True):
        try:
            from main import main as run_agent

            old_argv = sys.argv[:]
            try:
                sys.argv = [str(Path(__file__).resolve())]
                with st.spinner(f"Auditing {len(requests)} requests and indexing evidence…"):
                    run_agent()
            finally:
                sys.argv = old_argv
            st.success("Audit finished. `output.csv` has been updated.")
        except Exception as exc:
            st.exception(exc)

with right:
    st.subheader("Results")
    st.caption("Run the audit to refresh results. Existing `output.csv` is shown when available.")
    if not OUTPUT_PATH.is_file():
        st.warning("No output file yet. Click **Run full audit** to create one.")
        st.stop()

    try:
        results = pd.read_csv(OUTPUT_PATH, dtype={"case_id": str})
    except Exception as exc:
        st.error(f"Could not read output.csv: {exc}")
        st.stop()

    required = ["case_id", "deletion_status", "steps_json"]
    if list(results.columns) != required:
        st.error("The output file does not match the required schema: case_id,deletion_status,steps_json")
        st.stop()

    counts = results["deletion_status"].value_counts()
    metric_cols = st.columns(3)
    metric_cols[0].metric("Cases processed", len(results))
    metric_cols[1].metric("Incomplete", int(counts.get("INCOMPLETE", 0)))
    metric_cols[2].metric("Complete", int(counts.get("COMPLETE", 0)))

    status_filter = st.multiselect(
        "Filter by status",
        options=["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"],
        default=["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"],
    )
    filtered = results[results["deletion_status"].isin(status_filter)]
    st.dataframe(filtered[["case_id", "deletion_status"]], use_container_width=True, hide_index=True)

    request_by_id = {row["case_id"]: row for row in requests}
    if not filtered.empty:
        selected_case = st.selectbox("Inspect a request", filtered["case_id"].tolist())
        result_row = results.loc[results["case_id"] == selected_case].iloc[0]
        request = request_by_id.get(selected_case, {})
        st.markdown(f"### {selected_case} · {result_row['deletion_status']}")
        st.write("**Request:**", request.get("request_text", ""))
        st.caption(
            f"Audit cutoff: {request.get('audit_at', '—')} · "
            f"Reported workflow status: {request.get('reported_status', '—')}"
        )
        try:
            steps = json.loads(result_row["steps_json"])
        except (TypeError, json.JSONDecodeError):
            steps = []
            st.error("This row contains invalid steps_json.")
        if steps:
            st.dataframe(pd.DataFrame(steps), use_container_width=True, hide_index=True)
            with st.expander("View raw steps JSON"):
                st.code(json.dumps(steps, indent=2, ensure_ascii=False), language="json")
        else:
            st.write("No audit steps. This is expected for a request that does not authorize deletion.")

    st.download_button(
        "Download output.csv",
        data=OUTPUT_PATH.read_bytes(),
        file_name="output.csv",
        mime="text/csv",
    )
