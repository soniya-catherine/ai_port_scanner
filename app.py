import os

import pandas as pd
import streamlit as st

from core.scanner import resolve_target, scan_port_range
from core.explainer import get_explanation_report, has_hf_token

# Configure Streamlit page 
st.set_page_config(page_title="AI Port Scanner", page_icon="assets/logo.png", layout="wide")

st.image("assets/logo.png", width=64)
st.title("AI-Assisted Port Scanner")
st.write("Scan a target host for open TCP ports and get simple security-focused explanations.")

# Sidebar controls for scan and explanation settings.
with st.sidebar:
    st.header("Scan Settings")
    target = st.text_input("Target IP or Hostname", value="scanme.nmap.org")
    start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1, step=1)
    end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1024, step=1)
    timeout = st.slider("Timeout (seconds)", min_value=0.1, max_value=2.0, value=0.5, step=0.1, help="Maximum time to wait for a connection attempt on each port. If exceeded, port marked as closed or filtered.")
    max_workers = st.slider("Max Worker Threads", min_value=10, max_value=500, value=100, step=10,help="Controls how many ports are scanned at the same time. Higher values can make scans faster, but may use more system and network resources.")

    st.divider()
    st.header("Explanation Settings")
    use_ai = st.checkbox("Use Hugging Face AI explanation if available", value=True)

     # Show whether AI mode can be used.
    if has_hf_token():
        st.success("HF_TOKEN detected. AI mode is available.")
    else:
        st.info("HF_TOKEN not found. The app will use built-in explanations.")

    current_model = os.getenv("HF_MODEL", "Qwen/Qwen2.5-7B-Instruct")
    st.caption(f"Model setting: {current_model}")

scan_button = st.button("Start Scan")

# Start the scan only after basic input checks.
if scan_button:
    if not target.strip():
        st.error("Please enter a target IP address or hostname.")
    elif start_port > end_port:
        st.error("Start Port cannot be greater than End Port.")
    else:
        try:
            # Resolve target before scanning
            resolved_ip = resolve_target(target)
            st.info(f"Resolved target: {target} → {resolved_ip}")

            with st.spinner("Scanning ports..."):
                total_ports = int(end_port) - int(start_port) + 1
                progress_bar = st.progress(0)
                progress_text = st.empty()

                # Update live scan progress in the UI.
                def update_progress(completed, total):
                    percent = int((completed / total) * 100)
                    progress_bar.progress(percent)
                    progress_text.text(f"Scanning progress: {completed}/{total} ports checked ({percent}%)")

                raw_results = scan_port_range(
                    target=resolved_ip,
                    start_port=int(start_port),
                    end_port=int(end_port),
                    timeout=float(timeout),
                    max_workers=int(max_workers),
                    progress_callback=update_progress,
                )

                progress_bar.progress(100)
                progress_text.text(f"Scan complete: {total_ports}/{total_ports} ports checked (100%)")

            st.subheader("Scan Results")

            if raw_results:
                # Build report and enrich results for display
                report_text, report_mode, enriched_results = get_explanation_report(
                    raw_results=raw_results,
                    target_name=target,
                    resolved_ip=resolved_ip,
                    use_ai=use_ai,
                )

                st.success(f"Scan complete. Found {len(enriched_results)} open port(s).")

                table_data = []
                for item in enriched_results:
                    table_data.append(
                        {
                            "Port": item["port"],
                            "Service": item["service"],
                            "State": item["state"],
                            "Risk": item["risk"],
                        }
                    )

                df = pd.DataFrame(table_data)
                st.dataframe(df, use_container_width=True)

                st.subheader("Detailed Explanations")
                for item in enriched_results:
                    with st.expander(f"Port {item['port']} - {item['service']} ({item['risk']} Risk)"):
                        st.write(f"**State:** {item['state']}")
                        st.write(f"**Explanation:** {item['explanation']}")
                        st.write(f"**Recommendation:** {item['recommendation']}")

                st.subheader("Generated Report")

                # Adjust download name based on the report source
                if report_mode == "ai":
                    st.success("This report was generated using Hugging Face AI.")
                    download_name = "ai_scan_report.txt"
                else:
                    st.info("This report uses the built-in explanation system.")
                    download_name = "scan_report.txt"

                st.text_area("Report Output", report_text, height=320)

                st.download_button(
                    label="Download Report",
                    data=report_text,
                    file_name=download_name,
                    mime="text/plain",
                )

            else:
                st.warning("No open ports found in the selected range.")

        # Show error message if scan fails.
        except Exception as error:
            st.error(f"An error occurred: {error}")