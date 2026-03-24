import streamlit as st

from scanner import resolve_target, scan_port_range
from explainer import build_summary

# Configure the Streamlit page settings
st.set_page_config(page_title="AI Port Scanner", page_icon="assets/favicon.png", layout="wide")

# Display the app title and description
st.title("AI-Assisted Port Scanner")
st.write("Scan a target host for open TCP ports and get simple explanations for the results.")

# Sidebar inputs for scan configuration
with st.sidebar:
    st.header("Scan Settings")
    target = st.text_input("Target IP or Hostname", value="scanme.nmap.org")
    start_port = st.number_input("Start Port", min_value=1, max_value=65535, value=1, step=1)
    end_port = st.number_input("End Port", min_value=1, max_value=65535, value=1024, step=1)
    timeout = st.slider("Timeout (seconds)", min_value=0.1, max_value=2.0, value=0.5, step=0.1)
    max_workers = st.slider("Max Worker Threads", min_value=10, max_value=300, value=100, step=10)

# Button to start the scan
scan_button = st.button("Start Scan")

if scan_button:
    # Validate selected port range
    if start_port > end_port:
        st.error("Start Port cannot be greater than End Port.")
    else:
        try:
            # Resolve target hostname to an IP address
            resolved_ip = resolve_target(target)
            st.info(f"Resolved target: {target} → {resolved_ip}")

            # Run the port scan with a loading spinner
            with st.spinner("Scanning ports..."):
                results = scan_port_range(
                    target=resolved_ip,
                    start_port=int(start_port),
                    end_port=int(end_port),
                    timeout=float(timeout),
                    max_workers=int(max_workers)
                )

            st.subheader("Scan Results")

            if results:
                # Show successful scan results and explanations
                st.success(f"Scan complete. Found {len(results)} open port(s).")
                st.json(results)

                summary = build_summary(results)

                st.subheader("Explanation")
                st.text(summary)
            else:
                # Show a warning if no open ports are found
                st.warning("No open ports found in the selected range.")

        except Exception as error:
            # Display any runtime errors to the user
            st.error(f"An error occurred: {error}")