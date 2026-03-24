# Returns simple explanation for detected open port
def explain_port_result(port, service):
    if port == 22:
        return "Port 22 is open. This usually means SSH is running, which is used for secure remote login."
    elif port == 80:
        return "Port 80 is open. This usually means a web server is available over HTTP."
    elif port == 443:
        return "Port 443 is open. This usually means a secure web server is available over HTTPS."
    elif port == 3389:
        return "Port 3389 is open. This usually means Remote Desktop is enabled, which should not be exposed carelessly."
    elif port == 3306:
        return "Port 3306 is open. This usually means a MySQL database service may be running."
    elif service != "Unknown":
        return f"Port {port} is open. It is commonly associated with {service}."
    else:
        return f"Port {port} is open, but it is not in the common service list. It needs further investigation."

# Builds a readable summary of all scan results
def build_summary(results):
    if not results:
        return "No open ports were found in the selected range."

    lines = []
    lines.append(f"Total open ports found: {len(results)}.")
    lines.append("Here is a simple explanation of the findings:")

    # Add one explanation line for each open port.
    for item in results:
        lines.append(
            f"- Port {item['port']} ({item['service']}): {explain_port_result(item['port'], item['service'])}"
        )

    return "\n".join(lines)