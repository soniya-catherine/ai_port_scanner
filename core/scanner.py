import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.services import COMMON_PORTS

# Resolves hostname to its IP address
def resolve_target(target):
    return socket.gethostbyname(target)

# Scans a single TCP port on the target host
def scan_single_port(target, port, timeout=0.5):
    try:
        # Create a TCP socket for the connection attempt
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))

            # Return port details if the connection succeeds
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                return {
                    "port": port,
                    "service": service,
                    "state": "open"
                }
            
    # Return None if the scan fails or an error occurs
    except Exception:
        return None

    return None

# Scans a range of ports using multiple threads
def scan_port_range(target, start_port, end_port, timeout=0.5, max_workers=100, progress_callback=None):
    results = []
    total_ports = end_port - start_port + 1
    completed_ports = 0


    # Create a thread pool to scan ports concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_single_port, target, port, timeout): port
            for port in range(start_port, end_port + 1)
        }

        # Collect results as each scan completes
        for future in as_completed(future_to_port):
            completed_ports += 1

            result = future.result()
            if result:
                results.append(result)

            if progress_callback:
                progress_callback(completed_ports, total_ports)

    # Sort results by port number before returning
    results.sort(key=lambda item: item["port"])
    return results