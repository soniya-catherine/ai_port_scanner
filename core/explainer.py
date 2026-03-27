import json
import os
from typing import List, Dict, Tuple
from core.port_data import PORT_EXPLANATIONS
from huggingface_hub import InferenceClient
from dotenv import load_dotenv
load_dotenv()

DEFAULT_MODEL = os.getenv("HF_MODEL", "Qwen/Qwen2.5-7B-Instruct")


def get_risk_level(port: int, service: str) -> str:
    high_risk_ports = {21, 23, 3389, 445, 1433, 1521, 3306, 5432, 5900, 6379}
    medium_risk_ports = {22, 25, 53, 80, 110, 123, 139, 143, 161, 389, 443, 587, 993, 995, 8080, 8443}

    if port in high_risk_ports:
        return "High"
    if port in medium_risk_ports:
        return "Medium"
    return "Low"


def explain_port_result(port: int, service: str) -> str:
    if port in PORT_EXPLANATIONS:
        return f"Port {port} is open. {PORT_EXPLANATIONS[port]}"
    
    if service != "Unknown":
        return f"Port {port} is open. It is commonly associated with {service}."
    
    return f"Port {port} is open, but it is not in the common service list. It should be reviewed further."

def get_recommendation(port: int, service: str) -> str:
    if port in {21, 23, 69}:
        return "Avoid exposing this service publicly. Replace it with a more secure alternative if possible."
    elif port in {22, 3389, 5900}:
        return "Allow access only to trusted users or internal IP addresses, and use strong authentication."
    elif port in {3306, 5432, 6379, 1433, 1521}:
        return "Database services should usually not be directly exposed to the public internet."
    elif port in {80, 443, 8080, 8443}:
        return "Verify that the web service is intended to be public and keep the application patched and properly configured."
    elif port in {445, 139, 137, 138}:
        return "Restrict file-sharing related services to trusted networks wherever possible."
    elif port in {25, 587, 110, 143, 993, 995}:
        return "Make sure mail services are intentionally exposed and protected with proper authentication and encryption."
    elif port in {53, 67, 68, 123, 161, 389}:
        return "Confirm that this infrastructure service is expected to be reachable and limited to the right network scope."
    else:
        return "Review whether this open port is necessary. If not, close it or restrict access."


def enrich_results(results: List[Dict]) -> List[Dict]:
    enriched = []

    for item in results:
        port = item["port"]
        service = item["service"]

        enriched_item = {
            "port": port,
            "service": service,
            "state": item["state"],
            "risk": get_risk_level(port, service),
            "explanation": explain_port_result(port, service),
            "recommendation": get_recommendation(port, service),
        }

        enriched.append(enriched_item)

    return enriched


def build_summary(results: List[Dict], target_label: str = "the target") -> str:
    if not results:
        return f"No open ports were found for {target_label} in the selected range."

    high_count = sum(1 for item in results if item["risk"] == "High")
    medium_count = sum(1 for item in results if item["risk"] == "Medium")
    low_count = sum(1 for item in results if item["risk"] == "Low")

    lines = []
    lines.append("Port Scan Summary")
    lines.append(f"Target: {target_label}")
    lines.append(f"Total open ports found: {len(results)}")
    lines.append(f"High risk ports: {high_count}")
    lines.append(f"Medium risk ports: {medium_count}")
    lines.append(f"Low risk ports: {low_count}")
    lines.append("")
    lines.append("Detailed findings:")

    for item in results:
        lines.append(
            f"- Port {item['port']} ({item['service']}) | Risk: {item['risk']} | "
            f"{item['explanation']} Recommendation: {item['recommendation']}"
        )

    return "\n".join(lines)


def has_hf_token() -> bool:
    token = os.getenv("HF_TOKEN", "").strip()
    return bool(token)


def build_ai_messages(results: List[Dict], target_name: str, resolved_ip: str) -> List[Dict]:
    prompt_data = []

    for item in results:
        prompt_data.append(
            {
                "port": item["port"],
                "service": item["service"],
                "state": item["state"],
                "risk": item["risk"],
                "baseline_explanation": item["explanation"],
                "baseline_recommendation": item["recommendation"],
            }
        )

    system_message = (
        "You are a cybersecurity teaching assistant. "
        "Explain port scan results in very simple language for a beginner. "
        "Be accurate, practical, and concise. "
        "Do not claim a service is definitely running; say it usually suggests or commonly indicates that service. "
        "Organize the answer with: "
        "1) a short overall summary, "
        "2) one bullet per open port with what it may indicate, risk level, and recommendation, "
        "3) a short closing note. "
        "Do not use fear-based language."
    )

    user_message = (
        f"Target entered by user: {target_name}\n"
        f"Resolved IP: {resolved_ip}\n"
        f"Open port findings:\n{json.dumps(prompt_data, indent=2)}\n\n"
        "Please explain these results for a beginner."
    )

    return [
        {"role": "system", "content": system_message},
        {"role": "user", "content": user_message},
    ]


def generate_ai_explanation(
    results: List[Dict],
    target_name: str,
    resolved_ip: str,
) -> str:
    token = os.getenv("HF_TOKEN", "").strip()

    if not token:
        raise RuntimeError("HF_TOKEN not found.")

    client = InferenceClient(
        provider="auto",
        api_key=token,
    )

    messages = build_ai_messages(results, target_name, resolved_ip)

    completion = client.chat_completion(
        model=DEFAULT_MODEL,
        messages=messages,
        max_tokens=700,
        temperature=0.3,
    )

    return completion.choices[0].message.content.strip()


def get_explanation_report(
    raw_results: List[Dict],
    target_name: str,
    resolved_ip: str,
    use_ai: bool = True,
) -> Tuple[str, str, List[Dict]]:
    enriched_results = enrich_results(raw_results)

    if not enriched_results:
        report = build_summary(enriched_results, target_label=f"{target_name} ({resolved_ip})")
        return report, "fallback", enriched_results

    if not use_ai:
        report = build_summary(enriched_results, target_label=f"{target_name} ({resolved_ip})")
        return report, "fallback", enriched_results

    if not has_hf_token():
        report = build_summary(enriched_results, target_label=f"{target_name} ({resolved_ip})")
        return report, "fallback", enriched_results

    try:
        report = generate_ai_explanation(
            results=enriched_results,
            target_name=target_name,
            resolved_ip=resolved_ip,
        )
        return report, "ai", enriched_results
    except Exception:
        report = build_summary(enriched_results, target_label=f"{target_name} ({resolved_ip})")
        return report, "fallback", enriched_results