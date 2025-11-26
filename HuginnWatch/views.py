from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from django.contrib.auth.models import User
from .models import Server, ScanResult
from django.utils.timezone import now
import subprocess
import requests
from rest_framework import status
import os

# Optional: OpenAI (used if OPENAI_API_KEY is set)
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

NVD_API_KEY = "447dd0ae-c980-4cce-a348-864baedc5988"

# -------------------------------
# API Root
# -------------------------------
@api_view(["GET"])
@permission_classes([AllowAny])
def api_root(request):
    return Response({
        "message": "Welcome to HuginnWatch API. Use /api/ endpoints to interact."
    })

# -------------------------------
# User Signup
# -------------------------------
@api_view(["POST"])
@permission_classes([AllowAny])
def api_signup(request):
    data = request.data
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return Response({"error": "Username and password required"}, status=400)
    if User.objects.filter(username=username).exists():
        return Response({"error": "Username already exists"}, status=409)
    User.objects.create_user(username=username, password=password)
    return Response({"message": "User created successfully"}, status=201)

# -------------------------------
# List Servers
# -------------------------------
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def api_list_servers(request):
    servers = Server.objects.filter(user=request.user)
    data = []
    for s in servers:
        last_scan = ScanResult.objects.filter(server=s).order_by("-scan_date").first()
        data.append({
            "id": s.id,
            "name": s.name,
            "ip_address": s.ip_address,
            "added_on": s.added_on.strftime("%Y-%m-%d %H:%M"),
            "last_scan_ports": last_scan.ports if last_scan else "No scan yet",
            "last_scan_date": last_scan.scan_date.strftime("%Y-%m-%d %H:%M") if last_scan else "N/A",
            "vulnerabilities": last_scan.vulnerabilities_json if last_scan else []
        })
    return Response(data)

# -------------------------------
# Add Server
# -------------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def api_add_server(request):
    ip = request.data.get("ip_address")
    name = request.data.get("name")
    if not ip or not name:
        return Response({"error": "Missing 'ip_address' or 'name'"}, status=400)
    server = Server.objects.create(user=request.user, ip_address=ip, name=name)
    # Trigger first scan
    scan_result = perform_scan(server)
    return Response({
        "message": "Server added and initial scan done",
        "server_id": server.id,
        "scan": scan_result
    }, status=201)

# -------------------------------
# Trigger Scan
# -------------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def api_trigger_scan(request, server_id):
    try:
        server = Server.objects.get(id=server_id, user=request.user)
        scan_result = perform_scan(server)
        return Response(scan_result)
    except Server.DoesNotExist:
        return Response({"error": "Server not found or access denied"}, status=404)

# -------------------------------
# Delete Servers (bulk or single)
# -------------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def api_delete_servers(request):
    ids = request.data.get("ids", [])
    if not ids:
        return Response({"error": "No server IDs provided"}, status=400)

    # Only delete servers owned by this user
    servers_to_delete = Server.objects.filter(user=request.user, id__in=ids)
    count = servers_to_delete.count()
    if count == 0:
        return Response({"error": "No matching servers found for this user"}, status=404)

    servers_to_delete.delete()
    return Response({"message": f"🗑️ Deleted {count} server(s)."}, status=200)

# -------------------------------
# AI: Analyze latest scan for a server
# -------------------------------
@api_view(["POST"])
@permission_classes([IsAuthenticated])
def api_ai_analyze_scan(request, server_id):
    """
    Generates a human-friendly analysis of the most recent scan for the given server.
    - Uses OpenAI if OPENAI_API_KEY env var is present and SDK available.
    - Otherwise falls back to a rule-based analyzer.
    """
    try:
        server = Server.objects.get(id=server_id, user=request.user)
    except Server.DoesNotExist:
        return Response({"error": "Server not found or access denied"}, status=404)

    last_scan = ScanResult.objects.filter(server=server).order_by("-scan_date").first()
    if not last_scan:
        return Response({"error": "No scans found for this server."}, status=404)

    scan_text = last_scan.ports or ""
    vulns = last_scan.vulnerabilities_json or []

    # Compose a compact context
    context = f"""Server: {server.name} ({server.ip_address})
Scan date: {last_scan.scan_date.strftime('%Y-%m-%d %H:%M')}
Open ports (parsed):
{scan_text}

Detected issues:
{vulns}
"""

    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if OPENAI_AVAILABLE and api_key:
        try:
            client = OpenAI(api_key=api_key)
            prompt = (
                "You are a security assistant. Read the scan context and produce:\n"
                "1) Overall risk (Low/Medium/High) with reasoning\n"
                "2) Key findings by port/service (bullet points)\n"
                "3) Concrete remediation steps (numbered)\n"
                "Keep it concise and actionable for a junior engineer. Context:\n\n"
                f"{context}"
            )
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.2,
                messages=[
                    {"role": "system", "content": "You write concise security assessments."},
                    {"role": "user", "content": prompt}
                ]
            )
            analysis = resp.choices[0].message.content
            return Response({
                "analysis": analysis,
                "used": "openai",
                "scan_date": last_scan.scan_date.strftime("%Y-%m-%d %H:%M"),
            }, status=200)
        except Exception as e:
            # If OpenAI fails, fall back to rule-based
            fallback = rule_based_analysis(scan_text, vulns)
            return Response({
                "analysis": fallback,
                "used": "fallback",
                "error_note": str(e)[:300],
                "scan_date": last_scan.scan_date.strftime("%Y-%m-%d %H:%M"),
            }, status=200)
    else:
        # No API key or SDK → rule-based
        analysis = rule_based_analysis(scan_text, vulns)
        return Response({
            "analysis": analysis,
            "used": "fallback",
            "scan_date": last_scan.scan_date.strftime("%Y-%m-%d %H:%M"),
        }, status=200)

# -------------------------------
# Helper: Perform Scan
# -------------------------------
def perform_scan(server):
    try:
        # Run nmap
        command = ["nmap", "-sT", "-Pn", "-sV", server.ip_address]
        result = subprocess.run(command, capture_output=True, text=True)
        raw_output = result.stdout
        ports = [line.strip() for line in raw_output.splitlines() if "/tcp" in line and "open" in line]
        if not ports:
            ports = ["No open TCP ports found."]
        ports_text = "\n".join(ports)

        # Analyze local vulnerabilities
        vulnerabilities = analyze_vulnerabilities(ports_text)

        # Fetch NVD info for each port/service
        for v in vulnerabilities:
            v["nvd"] = fetch_nvd_cves(v["service"])

        scan = ScanResult.objects.create(
            server=server,
            ports=ports_text,
            raw_output=raw_output,
            open_ports_count=len(ports),
            vulnerability_count=len(vulnerabilities),
            vulnerabilities_json=vulnerabilities,
            scan_date=now()
        )
        return {
            "message": "Scan complete",
            "scan_date": scan.scan_date.strftime("%Y-%m-%d %H:%M"),
            "ports": ports_text,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities
        }
    except Exception as e:
        return {"error": str(e)}

# -------------------------------
# Local vulnerability analysis
# -------------------------------
def analyze_vulnerabilities(ports_text):
    vulnerable_ports = {
        "21/tcp": "FTP server may be vulnerable to attacks.",
        "22/tcp": "SSH service detected, ensure strong passwords.",
        "23/tcp": "Telnet service detected — insecure protocol.",
        "3389/tcp": "RDP service detected — often targeted by attackers.",
    }
    issues = []
    for line in ports_text.splitlines():
        for port, msg in vulnerable_ports.items():
            if port in line:
                parts = line.split()
                service_name = parts[2] if len(parts) > 2 else port
                issues.append({"port": port, "service": service_name, "message": msg})
    return issues

# -------------------------------
# Fetch NVD CVEs
# -------------------------------
def fetch_nvd_cves(service_name):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keyword={service_name}&apiKey={NVD_API_KEY}"
    try:
        resp = requests.get(url, timeout=20)
        data = resp.json()
        cve_list = []
        for item in data.get("vulnerabilities", []):
            cve_list.append({
                "id": item["cve"]["id"],
                "description": item["cve"].get("descriptions", [{}])[0].get("value", ""),
                "severity": item["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
            })
        return cve_list
    except:
        return []

# -------------------------------
# Fallback AI: simple rule-based summary
# -------------------------------
def rule_based_analysis(ports_text: str, vulns_json):
    risk_score = 0
    bullets = []

    def add(msg, weight=1):
        nonlocal risk_score
        bullets.append(f"- {msg}")
        risk_score += weight

    # Ports-based heuristics
    lines = [l.lower() for l in ports_text.splitlines()]
    if any("23/tcp" in l for l in lines):
        add("Telnet (23) is open — insecure protocol; disable or replace with SSH.", 3)
    if any("3389/tcp" in l for l in lines):
        add("RDP (3389) exposed — restrict with VPN and strong MFA.", 3)
    if any("21/tcp" in l for l in lines):
        add("FTP (21) open — prefer SFTP/FTPS; enforce strong creds.", 2)
    if any("22/tcp" in l for l in lines):
        add("SSH (22) open — use key auth, disable root login, rate-limit.", 1)
    if any("80/tcp" in l for l in lines) and not any("443/tcp" in l for l in lines):
        add("HTTP (80) without HTTPS (443) — enable TLS and redirect to HTTPS.", 2)

    # CVE-based heuristics
    high = 0
    for v in (vulns_json or []):
        sev = str(v.get("severity", "")).upper()
        cve_id = v.get("id") or "CVE"
        if "HIGH" in sev or "CRITICAL" in sev:
            add(f"{cve_id} severity {sev} — prioritize patch/update.", 3)
            high += 1

    # Risk level
    if risk_score >= 6 or high >= 2:
        level = "High"
    elif risk_score >= 3 or high == 1:
        level = "Medium"
    else:
        level = "Low"

    recs = [
        "1) Patch services with known HIGH/CRITICAL CVEs immediately.",
        "2) Enforce MFA and strong, rotated credentials.",
        "3) Limit exposed services via firewall/VPN; close unused ports.",
        "4) Enable TLS and harden configs (SSH hardening, HTTP→HTTPS).",
        "5) Schedule regular scans and track deltas over time."
    ]

    return (
        f"**Overall Risk:** {level}\n\n"
        f"**Key Findings:**\n" + "\n".join(bullets or ["- No obvious risky services detected."]) + "\n\n"
        f"**Recommended Actions:**\n" + "\n".join(recs)
    )
