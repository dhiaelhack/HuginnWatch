import streamlit as st
import requests

API_URL = "http://127.0.0.1:8000/api/v1"
st.set_page_config(page_title="🦉 HuginnWatch", layout="wide")

# -------------------------------
# Session state
# -------------------------------
if "access_token" not in st.session_state:
    st.session_state.access_token = None
if "username" not in st.session_state:
    st.session_state.username = None

# -------------------------------
# Helper: API request with auth
# -------------------------------
def api_request(method, endpoint, **kwargs):
    headers = kwargs.pop("headers", {})
    if st.session_state.access_token:
        headers["Authorization"] = f"Bearer {st.session_state.access_token}"
    try:
        resp = requests.request(method, f"{API_URL}{endpoint}", headers=headers, **kwargs)
        if resp.status_code == 401:
            st.error("Unauthorized. Please log in again.")
        return resp
    except Exception as e:
        st.error(f"⚠️ Cannot contact backend: {e}")
        return None

# -------------------------------
# Header
# -------------------------------
st.markdown(
    """
    <div style='background-color:#1B1B1B;padding:25px;border-radius:10px;text-align:center'>
        <h1 style='color:#F4C430;font-size:48px;'>🦉 HuginnWatch</h1>
        <h4 style='color:#E0E0E0;'>Your Raven of Cyber Vigilance</h4>
        <p style='color:#AAAAAA;font-size:14px;'>Monitoring servers like Huginn watches Midgard</p>
    </div>
    """,
    unsafe_allow_html=True
)

# -------------------------------
# Login / Signup
# -------------------------------
def login_page():
    st.title("🔐 Enter the Cyber Realm")
    choice = st.radio("Choose Action:", ["Login", "Signup"])
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button(choice):
        if choice == "Signup":
            resp = api_request("POST", "/signup/", json={"username": username, "password": password})
            if resp and resp.status_code == 201:
                st.success("✅ User created! Please log in.")
                st.stop()
            else:
                try:
                    st.error(resp.json().get("error", "Signup failed"))
                except Exception:
                    st.error("Signup failed")
        else:
            resp = requests.post(f"{API_URL}/token/", json={"username": username, "password": password})
            if resp.status_code == 200:
                tokens = resp.json()
                st.session_state.access_token = tokens["access"]
                st.session_state.username = username
                st.stop()  # Streamlit will rerun automatically
            else:
                st.error("❌ Login failed")

# -------------------------------
# Dashboard
# -------------------------------
def dashboard():
    st.sidebar.title(f"🦉 {st.session_state.username}'s Nest")
    if st.sidebar.button("Logout"):
        st.session_state.access_token = None
        st.session_state.username = None
        st.stop()

    st.title("📡 HuginnWatch Dashboard")
    st.markdown("Huginn is soaring over your network… keeping watch on every server.")

    # Add Server Form (Sidebar)
    st.sidebar.subheader("🌐 Explore New Server")
    with st.sidebar.form("add_server_form"):
        name = st.text_input("Server Name")
        ip = st.text_input("IP Address")
        submit = st.form_submit_button("Send Huginn")
        if submit:
            resp = api_request("POST", "/servers/add/", json={"name": name, "ip_address": ip})
            if resp and resp.status_code == 201:
                st.success("✅ Server added and Huginn has started scanning!")
                st.stop()
            else:
                try:
                    st.error(resp.json().get("error", "Error adding server."))
                except Exception:
                    st.error("Error adding server.")

    # List Servers
    resp = api_request("GET", "/servers/")
    if resp and resp.status_code == 200:
        servers = resp.json()
        st.subheader("🖥️ Your Servers")

        if servers:
            # Multi-select for deletion
            selected_ids = st.multiselect(
                "Select servers to delete:",
                options=[s["id"] for s in servers],
                format_func=lambda x: next(s["name"] for s in servers if s["id"] == x)
            )

            if st.button("🗑️ Delete Selected Servers"):
                if selected_ids:
                    del_resp = api_request("POST", "/servers/delete/", json={"ids": selected_ids})
                    if del_resp and del_resp.status_code == 200:
                        st.success(del_resp.json().get("message"))
                        st.stop()  # Refresh UI
                    else:
                        try:
                            st.error(del_resp.json().get("error", "Error deleting servers."))
                        except Exception:
                            st.error("Error deleting servers.")
                else:
                    st.warning("Please select at least one server to delete.")

            st.markdown("---")

        # Show each server in expander
        for s in servers:
            with st.expander(f"🦉 {s['name']} ({s['ip_address']})"):
                st.markdown(f"**Added on:** {s['added_on']}")
                st.markdown(f"**Last Scan:** {s.get('last_scan_date', 'Never')}")
                st.markdown("**Scan Result:**")
                st.code(s.get("last_scan_ports", "No scan results yet"), language="text")

                cols = st.columns(2)
                with cols[0]:
                    # Re-scan button
                    if st.button(f"🦅 Let Huginn Fly (Scan)", key=f"scan_{s['id']}"):
                        with st.spinner("🦉 Huginn is scanning your server…"):
                            scan_resp = api_request("POST", f"/servers/{s['id']}/scan/")
                        if scan_resp and scan_resp.status_code == 200:
                            detail = scan_resp.json()
                            st.success("✅ Scan completed. Huginn returned with intel!")
                            st.write(f"Open Ports: {detail['ports']}")
                            st.write(f"Vulnerabilities Found: {detail['vulnerability_count']}")
                            for v in detail.get("vulnerabilities", []):
                                st.warning(f"⚠️ {v['service']} ({v['port']}) - {v['message']}")
                                if v.get("nvd"):
                                    for cve in v["nvd"]:
                                        st.markdown(f"📜 **Intel:** {cve['id']}")
                                        st.markdown(f"Severity: {cve.get('severity','UNKNOWN')}")
                                        st.write(cve["description"])
                                        st.markdown("---")
                        else:
                            st.error("❌ Scan failed.")

                with cols[1]:
                    # AI Analysis button
                    if st.button("🤖 Generate AI Analysis", key=f"ai_{s['id']}"):
                        with st.spinner("🤖 Analyzing scan results…"):
                            ai_resp = api_request("POST", f"/servers/{s['id']}/ai/analyze/")
                        if ai_resp and ai_resp.status_code == 200:
                            data = ai_resp.json()
                            used = "OpenAI" if data.get("used") == "openai" else "Local"
                            st.info(f"AI Source: {used} • Scan date: {data.get('scan_date','')}")
                            st.markdown(data.get("analysis", ""))
                        else:
                            try:
                                st.error(ai_resp.json().get("error", "AI analysis failed."))
                            except Exception:
                                st.error("AI analysis failed.")
    else:
        st.error("⚠️ Failed to load servers.")

# -------------------------------
# Main
# -------------------------------
if st.session_state.access_token:
    dashboard()
else:
    login_page()
