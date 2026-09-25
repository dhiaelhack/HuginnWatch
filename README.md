# HuginnWatch

HuginnWatch is a small server inventory and network reconnaissance project. It combines a Django REST API with a Streamlit dashboard to register servers, run Nmap service scans, keep scan history, look up related CVEs through the NVD API, and summarize findings with optional OpenAI powered analysis.

> **Use responsibly:** Only scan systems you own or have explicit permission to assess. Nmap scans send traffic to the target and may be logged or disrupt fragile services. HuginnWatch is a learning project, not a hardened production security scanner.

## Features

- Account signup and JWT login
- Per-user server inventory
- TCP connect scans with Nmap service detection (`-sT -Pn -sV`)
- Stored scan output and vulnerability findings
- NVD CVE lookup for detected services
- Rule based analysis, with optional OpenAI analysis when configured
- Streamlit dashboard for managing servers and reviewing results

## Architecture

The Django application provides the API and accesses a MySQL database. The Streamlit UI in `app.py` calls the API at `http://127.0.0.1:8000/api/v1`.

## Requirements

- Python 3.10 or newer
- MySQL server and a database/user for HuginnWatch
- Nmap installed and available on `PATH` on the machine running Django
- Python packages: Django, Django REST Framework, Simple JWT, `mysqlclient`, Requests, and Streamlit
- Optional: the OpenAI Python package and an `OPENAI_API_KEY` for AI generated analysis

## Setup

1. Clone the repository and enter the project directory:

   ```bash
   git clone https://github.com/dhiaelhack/HuginnWatch.git
   cd HuginnWatch
   ```

2. Create and activate a virtual environment, then install the dependencies:

   ```bash
   python -m venv .venv
   source .venv/bin/activate       # Windows: .venv\Scripts\activate
   pip install Django djangorestframework djangorestframework-simplejwt mysqlclient requests streamlit
   # Optional OpenAI analysis:
   pip install openai
   ```

3. Install Nmap using your operating system's package manager. Confirm that `nmap --version` works in the same environment used to run Django.

4. Create a MySQL database and user, then configure `DATABASES` in `HuginnWatch_project/settings.py` to match your local credentials. Before exposing the service, move `SECRET_KEY` and database credentials to environment variables, set `DEBUG = False`, and configure `ALLOWED_HOSTS`. The checked-in settings currently contain development values and should not be used for a public deployment.

5. Apply migrations and create an administrator account:

   ```bash
   python manage.py migrate
   python manage.py createsuperuser
   ```

6. Start the API in one terminal:

   ```bash
   python manage.py runserver
   ```

7. Start the dashboard in a second terminal:

   ```bash
   streamlit run app.py
   ```

Open the local URL printed by Streamlit (usually `http://localhost:8501`). Create an account in the dashboard, add a server by IP address, and review its scan results.

## API overview

All API routes are under `/api/v1/`. Signup and token issuance are public; inventory, scan, and analysis operations require a JWT access token in the `Authorization: Bearer <access-token>` header.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/signup/` | Create a user (`username`, `password`) |
| `POST` | `/token/` | Obtain access and refresh tokens |
| `POST` | `/token/refresh/` | Refresh an access token |
| `GET` | `/servers/` | List the authenticated user's servers |
| `POST` | `/servers/add/` | Add a server (`name`, `ip_address`) and start its first scan |
| `POST` | `/servers/delete/` | Delete selected servers (`ids`) |
| `POST` | `/servers/<id>/scan/` | Run a new scan |
| `POST` | `/servers/<id>/ai/analyze/` | Analyze the latest scan |

For AI analysis, set `OPENAI_API_KEY` in the Django process environment. Without it, the API uses its built-in rule based analysis. The dashboard's API URL is currently defined directly in `app.py`; change `API_URL` there if the backend runs elsewhere.

## Project layout

```text
HuginnWatch/             Django app, API views, models, migrations, templates
HuginnWatch_project/     Django project configuration
app.py                   Streamlit dashboard
manage.py                Django management entry point
```

## Current limitations

- Dependency versions are not pinned in a requirements file.
- Database settings and the Django secret key are currently hardcoded in the settings module; configure these securely before sharing or deployment.
- The dashboard expects the API at localhost by default.
- Scans run synchronously in the API request, so larger or slow scans can take time.
- NVD lookup depends on external network availability. Configure any API credentials outside source code before deployment.
