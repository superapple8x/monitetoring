# Network Monitoring Dashboard

## Project Overview
A user-friendly network monitoring dashboard that provides real-time network visibility, with a phased approach to integrating intelligent security threat detection capabilities.

## Phase 1: Core Monitoring Engine & Basic API
This phase focuses on establishing a reliable data collection pipeline from network interfaces to a persistent database, with a basic API for future frontend consumption.

## Setup (Non-Docker - Fedora Linux Example)

This guide provides instructions for setting up the project manually on a Fedora Linux system.

### Prerequisites
*   **Rust:** Version 1.70+ (or as specified in `rust_engine/Cargo.toml`). Install via [rustup](https://rustup.rs/).
*   **Python:** Version 3.9+. Ensure `pip` and `venv` are available (often included or installable via `python3-pip`, `python3-venv`).
*   **PostgreSQL:** Server and client. (e.g., `postgresql-server`, `postgresql`).
*   **Redis:** Server. (e.g., `redis`).
*   **libpcap development files:** For Rust packet capture (e.g., `libpcap-devel` on Fedora).
*   **Build Essentials:** `gcc` and other build tools might be needed for Python package dependencies. (e.g., `dnf groupinstall "Development Tools"` on Fedora).

### Installation Steps

**1. Clone the Repository**
   ```bash
   git clone <repository_url>
   cd network-monitoring-dashboard
   ```

**2. PostgreSQL Setup (Fedora)**
   a. Install PostgreSQL server and client:
      ```bash
      sudo dnf install postgresql-server postgresql
      ```
   b. Initialize the database cluster:
      ```bash
      sudo postgresql-setup --initdb
      ```
   c. Start and enable the PostgreSQL service:
      ```bash
      sudo systemctl start postgresql
      sudo systemctl enable postgresql
      ```
   d. Create the database and user:
      Switch to the `postgres` user:
      ```bash
      sudo -i -u postgres
      ```
      Open `psql`:
      ```bash
      psql
      ```
      Execute the following SQL commands:
      ```sql
      CREATE DATABASE netmonitordb;
      CREATE USER "user" WITH PASSWORD 'password'; -- Note the quotes around "user"
      GRANT ALL PRIVILEGES ON DATABASE netmonitordb TO "user";
      ALTER DATABASE netmonitordb OWNER TO "user";
      \q
      ```
      Exit from the `postgres` user shell:
      ```bash
      exit
      ```
   e. Configure password authentication (Edit `pg_hba.conf`):
      Find the `pg_hba.conf` file (usually `/var/lib/pgsql/data/pg_hba.conf` on Fedora). Show path with: `sudo -u postgres psql -c 'SHOW hba_file;'`
      Edit the file (e.g., `sudo nano /var/lib/pgsql/data/pg_hba.conf`).
      Change the following lines for IPv4 and IPv6 local connections from `ident` or `peer` to `md5`:
      ```
      # IPv4 local connections:
      host    all             all             127.0.0.1/32            md5
      # IPv6 local connections:
      host    all             all             ::1/128                 md5
      ```
      Reload PostgreSQL configuration:
      ```bash
      sudo systemctl reload postgresql
      ```

**3. Redis Setup (Fedora)**
   a. Install Redis:
      ```bash
      sudo dnf install redis
      ```
   b. Start and enable the Redis service:
      ```bash
      sudo systemctl start redis
      sudo systemctl enable redis
      ```
   c. Verify Redis is running:
      ```bash
      redis-cli ping
      ```
      (Should return `PONG`)

**4. Python API Setup**
   a. Navigate to the Python API directory:
      ```bash
      cd python_api/
      ```
   b. Create and activate a Python virtual environment:
      ```bash
      python -m venv venv
      source venv/bin/activate
      ```
   c. Install dependencies:
      ```bash
      pip install -r requirements.txt
      ```
   d. Create database tables (ensure PostgreSQL is running and configured):
      ```bash
      python -m app.create_db
      ```
      (Expect output like: `INFO:__main__:Database tables creation process completed.`)
   e. Run the Python API (ensure Redis is running):
      ```bash
      python -m app.main
      ```
      (The API will typically be available at `http://localhost:8000`)

**5. Rust Engine Setup & Execution**
   a. Navigate to the Rust engine directory:
      ```bash
      cd ../rust_engine/  # Assuming you are in python_api/
      # Or: cd <path_to_project>/network-monitoring-dashboard/rust_engine/
      ```
   b. Build the Rust engine:
      ```bash
      cargo build --release
      ```
   c. Navigate to the release executable:
      ```bash
      cd target/release/
      ```
   d. Run the Rust engine (requires sudo for packet capture):
      ```bash
      sudo ./rust_engine
      ```
      (The engine might prompt for interface selection or log its activity. Data should start flowing to the Python API via Redis.)

### Accessing Services
- Python API: `http://localhost:8000`
- API Documentation (Swagger UI): `http://localhost:8000/docs`

## Troubleshooting

*   **PostgreSQL: "Connection refused"**
    *   Ensure the PostgreSQL service is running: `sudo systemctl status postgresql`.
    *   Verify it's listening on `localhost:5432`.
*   **PostgreSQL: "FATAL: Ident authentication failed for user..."**
    *   Edit `pg_hba.conf` as described in the setup to use `md5` authentication for local connections. Ensure you reload PostgreSQL: `sudo systemctl reload postgresql`.
*   **PostgreSQL: "FATAL: password authentication failed for user..."**
    *   Ensure you created the user with the correct password (`'password'`) and that `pg_hba.conf` is set to `md5` for the connection type.
*   **Python: `ImportError: attempted relative import with no known parent package`**
    *   When running scripts like `create_db.py` or `main.py` from the `app` directory, run them as modules from the parent `python_api` directory.
        *   Example: `cd python_api/` then `python -m app.create_db` or `python -m app.main`.
*   **Rust Engine: Permission denied / No interfaces found**
    *   The Rust engine needs root privileges for raw packet capture. Run it with `sudo ./rust_engine`.
    *   Ensure `libpcap-devel` (or equivalent) is installed.
*   **Redis: Connection errors from Python API or Rust Engine**
    *   Ensure the Redis service is running: `sudo systemctl status redis`.
    *   Verify it's accessible on `localhost:6379` (or that `REDIS_URL` env var is set correctly if using a different location).

## Project Structure
network-monitoring-dashboard/
├── rust_engine/       # Packet capture and processing
│   ├── src/           # Rust source code
│   └── Cargo.toml     # Rust dependencies
├── python_api/        # Backend API and data storage
│   ├── app/           # Python source code (main.py, models.py, database.py, create_db.py)
│   ├── venv/          # Python virtual environment (auto-generated, in .gitignore)
│   └── requirements.txt # Python dependencies
└── README.md          # Project documentation