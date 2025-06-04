# Phase 1 Verification Plan (Non-Docker)

**I. Finished Part:**

1.  **Rust Engine Compilation:**
    *   **Status:** COMPLETED
    *   **Details:** The `rust_engine` located in [`network-monitoring-dashboard/rust_engine/`](network-monitoring-dashboard/rust_engine/) now compiles successfully. The executable can be found at `network-monitoring-dashboard/rust_engine/target/release/rust_engine`.

---

**II. Next Steps to be Taken:**

1.  **Setup and Run Prerequisite Services (Redis & PostgreSQL):**
    *   **Goal:** Ensure Redis and PostgreSQL are running and accessible.
    *   **Action (Redis):**
        *   Start a Redis instance. If `redis-server` is installed, run `redis-server`.
        *   **Confirmation:** Ensure it's running (e.g., `redis-cli ping` should return `PONG`).
        *   **Note:** The Python API will try to connect to `localhost:6379` by default. If Redis is elsewhere, set the `REDIS_URL` environment variable (default referenced in [`network-monitoring-dashboard/python_api/app/main.py`](network-monitoring-dashboard/python_api/app/main.py:22)).
    *   **Action (PostgreSQL):**
        *   Start a PostgreSQL instance.
        *   Create the database: `netmonitordb`.
        *   Create user `user` with password `password` and grant privileges to `netmonitordb`, or ensure the connection string specified in the `DATABASE_URL` environment variable is used. The default is `postgresql://user:password@localhost:5432/netmonitordb` (default referenced in [`network-monitoring-dashboard/python_api/app/main.py`](network-monitoring-dashboard/python_api/app/main.py:23)).
        *   **Confirmation:** Ensure you can connect to it (e.g., using `psql -U user -d netmonitordb -h localhost`).
        *   **Table Creation:** This will be handled by the `app/create_db.py` script (see step 2.7 below).

2.  **Prepare and Run the Python API:**
    *   **Goal:** Get the Python backend service running, with database tables created by a separate script.
    *   **Action:**
        1.  Navigate to the Python API directory: `cd network-monitoring-dashboard/python_api`
        2.  Create a virtual environment (recommended): `python -m venv venv`
        3.  Activate the virtual environment: `source venv/bin/activate` (Linux/macOS) or `venv\Scripts\activate` (Windows).
        4.  Install dependencies: `pip install -r requirements.txt` (from [`network-monitoring-dashboard/python_api/requirements.txt`](network-monitoring-dashboard/python_api/requirements.txt)).
        5.  **Refactor for Shared Database/Model Definitions:**
            *   Create [`network-monitoring-dashboard/python_api/app/database.py`](network-monitoring-dashboard/python_api/app/database.py). This file will define `DATABASE_URL`, `engine`, `SessionLocal`, and `Base = declarative_base()`.
            *   Create [`network-monitoring-dashboard/python_api/app/models.py`](network-monitoring-dashboard/python_api/app/models.py). This file will import `Base` from `app.database` and define the `Device(Base)` and `NetworkInterfaceMetric(Base)` SQLAlchemy models.
            *   Update [`network-monitoring-dashboard/python_api/app/main.py`](network-monitoring-dashboard/python_api/app/main.py:1) to import necessary components from `app.database` and `app.models`, removing local definitions. The `if __name__ == "__main__":` block should be simplified to just run the FastAPI app using Uvicorn.
        6.  **Create `app/create_db.py`:**
            *   Create [`network-monitoring-dashboard/python_api/app/create_db.py`](network-monitoring-dashboard/python_api/app/create_db.py). This script will import `engine` and `Base` from `app.database`, and models from `app.models`. It will contain a function `init_db()` that calls `Base.metadata.create_all(bind=engine)` and will be executed when the script is run directly.
        7.  **Create Database Tables:**
            *   Run the script: `python app/create_db.py`
        8.  Run the API: `python app/main.py` (this will likely start Uvicorn on `http://localhost:8000`).
            *   Ensure `DATABASE_URL` and `REDIS_URL` environment variables are correctly set if not using defaults.
    *   **Verification:**
        *   Check logs from `app/create_db.py` for table creation confirmation.
        *   Check Python API logs for successful startup, connection to Redis, and connection to PostgreSQL.
        *   Look for messages about subscribing to Redis channels (`network_metrics_channel`, `device_discovery_channel`).
        *   Connect to PostgreSQL and verify that the `devices` and `network_interface_metrics` tables exist.

3.  **Run the Rust Packet Capture Engine:**
    *   **Goal:** Start capturing network data and sending it to Redis.
    *   **Action:**
        1.  Navigate to the Rust engine's executable directory: `cd network-monitoring-dashboard/rust_engine/target/release/`
        2.  Run the engine: `./rust_engine`.
            *   **Permissions:** This will likely require `sudo` (e.g., `sudo ./rust_engine`) for raw socket access.
            *   **Interface Selection:** The engine might prompt for a network interface or try to pick one.
            *   **Redis Connection:** Ensure it can connect to the Redis instance.
    *   **Verification (Rust Engine Logs):**
        *   Successful interface selection/binding.
        *   Packet capture starting.
        *   ARP packets processed, devices discovered/updated.
        *   Metrics aggregated.
        *   Messages about publishing to Redis channels.

4.  **System-Wide Verification & Testing:**
    *   **Goal:** Confirm data flows correctly through the entire system.
    *   **Action (Redis Monitoring - Optional but Recommended):**
        *   If `redis-cli` is installed, run `redis-cli MONITOR`.
        *   Observe `PUBLISH` commands to `network_metrics_channel` and `device_discovery_channel`.
    *   **Action (Python API Logs):**
        *   Observe logs for receiving messages from Redis, parsing data, and storing to PostgreSQL.
    *   **Action (Database Verification):**
        *   Connect to PostgreSQL and query `devices` and `network_interface_metrics` tables.
    *   **Action (API Endpoint Testing):**
        *   Use `curl` or Postman to test API endpoints like `/api/v1/devices` and `/api/v1/metrics/interfaces/...`.

5.  **Review and Update README:**
    *   **Goal:** Document the non-Docker setup.
    *   **Action:** Update [`network-monitoring-dashboard/README.md`](network-monitoring-dashboard/README.md) with instructions for prerequisites, Python API refactoring and setup (including `app/create_db.py`), Rust engine execution, environment variables, and troubleshooting.

---

**Python API Setup Diagram (Non-Docker):**

```mermaid
graph TD
    A[Start Python API Setup] --> B{PostgreSQL Running?};
    B -- No --> C[Start PostgreSQL Instance];
    C --> D[Create 'netmonitordb' Database];
    B -- Yes --> D;
    D --> E{Redis Running?};
    E -- No --> F[Start Redis Instance];
    F --> G[Navigate to network-monitoring-dashboard/python_api];
    E -- Yes --> G;
    G --> H[Setup Python Venv & Activate];
    H --> I[pip install -r requirements.txt];
    I --> J[Refactor: Create app/database.py & app/models.py, Update app/main.py imports];
    J --> K[Create app/create_db.py with init_db() function];
    K --> L[Run: python app/create_db.py to create tables];
    L --> M[Set DATABASE_URL & REDIS_URL env vars if non-default];
    M --> N[Run API: python app/main.py];
    N --> O[Verify API Logs & DB Table Existence];
    O --> P[End Python API Setup];