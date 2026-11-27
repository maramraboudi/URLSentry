import json
import os
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import urlopen


API_URL = "http://127.0.0.1:8000"
FRONTEND_URL = "http://127.0.0.1:8501"


def wait_for_api(process, timeout=30):
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("The API server exited before becoming ready.")

        try:
            with urlopen(f"{API_URL}/", timeout=1) as response:
                info = json.loads(response.read().decode("utf-8"))
                if info.get("application") == "URLSentry":
                    return
        except (URLError, TimeoutError, json.JSONDecodeError):
            time.sleep(0.5)

    raise RuntimeError(f"The API server did not become ready at {API_URL}.")


def stop_process(process):
    if process is None or process.poll() is not None:
        return

    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def main():
    environment = os.environ.copy()
    environment["URLSENTRY_API_URL"] = API_URL

    backend = None
    frontend = None

    try:
        backend = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                "8000",
            ],
            env=environment,
        )
        wait_for_api(backend)

        frontend = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                "frontend/app.py",
                "--server.address",
                "127.0.0.1",
                "--server.port",
                "8501",
                "--server.headless",
                "true",
                "--browser.gatherUsageStats",
                "false",
            ],
            env=environment,
        )

        print(f"URLSentry frontend: {FRONTEND_URL}")
        print(f"URLSentry API:      {API_URL}")
        print(f"API documentation:  {API_URL}/docs")
        print("Press Ctrl+C to stop both servers.")

        while backend.poll() is None and frontend.poll() is None:
            time.sleep(0.5)

        if backend.poll() is not None:
            raise RuntimeError("The API server stopped unexpectedly.")
        raise RuntimeError("The Streamlit frontend stopped unexpectedly.")
    except KeyboardInterrupt:
        print("\nStopping URLSentry...")
    finally:
        stop_process(frontend)
        stop_process(backend)


if __name__ == "__main__":
    main()
