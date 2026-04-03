import json
import os
import platform
import re
import shutil
import subprocess
import threading
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen

from flask import Flask, has_request_context, jsonify, request, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge


REPO_ROOT = Path(__file__).resolve().parents[1]
# Match generate-sbom.ps1 (env TRIVY_IMAGE); pinned tag avoids flaky :latest resolution after fresh Docker installs.
TRIVY_IMAGE = os.environ.get("TRIVY_IMAGE", "aquasec/trivy:0.69.3")
GRYPE_IMAGE = os.environ.get("GRYPE_IMAGE", "anchore/grype:latest")
SBOM_DIR = REPO_ROOT / "sbom"
REPORT_DIR = REPO_ROOT / "reports"
STATIC_DIR = REPO_ROOT / "sbom_ui" / "static"
UPLOAD_DIR = REPO_ROOT / ".ui_uploads"
STAGE_NAMES = ["Build", "Generate", "Sign", "Scan", "Report"]

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB
LOCAL_RUNS = {}
LOCAL_RUNS_LOCK = threading.Lock()


def run_cmd(cmd):
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def run_cmd_stream(cmd, on_output=None):
    proc = subprocess.Popen(
        cmd,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        bufsize=1,
    )
    chunks = []
    try:
        if proc.stdout is not None:
            for line in proc.stdout:
                chunks.append(line)
                if on_output:
                    try:
                        on_output(line)
                    except Exception:
                        pass
        proc.wait()
    finally:
        if proc.stdout is not None:
            try:
                proc.stdout.close()
            except Exception:
                pass
    return proc.returncode, "".join(chunks)


def iso_duration_seconds(started_at, completed_at):
    try:
        if not started_at or not completed_at:
            return None
        s = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        e = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))
        return max(int((e - s).total_seconds()), 0)
    except Exception:
        return None


def parse_json(path):
    if not path.exists():
        return None
    try:
        raw = path.read_text(encoding="utf-8")
        try:
            return json.loads(raw)
        except Exception:
            # Some scanner CLIs may append warnings after JSON payload.
            # Recover by decoding the first JSON document found in the text.
            start_positions = [pos for pos in (raw.find("{"), raw.find("[")) if pos >= 0]
            if not start_positions:
                return None
            start = min(start_positions)
            obj, _ = json.JSONDecoder().raw_decode(raw[start:])
            return obj
    except Exception:
        return None


def parse_key_value_lines(text):
    values = {}
    for line in (text or "").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip().lower()] = value.strip()
    return values


def file_mtime_iso(path):
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
    except Exception:
        return None


def parse_trivy_db_meta(text):
    # Example debug line:
    # DB info schema=2 updated_at=... next_update=... downloaded_at=...
    m = re.search(
        r"DB info\s+schema=(\S+)\s+updated_at=(\S+)\s+next_update=(\S+)\s+downloaded_at=(\S+)",
        text or "",
    )
    if not m:
        return {}
    return {
        "schema": m.group(1),
        "updated_at": m.group(2),
        "next_update": m.group(3),
        "downloaded_at": m.group(4),
    }


def get_db_freshness():
    grype_status_path = REPORT_DIR / "grype-db-status.txt"
    grype_update_path = REPORT_DIR / "grype-db-update.txt"
    trivy_status_path = REPORT_DIR / "trivy-db-status.txt"
    trivy_update_path = REPORT_DIR / "trivy-db-update.txt"
    trivy_report_path = REPORT_DIR / "trivy-sbom-report.json"

    grype_text = grype_status_path.read_text(encoding="utf-8", errors="replace") if grype_status_path.exists() else ""
    grype_values = parse_key_value_lines(grype_text)

    trivy_text = trivy_status_path.read_text(encoding="utf-8", errors="replace") if trivy_status_path.exists() else ""
    trivy_meta = parse_trivy_db_meta(trivy_text)
    trivy_report = parse_json(trivy_report_path) or {}
    trivy_created = trivy_report.get("CreatedAt")

    return {
        "grype": {
            "status": grype_values.get("status") or "unknown",
            "built_at": grype_values.get("built"),
            "db_path": grype_values.get("path"),
            "schema": grype_values.get("schema"),
            "status_file_mtime": file_mtime_iso(grype_status_path) if grype_status_path.exists() else None,
            "update_file_mtime": file_mtime_iso(grype_update_path) if grype_update_path.exists() else None,
            "available": grype_status_path.exists(),
        },
        "trivy": {
            "schema": trivy_meta.get("schema"),
            "updated_at": trivy_meta.get("updated_at"),
            "next_update": trivy_meta.get("next_update"),
            "downloaded_at": trivy_meta.get("downloaded_at"),
            "scan_created_at": trivy_created,
            "status_file_mtime": file_mtime_iso(trivy_status_path) if trivy_status_path.exists() else None,
            "update_file_mtime": file_mtime_iso(trivy_update_path) if trivy_update_path.exists() else None,
            "available": trivy_status_path.exists() or trivy_report_path.exists(),
        },
    }


def get_latest_sbom_path():
    candidates = [
        SBOM_DIR / "sbom-source.enriched.json",
        SBOM_DIR / "sbom-build.enriched.json",
        SBOM_DIR / "sbom-image.enriched.json",
        SBOM_DIR / "sbom-source.json",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def ensure_dirs():
    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def normalize_path_for_script(path_value):
    if not path_value:
        return None
    try:
        p = Path(str(path_value)).expanduser()
        if not p.is_absolute():
            p = (REPO_ROOT / p).resolve()
        else:
            p = p.resolve()
        return os.path.relpath(str(p), str(REPO_ROOT))
    except Exception:
        return str(path_value)


def build_temp_metadata(app_name, source_path):
    app = (app_name or "custom-cpp-app").strip() or "custom-cpp-app"
    src = (source_path or "").strip()
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", app).strip("-").lower() or "custom-cpp-app"
    payload = {
        "name": app,
        "version": "1.0.0",
        "description": f"{app} (UI ad-hoc pipeline target)",
        "language": "C++",
        "author": "SBOM Mission Control UI",
        "repository": "",
        "build_system": "unknown",
        "entry_point": "main",
        "source_file": src or "src/main.cpp",
        "license": "MIT",
        "supplier": {
            "name": "Unknown",
            "url": [],
        },
        "purl": f"pkg:generic/{slug}@1.0.0",
    }
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    path = REPORT_DIR / f"tmp-app-metadata-{ts}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def run_generate_pipeline(body, log_callback=None):
    ensure_dirs()
    body = body or {}

    source_path = body.get("source_path")
    if not source_path:
        return {
            "status": "error",
            "message": "Missing source_path",
            "exit_code": 1
        }

    try:
        source_dir = (REPO_ROOT / source_path).resolve()
        if not source_dir.exists():
            return {
                "status": "error",
                "message": f"Source path does not exist: {source_path}",
                "exit_code": 1
            }

        sbom_path = SBOM_DIR / "sbom-source.enriched.json"
        signed_sbom_path = SBOM_DIR / "sbom-source.signed.json"

        # Generate SBOM
        gen_cmd = [
            "syft",
            str(source_dir),
            "-o",
            f"cyclonedx-json={sbom_path}"
        ]

        if log_callback:
            code, output = run_cmd_stream(gen_cmd, on_output=log_callback)
        else:
            code, output = run_cmd(gen_cmd)

        if code != 0:
            return {
                "status": "error",
                "message": "SBOM generation failed",
                "log": output,
                "exit_code": code
            }

        # Sign SBOM
        sign_cmd = [
            "bash",
            str(REPO_ROOT / "scripts" / "sign-sbom.sh"),
            str(sbom_path),
            str(signed_sbom_path),
            str(SBOM_DIR / "pki")
        ]

        if log_callback:
            sign_code, sign_output = run_cmd_stream(sign_cmd, on_output=log_callback)
        else:
            sign_code, sign_output = run_cmd(sign_cmd)

        if sign_code != 0:
            return {
                "status": "error",
                "message": "SBOM signing failed",
                "log": output + "\n" + sign_output,
                "exit_code": sign_code
            }

        # Replace original with signed version
        if signed_sbom_path.exists():
            shutil.move(str(signed_sbom_path), str(sbom_path))

        return {
            "status": "ok",
            "message": "SBOM generated and signed successfully",
            "log": output + "\n" + sign_output,
            "exit_code": 0,
            "source_path": source_path
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "exit_code": 1
        }


def _local_run_worker(run_id, body):
    started = datetime.now(timezone.utc)
    with LOCAL_RUNS_LOCK:
        run = LOCAL_RUNS.get(run_id, {})
        run["status"] = "running"
        run["started_at"] = started.isoformat()
        LOCAL_RUNS[run_id] = run
    def _append_live_log(chunk):
        if not chunk:
            return
        with LOCAL_RUNS_LOCK:
            run = LOCAL_RUNS.get(run_id, {})
            current = run.get("log", "")
            # Prevent unbounded growth in long-running jobs.
            next_log = (current + chunk)[-400000:]
            run["log"] = next_log
            LOCAL_RUNS[run_id] = run

    result = run_generate_pipeline(body, log_callback=_append_live_log)
    finished = datetime.now(timezone.utc)
    duration = max(int((finished - started).total_seconds()), 0)
    with LOCAL_RUNS_LOCK:
        run = LOCAL_RUNS.get(run_id, {})
        run.update(
            {
                "status": "success" if result.get("status") == "ok" else "failed",
                "finished_at": finished.isoformat(),
                "duration": duration,
                "exit_code": result.get("exit_code"),
                "log": result.get("log", ""),
                "source_path": result.get("source_path"),
                "app_metadata_path": result.get("app_metadata_path"),
            }
        )
        LOCAL_RUNS[run_id] = run


def safe_extract_zip(zip_path, target_dir):
    target_resolved = target_dir.resolve()
    extracted_files = 0
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            name = (info.filename or "").replace("\\", "/")
            if not name or name.endswith("/"):
                continue
            if name.startswith("/") or ".." in Path(name).parts:
                continue
            dest = (target_dir / name).resolve()
            if not str(dest).startswith(str(target_resolved)):
                continue
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(dest, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted_files += 1
    return extracted_files


def save_uploaded_project_files(files, target_dir):
    target_resolved = target_dir.resolve()
    saved = 0
    for f in files:
        name = (f.filename or "").replace("\\", "/")
        if not name:
            continue
        if name.startswith("/") or ".." in Path(name).parts:
            continue
        dest = (target_dir / name).resolve()
        if not str(dest).startswith(str(target_resolved)):
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        f.save(str(dest))
        saved += 1
    return saved


def pick_source_root(extract_root):
    children = [p for p in extract_root.iterdir() if p.is_dir()]
    if len(children) == 1:
        return children[0]
    return extract_root


def rel_to_repo(path_obj):
    return os.path.relpath(str(path_obj.resolve()), str(REPO_ROOT))


@app.after_request
def add_no_cache_headers(response):
    # Prevent stale cached JS/HTML so UI updates are immediately visible.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    # Allow hosted frontends (e.g., GitHub Pages) to call this API.
    response.headers["Access-Control-Allow-Origin"] = os.getenv("CORS_ALLOW_ORIGIN", "*")
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    # Include X-SBOM-TOKEN — browsers will not send custom headers on cross-origin fetches without this on preflight.
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-SBOM-TOKEN"
    return response


@app.errorhandler(RequestEntityTooLarge)
def handle_large_upload(_err):
    return jsonify({"status": "error", "message": "Upload is too large. Remove build/cache folders and retry."}), 413


@app.route("/api/<path:_unused>", methods=["OPTIONS"])
def api_preflight(_unused):
    return ("", 204)


def get_local_snapshot():
    sbom_path = get_latest_sbom_path()
    sbom = parse_json(sbom_path) if sbom_path else None
    grype_report = parse_json(REPORT_DIR / "grype-report.json")
    trivy_report = parse_json(REPORT_DIR / "trivy-sbom-report.json")

    grype_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    if grype_report and isinstance(grype_report.get("matches"), list):
        for match in grype_report["matches"]:
            sev = ((match.get("vulnerability") or {}).get("severity") or "other").lower()
            if sev in grype_severity:
                grype_severity[sev] += 1
            else:
                grype_severity["other"] += 1

    trivy_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    trivy_total = 0
    for result in (trivy_report or {}).get("Results", []) or []:
        vulns = result.get("Vulnerabilities") or []
        trivy_total += len(vulns)
        for v in vulns:
            sev = (v.get("Severity") or "UNKNOWN").lower()
            if sev in trivy_severity:
                trivy_severity[sev] += 1
            else:
                trivy_severity["unknown"] += 1

    artifacts = [
        {"label": "SBOM JSON", "path": "sbom/sbom-source.enriched.json"},
        {"label": "Signed SBOM", "path": "sbom/sbom-source.enriched.json"},
        {"label": "Grype Report", "path": "reports/grype-report.json"},
        {"label": "Trivy SBOM Report", "path": "reports/trivy-sbom-report.json"},
        {"label": "Grype DB Status", "path": "reports/grype-db-status.txt"},
        {"label": "Grype DB Providers", "path": "reports/grype-db-providers.txt"},
        {"label": "Public Key", "path": "sbom/pki/sbom_public_key.pem"},
    ]

    return {
        "sbom_file": str(sbom_path.relative_to(REPO_ROOT)) if sbom_path else None,
        "components": len(sbom.get("components", [])) if sbom else 0,
        "dependencies": len(sbom.get("dependencies", [])) if sbom else 0,
        "vulnerabilities": len((grype_report or {}).get("matches", [])),
        "vulnerabilities_grype": len((grype_report or {}).get("matches", [])),
        "vulnerabilities_trivy": trivy_total,
        "timestamp": (sbom.get("metadata", {}) or {}).get("timestamp", "-") if sbom else "-",
        "severity": grype_severity,
        "severity_trivy": trivy_severity,
        "artifacts": artifacts,
        "has_docker": shutil.which("docker") is not None,
        "has_pwsh": shutil.which("pwsh") is not None,
        "has_bash": shutil.which("bash") is not None,
        "os": platform.platform(),
    }


def parse_repo_slug():
    code, out = run_cmd(["git", "config", "--get", "remote.origin.url"])
    if code != 0:
        return "Richmansolom/SBOM-ATTESTATION"
    url = out.strip()
    if "github.com/" in url:
        slug = url.split("github.com/")[-1]
        slug = slug.replace(".git", "").replace(":", "/")
        if slug.count("/") >= 1:
            return "/".join(slug.split("/")[-2:])
    if url.startswith("git@github.com:"):
        return url.replace("git@github.com:", "").replace(".git", "")
    return "Richmansolom/SBOM-ATTESTATION"


def get_requested_repo():
    # Allow UI override, but default to current git remote.
    repo = (request.args.get("project") or "").strip()
    if repo and "/" in repo:
        return repo
    payload = request.get_json(silent=True) or {}
    repo = str(payload.get("project") or "").strip()
    if repo and "/" in repo:
        return repo
    return parse_repo_slug()


def get_requested_provider():
    provider = (request.args.get("provider") or "").strip().lower()
    if provider in ("github", "gitlab"):
        return provider
    payload = request.get_json(silent=True) or {}
    provider = str(payload.get("provider") or "").strip().lower()
    if provider in ("github", "gitlab"):
        return provider
    return "github"


def get_requested_token():
    token = (request.headers.get("X-SBOM-TOKEN") or "").strip()
    if token:
        return token
    token = (request.args.get("token") or "").strip()
    if token:
        return token
    payload = request.get_json(silent=True) or {}
    token = str(payload.get("token") or "").strip()
    if token:
        return token
    return ""


def get_gh_json(path):
    if shutil.which("gh") is None:
        return None
    code, out = run_cmd(["gh", "api", path])
    if code != 0:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


def _github_token_for_request():
    """
    Get GitHub token from:
    1. Request (UI input)
    2. Environment variable (Render)
    """
    body = request.get_json(silent=True) or {}
    token = (body.get("token") or "").strip()

    if token:
        return token

    # fallback to Render env
    env_token = os.getenv("GITHUB_TOKEN", "").strip()
    return env_token


def github_rest_request(path, method="GET", token="", json_body=None):
    """Call GitHub REST API v3. Supports unauthenticated GET for public repos."""
    url = f"https://api.github.com/{path.lstrip('/')}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "sbom-mission-control",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    # Only attach Authorization when a token is actually present.
    if token:
        headers["Authorization"] = f"Bearer {token}"

    method = (method or "GET").upper()
    data = None
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(url=url, method=method, headers=headers, data=data)

    try:
        with urlopen(req, timeout=120) as resp:
            raw = resp.read()
            text = raw.decode("utf-8", errors="replace") if raw else ""
            return resp.status, text
    except HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, err_body
    except URLError as e:
        return 599, str(e.reason or e)
    except Exception as exc:
        return 500, str(exc)


def fetch_github_json(path):
    """
    Prefer GitHub REST API first.
    - For public repos, unauthenticated GET should work.
    - If a token exists, use it.
    - Fall back to gh CLI only if REST fails.
    """
    token = _github_token_for_request()

    # Try GitHub REST first, even without token, for public-read support.
    code, body = github_rest_request(path, "GET", token)
    if code == 200 and body:
        try:
            return json.loads(body)
        except Exception:
            pass

    # If rate-limited or unauthorized/private, gh may still help in local dev.
    gh_data = get_gh_json(path)
    if gh_data is not None:
        return gh_data

    return None


def gh_api(path, method="GET", data=None):
    if shutil.which("gh") is None:
        return 1, "gh CLI not found. Install GitHub CLI and run: gh auth login"
    cmd = ["gh", "api", "-X", method, path]
    if data:
        for k, v in data.items():
            cmd.extend(["-f", f"{k}={v}"])
    return run_cmd(cmd)


def map_gitlab_status(status):
    s = (status or "").lower()
    if s in ("success", "passed"):
        return "success"
    if s in ("failed", "failure"):
        return "failed"
    if s in ("running", "in_progress"):
        return "running"
    if s in ("canceled", "cancelled"):
        return "canceled"
    if s in ("pending", "created", "manual", "scheduled", "preparing", "waiting_for_resource"):
        return "pending"
    return s or "pending"


def gitlab_api(path, method="GET", token="", data=None):
    base = "https://gitlab.com/api/v4"
    url = f"{base}/{path.lstrip('/')}"
    headers = {"Accept": "application/json"}
    if token:
        headers["PRIVATE-TOKEN"] = token
    payload = None
    if data is not None:
        payload = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url=url, method=method.upper(), headers=headers, data=payload)
    try:
        with urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except Exception as exc:
        return 500, str(exc)


def get_stage_status_from_steps(steps):
    stage_state = {s: "pending" for s in STAGE_NAMES}
    for step in steps or []:
        name = (step.get("name") or "").lower()
        conclusion = (step.get("conclusion") or "").lower()
        status = "running" if (step.get("status") == "in_progress") else conclusion
        if "build example" in name:
            stage_state["Build"] = status
        elif "generate cots sboms" in name or "generate sbom" in name:
            stage_state["Generate"] = status
        elif "sign sboms" in name or "sign sbom" in name:
            stage_state["Sign"] = status
        elif "grype vulnerability scan" in name or "scan" in name:
            stage_state["Scan"] = status
        elif "generate vulnerability analysis report" in name or "upload artifacts" in name:
            stage_state["Report"] = status
    return [{"name": s, "status": stage_state[s]} for s in STAGE_NAMES]


def map_run_status(run):
    status = (run.get("status") or "").lower()
    conclusion = (run.get("conclusion") or "").lower()
    if status == "completed":
        if conclusion in ("success", "failure", "cancelled"):
            return "success" if conclusion == "success" else ("failed" if conclusion == "failure" else "canceled")
        return "pending"
    if status == "in_progress":
        return "running"
    if status in ("queued", "requested", "waiting", "pending"):
        return "pending"
    return status or "pending"


def map_job_stage(name):
    n = (name or "").lower()
    if "build" in n:
        return "build"
    if "generate" in n:
        return "sbom_generate"
    if "sign" in n:
        return "sbom_sign"
    if "scan" in n or "grype" in n:
        return "sbom_scan"
    if "report" in n or "artifact" in n:
        return "report"
    return "report"


def normalize_stage_status(status):
    s = (status or "").lower()
    if s in ("success", "completed"):
        return "success"
    if s in ("failure", "failed"):
        return "failed"
    if s in ("in_progress", "running"):
        return "running"
    if s in ("cancelled", "canceled"):
        return "canceled"
    return "pending"


def derive_gitlab_stage_progress_from_trace(trace_text, job_status):
    """Infer Build/Generate/Sign/Scan/Report progress from a single GitLab job trace."""
    markers = [
        ("Build", "build", "==> Build example C++ application"),
        ("Generate", "sbom_generate", "==> Generate COTS SBOMs"),
        ("Sign", "sbom_sign", "==> Sign SBOMs with embedded CycloneDX signature"),
        ("Scan", "sbom_scan", "==> SBOM vulnerability scan using Grype + Trivy"),
        ("Report", "report", "==> Generate vulnerability analysis report"),
    ]
    stage_states = [{"name": m[0], "stage": m[1], "status": "pending"} for m in markers]
    text = (trace_text or "")
    found = [m[2] in text for m in markers]
    job_state = normalize_stage_status(job_status)

    if job_state == "success":
        for s in stage_states:
            s["status"] = "success"
        return stage_states

    last_found_idx = -1
    for idx, is_found in enumerate(found):
        if is_found:
            last_found_idx = idx

    if last_found_idx < 0:
        # No known marker yet; reflect current job lifecycle on Build only.
        stage_states[0]["status"] = "running" if job_state == "running" else ("failed" if job_state == "failed" else "pending")
        return stage_states

    for idx in range(last_found_idx):
        stage_states[idx]["status"] = "success"

    if job_state == "running":
        stage_states[last_found_idx]["status"] = "running"
    elif job_state == "failed":
        stage_states[last_found_idx]["status"] = "failed"
    elif job_state == "canceled":
        stage_states[last_found_idx]["status"] = "canceled"
    else:
        stage_states[last_found_idx]["status"] = "pending"

    return stage_states


def get_github_snapshot():
    repo = get_requested_repo() if has_request_context() else parse_repo_slug()
    runs_json = fetch_github_json(f"repos/{repo}/actions/runs?per_page=12")
    if not runs_json:
        return {
            "repo": repo,
            "available": False,
           "message": "GitHub data unavailable. For public repos, verify the repo name. For private repos, add a PAT in Connect with repo + actions:read.",
            "totals": {"pipelines": 0, "passed": 0, "failed": 0, "running": 0, "success_rate": 0},
            "latest": None,
            "recent": [],
        }

    runs = runs_json.get("workflow_runs", [])
    passed = sum(1 for r in runs if r.get("conclusion") == "success")
    failed = sum(1 for r in runs if r.get("conclusion") == "failure")
    running = sum(1 for r in runs if r.get("status") == "in_progress")
    total = len(runs)
    success_rate = int((passed / total) * 100) if total else 0

    latest = runs[0] if runs else None
    latest_payload = None
    if latest:
        jobs_json = fetch_github_json(f"repos/{repo}/actions/runs/{latest.get('id')}/jobs")
        jobs = jobs_json.get("jobs", []) if jobs_json else []
        steps = jobs[0].get("steps", []) if jobs else []
        latest_payload = {
            "id": latest.get("run_number"),
            "sha": (latest.get("head_sha") or "")[:7],
            "branch": latest.get("head_branch"),
            "status": latest.get("conclusion") or latest.get("status"),
            "stages": get_stage_status_from_steps(steps),
            "url": latest.get("html_url"),
        }

    recent = [
        {
            "id": r.get("run_number"),
            "sha": (r.get("head_sha") or "")[:7],
            "branch": r.get("head_branch"),
            "status": r.get("conclusion") or r.get("status"),
            "url": r.get("html_url"),
        }
        for r in runs[:8]
    ]

    return {
        "repo": repo,
        "available": True,
        "totals": {
            "pipelines": total,
            "passed": passed,
            "failed": failed,
            "running": running,
            "success_rate": success_rate,
        },
        "latest": latest_payload,
        "recent": recent,
    }


@app.route("/")
def index():
    return send_from_directory(str(STATIC_DIR), "index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route("/api/status")
def status():
    return jsonify(get_local_snapshot())


@app.route("/api/db-status")
def db_status():
    return jsonify(get_db_freshness())


@app.route("/api/github")
def github():
    return jsonify(get_github_snapshot())


@app.route("/api/dashboard")
def dashboard():
    return jsonify({"local": get_local_snapshot(), "github": get_github_snapshot()})


@app.route("/api/generate", methods=["POST"])
def generate():
    result = run_generate_pipeline(request.get_json(silent=True) or {})
    return jsonify(result)


@app.route("/api/local-run/start", methods=["POST"])
def start_local_run():
    body = request.get_json(silent=True) or {}
    run_id = f"local-{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()
    with LOCAL_RUNS_LOCK:
        LOCAL_RUNS[run_id] = {
            "id": run_id,
            "status": "pending",
            "created_at": now,
            "started_at": None,
            "finished_at": None,
            "duration": None,
            "exit_code": None,
            "log": "",
            "source_path": body.get("source_path") or "",
            "app_name": body.get("app_name") or "",
        }
    t = threading.Thread(target=_local_run_worker, args=(run_id, body), daemon=True)
    t.start()
    return jsonify({"status": "ok", "id": run_id})


@app.route("/api/local-runs")
def list_local_runs():
    with LOCAL_RUNS_LOCK:
        runs = list(LOCAL_RUNS.values())
    runs.sort(key=lambda r: (r.get("created_at") or ""), reverse=True)
    return jsonify(runs[:30])


@app.route("/api/upload-source", methods=["POST"])
def upload_source():
    ensure_dirs()
    f = request.files.get("project_zip")
    uploaded_files = request.files.getlist("project_files")
    if (not f or not f.filename) and not uploaded_files:
        return jsonify({"status": "error", "message": "Upload a project folder or a .zip file"}), 400

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    upload_root = UPLOAD_DIR / f"src-{ts}"
    extract_root = upload_root / "src"
    upload_root.mkdir(parents=True, exist_ok=True)
    extract_root.mkdir(parents=True, exist_ok=True)

    count = 0
    if f and f.filename:
        if not str(f.filename).lower().endswith(".zip"):
            return jsonify({"status": "error", "message": "Project zip upload must be a .zip file"}), 400
        zip_path = upload_root / "project.zip"
        f.save(str(zip_path))
        try:
            count = safe_extract_zip(zip_path, extract_root)
        except Exception as exc:
            return jsonify({"status": "error", "message": f"Failed to extract zip: {exc}"}), 400
    else:
        count = save_uploaded_project_files(uploaded_files, extract_root)

    if count == 0:
        return jsonify({"status": "error", "message": "No valid project files were uploaded"}), 400

    source_root = pick_source_root(extract_root)
    app_meta = source_root / "app-metadata.json"
    detected_name = source_root.name
    return jsonify(
        {
            "status": "ok",
            "source_path": rel_to_repo(source_root),
            "app_metadata_path": rel_to_repo(app_meta) if app_meta.exists() else "",
            "detected_app_name": detected_name,
            "message": "Project uploaded successfully",
        }
    )


@app.route("/api/upload-metadata", methods=["POST"])
def upload_metadata():
    ensure_dirs()
    f = request.files.get("metadata_file")
    if not f or not f.filename:
        return jsonify({"status": "error", "message": "Missing metadata_file upload"}), 400
    if not str(f.filename).lower().endswith(".json"):
        return jsonify({"status": "error", "message": "Metadata upload must be a .json file"}), 400
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    target = UPLOAD_DIR / f"app-metadata-{ts}.json"
    f.save(str(target))
    # Basic validation for UX feedback.
    try:
        json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return jsonify({"status": "error", "message": "Uploaded metadata JSON is invalid"}), 400
    return jsonify({"status": "ok", "app_metadata_path": rel_to_repo(target), "message": "Metadata uploaded successfully"})


@app.route("/api/pick-folder", methods=["POST"])
def pick_folder():
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Folder picker unavailable: {exc}"}), 500

    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askdirectory(title="Select C/C++ project folder")
        root.destroy()
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Failed to open folder picker: {exc}"}), 500

    if not selected:
        return jsonify({"status": "error", "message": "Folder selection cancelled"}), 400

    source_dir = Path(selected)
    meta = source_dir / "app-metadata.json"
    # Detect if there are likely C/C++ files for user feedback.
    has_cpp = any(source_dir.rglob(ext) for ext in ("*.cpp", "*.cxx", "*.cc", "*.c", "*.hpp", "*.hxx", "*.hh", "*.h"))
    return jsonify(
        {
            "status": "ok",
            "source_path": str(source_dir),
            "app_metadata_path": str(meta) if meta.exists() else "",
            "detected_app_name": source_dir.name,
            "has_cpp": bool(has_cpp),
        }
    )


@app.route("/api/pick-metadata", methods=["POST"])
def pick_metadata():
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Metadata picker unavailable: {exc}"}), 500

    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        selected = filedialog.askopenfilename(
            title="Select app-metadata.json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        root.destroy()
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Failed to open metadata picker: {exc}"}), 500

    if not selected:
        return jsonify({"status": "error", "message": "Metadata selection cancelled"}), 400
    return jsonify({"status": "ok", "app_metadata_path": str(Path(selected))})


@app.route("/api/sign", methods=["POST"])
def sign():
    ensure_dirs()

    source_sbom = SBOM_DIR / "sbom-source.enriched.json"
    build_sbom = SBOM_DIR / "sbom-build.enriched.json"
    sign_script = REPO_ROOT / "scripts" / "sign-sbom.sh"
    pki_dir = SBOM_DIR / "pki"

    if not sign_script.exists():
        return jsonify({"status": "error", "log": f"Signing script not found: {sign_script}"}), 500

    targets = []
    if source_sbom.exists():
        targets.append(source_sbom)
    if build_sbom.exists():
        targets.append(build_sbom)

    if not targets:
        return jsonify({"status": "error", "log": "No enriched SBOM found to sign in sbom/"}), 400

    combined_log = []

    for sbom_file in targets:
        signed_tmp = sbom_file.with_suffix(".signed.json")
        cmd = [
            "bash",
            str(sign_script),
            str(sbom_file),
            str(signed_tmp),
            str(pki_dir),
        ]
        code, output = run_cmd(cmd)
        combined_log.append(output)

        if code != 0:
            return jsonify({
                "status": "error",
                "exit_code": code,
                "log": "\n".join(combined_log)
            })

        if signed_tmp.exists():
            shutil.move(str(signed_tmp), str(sbom_file))

    return jsonify({
        "status": "ok",
        "exit_code": 0,
        "log": "\n".join(combined_log)
    })


@app.route("/api/scan", methods=["POST"])
def scan():
    # lots of docker code
    # lots of grype stuff
    # lots of trivy stuff
    return jsonify(...)

@app.route("/api/something_else")   👈 STOP HERE
def something_else():
    ...

@app.route("/api/sbom")
def get_sbom():
    path = get_latest_sbom_path()
    if not path:
        return jsonify({"status": "error", "message": "No SBOM file found"}), 404
    return send_from_directory(str(path.parent), path.name, mimetype="application/json")


@app.route("/api/report")
def get_report():
    scanner = (request.args.get("scanner") or "grype").strip().lower()
    report_map = {
        "grype": REPORT_DIR / "grype-report.json",
        "trivy": REPORT_DIR / "trivy-sbom-report.json",
    }
    path = report_map.get(scanner, REPORT_DIR / "grype-report.json")
    if not path.exists():
        return jsonify({"status": "error", "message": f"No vulnerability report found for scanner '{scanner}'"}), 404
    payload = parse_json(path)
    if payload is None:
        return jsonify({"status": "error", "message": f"Report exists but is not valid JSON for scanner '{scanner}'"}), 500
    return jsonify(payload)


@app.route("/api/pipelines")
def pipelines():
    provider = get_requested_provider()
    repo = get_requested_repo()
    per_page = request.args.get("per_page", "15")
    if provider == "gitlab":
        encoded_project = quote(repo, safe="")
        token = get_requested_token() or os.getenv("GITLAB_TOKEN", "")
        status, out = gitlab_api(f"projects/{encoded_project}/pipelines?per_page={per_page}", token=token)
        if status >= 300:
            return jsonify({"message": out.strip() or "Failed to fetch GitLab pipelines"}), 500
        try:
            runs = json.loads(out)
        except Exception:
            return jsonify({"message": "Failed to parse GitLab response"}), 500
        payload = []
        for run in runs:
            payload.append(
                {
                    "id": run.get("id"),
                    "status": map_gitlab_status(run.get("status")),
                    "duration": iso_duration_seconds(run.get("started_at"), run.get("updated_at") or run.get("finished_at")),
                    "ref": run.get("ref"),
                    "sha": (run.get("sha") or "")[:7],
                    "created_at": run.get("created_at"),
                    "run_number": run.get("iid"),
                    "workflow_id": None,
                    "html_url": run.get("web_url"),
                }
            )
        return jsonify(payload)

    data = fetch_github_json(f"repos/{repo}/actions/runs?per_page={per_page}")
    if not data:
        code, out = gh_api(f"repos/{repo}/actions/runs?per_page={per_page}")
        if code != 0:
            return jsonify({"message": out.strip() or "Failed to fetch workflows — use Connect token or gh auth login"}), 500
        try:
            data = json.loads(out)
        except Exception:
            return jsonify({"message": "Failed to parse GitHub response"}), 500
    runs = data.get("workflow_runs", [])

    payload = []
    for run in runs:
        qs = parse_qs(urlparse(run.get("jobs_url") or "").query)
        payload.append(
            {
                "id": run.get("id"),
                "status": map_run_status(run),
                "duration": iso_duration_seconds(run.get("run_started_at"), run.get("updated_at")),
                "ref": run.get("head_branch"),
                "sha": (run.get("head_sha") or "")[:7],
                "created_at": run.get("created_at"),
                "run_number": run.get("run_number"),
                "workflow_id": (qs.get("workflow_id") or [None])[0],
                "html_url": run.get("html_url"),
            }
        )
    return jsonify(payload)


@app.route("/api/pipelines/<int:run_id>/jobs")
def pipeline_jobs(run_id):
    provider = get_requested_provider()
    repo = get_requested_repo()
    if provider == "gitlab":
        encoded_project = quote(repo, safe="")
        token = get_requested_token() or os.getenv("GITLAB_TOKEN", "")
        status, out = gitlab_api(f"projects/{encoded_project}/pipelines/{run_id}/jobs", token=token)
        if status >= 300:
            return jsonify({"message": out.strip() or "Failed to fetch GitLab jobs"}), 500
        try:
            jobs = json.loads(out)
        except Exception:
            return jsonify({"message": "Failed to parse GitLab jobs response"}), 500
        mapped = []
        for j in jobs:
            mapped.append(
                {
                    "id": j.get("id"),
                    "name": j.get("name"),
                    "status": map_gitlab_status(j.get("status")),
                    "stage": map_job_stage(j.get("stage") or j.get("name")),
                    "duration": iso_duration_seconds(j.get("started_at"), j.get("finished_at")),
                }
            )

        # GitLab pipeline may be implemented as one consolidated job; infer logical stages from trace.
        if len(mapped) == 1:
            only = mapped[0]
            trace_status, trace_out = gitlab_api(f"projects/{encoded_project}/jobs/{only.get('id')}/trace", token=token)
            if trace_status < 300 and trace_out:
                inferred = derive_gitlab_stage_progress_from_trace(trace_out, only.get("status"))
                if inferred:
                    synthetic = []
                    for s in inferred:
                        synthetic.append(
                            {
                                "id": only.get("id"),
                                "name": s.get("name"),
                                "status": s.get("status"),
                                "stage": s.get("stage"),
                                "duration": None,
                            }
                        )
                    return jsonify(synthetic)
        return jsonify(mapped)

    data = fetch_github_json(f"repos/{repo}/actions/runs/{run_id}/jobs")
    if not data:
        code, out = gh_api(f"repos/{repo}/actions/runs/{run_id}/jobs")
        if code != 0:
            return jsonify({"message": out.strip() or "Failed to fetch jobs"}), 500
        try:
            data = json.loads(out)
        except Exception:
            return jsonify({"message": "Failed to parse jobs response"}), 500
    jobs = data.get("jobs", [])

    # Some workflows use one job with multiple step stages.
    # For the UI stage-strip, derive stage states from job steps when available.
    if jobs and isinstance(jobs[0].get("steps"), list) and jobs[0]["steps"]:
        stage_map = {"Build": "build", "Generate": "sbom_generate", "Sign": "sbom_sign", "Scan": "sbom_scan", "Report": "report"}
        job_id = jobs[0].get("id")
        step_states = get_stage_status_from_steps(jobs[0].get("steps"))
        synthetic = []
        for s in step_states:
            synthetic.append(
                {
                    "id": job_id,
                    "name": s.get("name"),
                    "status": normalize_stage_status(s.get("status")),
                    "stage": stage_map.get(s.get("name"), "report"),
                    "duration": None,
                }
            )
        return jsonify(synthetic)

    mapped = []
    for j in jobs:
        mapped.append(
            {
                "id": j.get("id"),
                "name": j.get("name"),
                "status": map_run_status(j),
                "stage": map_job_stage(j.get("name")),
                "duration": iso_duration_seconds(j.get("started_at"), j.get("completed_at")),
            }
        )
    return jsonify(mapped)


@app.route("/api/pipeline", methods=["POST"])
def trigger_pipeline():
    provider = get_requested_provider()
    repo = get_requested_repo()
    body = request.get_json(silent=True) or {}
    ref = body.get("ref") or "main"
    workflow = body.get("workflow") or "sbom-pipeline.yml"
    token = get_requested_token() or os.getenv("GITLAB_TOKEN", "")

    if provider == "gitlab":
        encoded_project = quote(repo, safe="")
        trigger_token = str(body.get("trigger_token") or "").strip() or os.getenv("GITLAB_TRIGGER_TOKEN", "")
        if trigger_token:
            query = urlencode({"token": trigger_token, "ref": str(ref)})
            status, out = gitlab_api(f"projects/{encoded_project}/trigger/pipeline?{query}", method="POST")
        else:
            if not token:
                return jsonify({"message": "GitLab token required to trigger pipeline. Set GITLAB_TOKEN or provide token in Connect."}), 400
            query = urlencode({"ref": str(ref)})
            status, out = gitlab_api(f"projects/{encoded_project}/pipeline?{query}", method="POST", token=token)
        if status >= 300:
            return jsonify({"message": out.strip() or "Failed to trigger GitLab pipeline"}), 500
        try:
            created = json.loads(out)
        except Exception:
            created = {}
        return jsonify(
            {
                "id": created.get("id"),
                "status": map_gitlab_status(created.get("status") or "pending"),
                "html_url": created.get("web_url"),
                "message": "Pipeline trigger submitted",
            }
        )

    token = _github_token_for_request()
    ref_full = str(ref) if str(ref).startswith("refs/") else f"refs/heads/{ref}"
    wf_enc = quote(workflow, safe="")

    if token:
        dispatch_path = f"repos/{repo}/actions/workflows/{wf_enc}/dispatches"
        code, body = github_rest_request(dispatch_path, "POST", token, json_body={"ref": ref_full})
        if code not in (200, 201, 204):
            msg = body
            try:
                msg = json.loads(body).get("message", body) if body else str(code)
            except Exception:
                pass
            return jsonify({"message": f"GitHub API: {msg}"}), 500
    elif shutil.which("gh"):
        code, out = run_cmd(["gh", "workflow", "run", workflow, "--repo", repo, "--ref", str(ref)])
        if code != 0:
            return jsonify({"message": out.strip() or "Failed to trigger workflow"}), 500
    else:
        return jsonify(
            {
                "message": "GitHub: add a Personal Access Token in Connect (repo + actions:write) or install `gh` CLI and run `gh auth login`.",
            }
        ), 400

    # Return newest run as immediate feedback for the UI.
    latest_data = fetch_github_json(f"repos/{repo}/actions/runs?per_page=1")
    latest = None
    if latest_data:
        latest = (latest_data.get("workflow_runs") or [None])[0]
    if not latest:
        return jsonify({"id": None, "status": "queued", "html_url": None, "message": "Workflow trigger submitted"})
    return jsonify(
        {
            "id": latest.get("id"),
            "status": map_run_status(latest),
            "html_url": latest.get("html_url"),
            "message": "Workflow trigger submitted",
        }
    )


@app.route("/api/jobs/<int:job_id>/trace")
def job_trace(job_id):
    provider = get_requested_provider()
    repo = get_requested_repo()
    run_id = request.args.get("run_id")
    if provider == "gitlab":
        encoded_project = quote(repo, safe="")
        token = get_requested_token() or os.getenv("GITLAB_TOKEN", "")
        status, out = gitlab_api(f"projects/{encoded_project}/jobs/{job_id}/trace", token=token)
        if status >= 300:
            return (out or "Unable to load job trace."), 500, {"Content-Type": "text/plain; charset=utf-8"}
        return out, 200, {"Content-Type": "text/plain; charset=utf-8"}

    if not run_id:
        return "Missing run_id query parameter", 400
    ght = (get_requested_token() or os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip()
    if ght:
        code, log_body = github_rest_request(f"repos/{repo}/actions/jobs/{job_id}/logs", "GET", ght)
        if code == 200 and log_body:
            return log_body, 200, {"Content-Type": "text/plain; charset=utf-8"}

        # Fallback: some GitHub environments may reject job-log endpoint while allowing run-log archives.
        if run_id:
            run_code, run_logs = github_rest_request(f"repos/{repo}/actions/runs/{run_id}/logs", "GET", ght)
            if run_code == 200 and run_logs:
                return run_logs, 200, {"Content-Type": "text/plain; charset=utf-8"}

        # Token exists but API call failed; return actionable reason instead of misleading gh-cli guidance.
        api_msg = log_body or "Unable to load workflow logs from GitHub API."
        try:
            parsed = json.loads(log_body or "{}")
            api_msg = parsed.get("message") or api_msg
        except Exception:
            pass
        return f"GitHub API log access failed ({code}): {api_msg}", 500, {"Content-Type": "text/plain; charset=utf-8"}

    if shutil.which("gh") is None:
        return "Job logs require a GitHub token (Connect or backend GITHUB_TOKEN) or the gh CLI.", 500, {"Content-Type": "text/plain; charset=utf-8"}
    code, out = run_cmd(["gh", "run", "view", str(run_id), "--repo", repo, "--job", str(job_id), "--log"])
    if code != 0:
        if "still in progress" in (out or "").lower():
            return out, 200, {"Content-Type": "text/plain; charset=utf-8"}
        return out or "Unable to load workflow logs.", 500
    return out, 200, {"Content-Type": "text/plain; charset=utf-8"}


if __name__ == "__main__":
    ensure_dirs()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "5000"))
    app.run(host=host, port=port, debug=False)
