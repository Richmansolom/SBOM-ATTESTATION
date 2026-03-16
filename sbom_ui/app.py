import json
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from flask import Flask, jsonify, request, send_from_directory


REPO_ROOT = Path(__file__).resolve().parents[1]
SBOM_DIR = REPO_ROOT / "sbom"
REPORT_DIR = REPO_ROOT / "reports"
STATIC_DIR = REPO_ROOT / "sbom_ui" / "static"
STAGE_NAMES = ["Build", "Generate", "Sign", "Scan", "Report"]

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")


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


@app.after_request
def add_no_cache_headers(response):
    # Prevent stale cached JS/HTML so UI updates are immediately visible.
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    # Allow hosted frontends (e.g., GitHub Pages) to call this API.
    response.headers["Access-Control-Allow-Origin"] = os.getenv("CORS_ALLOW_ORIGIN", "*")
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return response


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


def gh_api(path, method="GET", data=None):
    if shutil.which("gh") is None:
        return 1, "gh CLI not found. Install GitHub CLI and run: gh auth login"
    cmd = ["gh", "api", "-X", method, path]
    if data:
        for k, v in data.items():
            cmd.extend(["-f", f"{k}={v}"])
    return run_cmd(cmd)


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
    if "generate" in n and "sbom" in n:
        return "sbom_generate"
    if "sign" in n and "sbom" in n:
        return "sbom_sign"
    if "scan" in n or "grype" in n:
        return "sbom_scan"
    if "report" in n or "artifact" in n:
        return "report"
    return "report"


def get_github_snapshot():
    repo = parse_repo_slug()
    runs_json = get_gh_json(f"repos/{repo}/actions/runs?per_page=12")
    if not runs_json:
        return {
            "repo": repo,
            "available": False,
            "message": "GitHub data unavailable (gh auth or network).",
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
        jobs_json = get_gh_json(f"repos/{repo}/actions/runs/{latest.get('id')}/jobs")
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


@app.route("/api/github")
def github():
    return jsonify(get_github_snapshot())


@app.route("/api/dashboard")
def dashboard():
    return jsonify({"local": get_local_snapshot(), "github": get_github_snapshot()})


@app.route("/api/generate", methods=["POST"])
def generate():
    ensure_dirs()
    mode = (request.json or {}).get("mode", "native")
    if mode not in ("native", "container"):
        mode = "native"
    if shutil.which("pwsh") is None:
        return jsonify({"status": "error", "log": "PowerShell (pwsh) not found in PATH"}), 500
    cmd = ["pwsh", "-ExecutionPolicy", "Bypass", "-File", str(REPO_ROOT / "generate-sbom.ps1"), "-Mode", mode]
    code, output = run_cmd(cmd)
    return jsonify({"status": "ok" if code == 0 else "error", "exit_code": code, "log": output})


@app.route("/api/sign", methods=["POST"])
def sign():
    ensure_dirs()
    if shutil.which("docker") is None:
        return jsonify({"status": "error", "log": "Docker is required for signing endpoint"}), 500
    source_sbom = SBOM_DIR / "sbom-source.enriched.json"
    build_sbom = SBOM_DIR / "sbom-build.enriched.json"
    cmds = []
    if source_sbom.exists():
        cmds.append("bash scripts/sign-sbom.sh sbom/sbom-source.enriched.json sbom/sbom-source.enriched.signed.json sbom/pki && mv sbom/sbom-source.enriched.signed.json sbom/sbom-source.enriched.json")
    if build_sbom.exists():
        cmds.append("bash scripts/sign-sbom.sh sbom/sbom-build.enriched.json sbom/sbom-build.enriched.signed.json sbom/pki && mv sbom/sbom-build.enriched.signed.json sbom/sbom-build.enriched.json")
    if not cmds:
        return jsonify({"status": "error", "log": "No enriched SBOM found to sign in sbom/"}), 400
    inner = " && ".join(["apk add --no-cache bash jq openssl python3 coreutils >/dev/null", *cmds])
    cmd = ["docker", "run", "--rm", "-v", f"{REPO_ROOT}:/work", "-w", "/work", "alpine:3.20", "sh", "-lc", inner]
    code, output = run_cmd(cmd)
    return jsonify({"status": "ok" if code == 0 else "error", "exit_code": code, "log": output})


@app.route("/api/scan", methods=["POST"])
def scan():
    ensure_dirs()
    if shutil.which("docker") is None:
        return jsonify({"status": "error", "log": "Docker is required for scan endpoint"}), 500
    target = SBOM_DIR / "sbom-source.enriched.json"
    if not target.exists():
        return jsonify({"status": "error", "log": "Run generate first: sbom-source.enriched.json not found"}), 400

    convert_cmd = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/data", "cyclonedx/cyclonedx-cli:latest", "convert",
        "--input-file", "/data/sbom/sbom-source.enriched.json",
        "--output-file", "/data/sbom/sbom-source.enriched.v16.json",
        "--output-format", "json", "--output-version", "v1_6",
    ]
    c1, o1 = run_cmd(convert_cmd)
    if c1 != 0:
        return jsonify({"status": "error", "exit_code": c1, "log": o1})

    grype_cache = REPO_ROOT / ".cache" / "grype-db"
    grype_cache.mkdir(parents=True, exist_ok=True)

    grype_db_update_cmd = ["docker", "run", "--rm", "-v", f"{grype_cache}:/root/.cache/grype/db", "anchore/grype:latest", "db", "update"]
    _, gdb_update = run_cmd(grype_db_update_cmd)
    (REPORT_DIR / "grype-db-update.txt").write_text(gdb_update, encoding="utf-8")

    grype_db_status_cmd = ["docker", "run", "--rm", "-v", f"{grype_cache}:/root/.cache/grype/db", "anchore/grype:latest", "db", "status"]
    _, gdb_status = run_cmd(grype_db_status_cmd)
    (REPORT_DIR / "grype-db-status.txt").write_text(gdb_status, encoding="utf-8")

    grype_db_providers_cmd = ["docker", "run", "--rm", "-v", f"{grype_cache}:/root/.cache/grype/db", "anchore/grype:latest", "db", "providers"]
    _, gdb_providers = run_cmd(grype_db_providers_cmd)
    (REPORT_DIR / "grype-db-providers.txt").write_text(gdb_providers, encoding="utf-8")

    grype_json_cmd = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/data", "-v", f"{grype_cache}:/root/.cache/grype/db", "anchore/grype:latest",
        "sbom:/data/sbom/sbom-source.enriched.v16.json", "-o", "json",
    ]
    c2, o2 = run_cmd(grype_json_cmd)
    if c2 != 0:
        return jsonify({"status": "error", "exit_code": c2, "log": o1 + "\n" + o2})
    (REPORT_DIR / "grype-report.json").write_text(o2, encoding="utf-8")

    grype_table_cmd = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/data", "-v", f"{grype_cache}:/root/.cache/grype/db", "anchore/grype:latest",
        "sbom:/data/sbom/sbom-source.enriched.v16.json", "-o", "table",
    ]
    c3, o3 = run_cmd(grype_table_cmd)
    (REPORT_DIR / "grype-report.txt").write_text(o3, encoding="utf-8")
    if c3 != 0:
        return jsonify({"status": "error", "exit_code": c3, "log": o1 + "\n" + o2 + "\n" + o3})

    trivy_json_cmd = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/data", "aquasec/trivy:latest", "sbom",
        "--scanners", "vuln", "--vuln-severity-source", "nvd,ghsa,osv",
        "--format", "json", "--output", "/data/reports/trivy-sbom-report.json",
        "/data/sbom/sbom-source.enriched.v16.json",
    ]
    c4, o4 = run_cmd(trivy_json_cmd)
    if c4 != 0:
        return jsonify({"status": "error", "exit_code": c4, "log": o1 + "\n" + o2 + "\n" + o3 + "\n" + o4})

    trivy_table_cmd = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/data", "aquasec/trivy:latest", "sbom",
        "--scanners", "vuln", "--vuln-severity-source", "nvd,ghsa,osv",
        "--format", "table", "--output", "/data/reports/trivy-sbom-report.txt",
        "/data/sbom/sbom-source.enriched.v16.json",
    ]
    c5, o5 = run_cmd(trivy_table_cmd)
    if c5 != 0:
        return jsonify({"status": "error", "exit_code": c5, "log": o1 + "\n" + o2 + "\n" + o3 + "\n" + o4 + "\n" + o5})

    return jsonify({"status": "ok", "exit_code": 0, "log": "\n".join([o1, gdb_update, gdb_status, gdb_providers, o2, o3, o4, o5])})


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
    repo = get_requested_repo()
    per_page = request.args.get("per_page", "15")
    code, out = gh_api(f"repos/{repo}/actions/runs?per_page={per_page}")
    if code != 0:
        return jsonify({"message": out.strip() or "Failed to fetch workflows"}), 500
    try:
        runs = json.loads(out).get("workflow_runs", [])
    except Exception:
        return jsonify({"message": "Failed to parse GitHub response"}), 500

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
    repo = get_requested_repo()
    code, out = gh_api(f"repos/{repo}/actions/runs/{run_id}/jobs")
    if code != 0:
        return jsonify({"message": out.strip() or "Failed to fetch jobs"}), 500
    try:
        jobs = json.loads(out).get("jobs", [])
    except Exception:
        return jsonify({"message": "Failed to parse jobs response"}), 500

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
    repo = get_requested_repo()
    body = request.get_json(silent=True) or {}
    ref = body.get("ref") or "main"
    workflow = body.get("workflow") or "sbom-pipeline.yml"

    if shutil.which("gh") is None:
        return jsonify({"message": "gh CLI not found. Install GitHub CLI first."}), 500

    code, out = run_cmd(["gh", "workflow", "run", workflow, "--repo", repo, "--ref", str(ref)])
    if code != 0:
        return jsonify({"message": out.strip() or "Failed to trigger workflow"}), 500

    # Return newest run as immediate feedback for the UI.
    c2, o2 = gh_api(f"repos/{repo}/actions/runs?per_page=1")
    if c2 != 0:
        return jsonify({"id": None, "status": "queued", "message": out.strip() or "Workflow triggered"})
    try:
        latest = (json.loads(o2).get("workflow_runs") or [None])[0]
    except Exception:
        latest = None
    return jsonify(
        {
            "id": latest.get("id") if latest else None,
            "status": map_run_status(latest) if latest else "queued",
            "html_url": latest.get("html_url") if latest else None,
            "message": "Workflow trigger submitted",
        }
    )


@app.route("/api/jobs/<int:job_id>/trace")
def job_trace(job_id):
    repo = get_requested_repo()
    run_id = request.args.get("run_id")
    if not run_id:
        return "Missing run_id query parameter", 400
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
