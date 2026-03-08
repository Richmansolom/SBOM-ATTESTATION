import json
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

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


def parse_json(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
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
    return response


def get_local_snapshot():
    sbom_path = get_latest_sbom_path()
    sbom = parse_json(sbom_path) if sbom_path else None
    report = parse_json(REPORT_DIR / "grype-report.json")

    severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "other": 0}
    if report and isinstance(report.get("matches"), list):
        for match in report["matches"]:
            sev = ((match.get("vulnerability") or {}).get("severity") or "other").lower()
            if sev in severity:
                severity[sev] += 1
            else:
                severity["other"] += 1

    artifacts = [
        {"label": "SBOM JSON", "path": "sbom/sbom-source.enriched.json"},
        {"label": "Signed SBOM", "path": "sbom/sbom-source.enriched.json"},
        {"label": "Vuln Report", "path": "reports/grype-report.json"},
        {"label": "Public Key", "path": "sbom/pki/sbom_public_key.pem"},
    ]

    return {
        "sbom_file": str(sbom_path.relative_to(REPO_ROOT)) if sbom_path else None,
        "components": len(sbom.get("components", [])) if sbom else 0,
        "dependencies": len(sbom.get("dependencies", [])) if sbom else 0,
        "vulnerabilities": len(report.get("matches", [])) if report else 0,
        "timestamp": (sbom.get("metadata", {}) or {}).get("timestamp", "-") if sbom else "-",
        "severity": severity,
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

    grype_json_cmd = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/data", "anchore/grype:latest",
        "sbom:/data/sbom/sbom-source.enriched.v16.json", "-o", "json",
    ]
    c2, o2 = run_cmd(grype_json_cmd)
    if c2 != 0:
        return jsonify({"status": "error", "exit_code": c2, "log": o1 + "\n" + o2})
    (REPORT_DIR / "grype-report.json").write_text(o2, encoding="utf-8")

    grype_table_cmd = [
        "docker", "run", "--rm", "-v", f"{REPO_ROOT}:/data", "anchore/grype:latest",
        "sbom:/data/sbom/sbom-source.enriched.v16.json", "-o", "table",
    ]
    c3, o3 = run_cmd(grype_table_cmd)
    (REPORT_DIR / "grype-report.txt").write_text(o3, encoding="utf-8")
    if c3 != 0:
        return jsonify({"status": "error", "exit_code": c3, "log": o1 + "\n" + o2 + "\n" + o3})

    return jsonify({"status": "ok", "exit_code": 0, "log": o1 + "\n" + o2 + "\n" + o3})


@app.route("/api/sbom")
def get_sbom():
    path = get_latest_sbom_path()
    if not path:
        return jsonify({"status": "error", "message": "No SBOM file found"}), 404
    return send_from_directory(str(path.parent), path.name, mimetype="application/json")


@app.route("/api/report")
def get_report():
    path = REPORT_DIR / "grype-report.json"
    if not path.exists():
        return jsonify({"status": "error", "message": "No vulnerability report found"}), 404
    return send_from_directory(str(path.parent), path.name, mimetype="application/json")


if __name__ == "__main__":
    ensure_dirs()
    app.run(host="127.0.0.1", port=5000, debug=False)
