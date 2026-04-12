import copy
import json
import io
import os
import platform
import re
import shutil
import subprocess
import tarfile
import threading
import uuid
import zipfile
from hashlib import sha1
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlparse
from urllib.request import Request, urlopen

from flask import Flask, has_request_context, jsonify, request, send_from_directory
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from metadata_parser import app_metadata_to_json_bytes, parse_app_metadata_bytes


REPO_ROOT = Path(__file__).resolve().parents[1]
# Match generate-sbom.ps1 (env TRIVY_IMAGE); pinned tag avoids flaky :latest resolution after fresh Docker installs.
TRIVY_IMAGE = os.environ.get("TRIVY_IMAGE", "aquasec/trivy:0.69.3")
GRYPE_IMAGE = os.environ.get("GRYPE_IMAGE", "anchore/grype:latest")
SBOM_DIR = REPO_ROOT / "sbom"
REPORT_DIR = REPO_ROOT / "reports"
SCAN_MANIFEST_PATH = REPORT_DIR / "scan-manifest.json"
STATIC_DIR = REPO_ROOT / "sbom_ui" / "static"
UPLOAD_DIR = REPO_ROOT / ".ui_uploads"
TOOLS_BIN_DIR = REPO_ROOT / ".tools" / "bin"
SOURCE_DIAG_PATH = REPORT_DIR / "source-diagnostics.json"
STAGE_NAMES = ["Build", "Generate", "Sign", "Scan", "Report"]

app = Flask(__name__, static_folder=str(STATIC_DIR), static_url_path="/static")
app.config["MAX_CONTENT_LENGTH"] = 512 * 1024 * 1024  # 512 MB
LOCAL_RUNS = {}
LOCAL_RUNS_LOCK = threading.Lock()


def run_cmd(cmd, env_extra=None):
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        env=env,
    )
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def run_cmd_stream(cmd, on_output=None, env_extra=None):
    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)
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
        env=env,
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


def parse_json_text(raw):
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        # Some scanner outputs may contain extra non-JSON lines.
        try:
            start_positions = [pos for pos in (raw.find("{"), raw.find("[")) if pos >= 0]
            if not start_positions:
                return None
            start = min(start_positions)
            obj, _ = json.JSONDecoder().raw_decode(raw[start:])
            return obj
        except Exception:
            return None


def parse_json_bytes(raw_bytes):
    if raw_bytes is None:
        return None
    try:
        text = raw_bytes.decode("utf-8", errors="replace")
    except Exception:
        return None
    return parse_json_text(text)


def extract_report_from_zip_bytes(zip_bytes, scanner):
    scanner = (scanner or "grype").strip().lower()
    candidates = {
        "grype": ["reports/grype-report.json", "grype-report.json"],
        "trivy": ["reports/trivy-sbom-report.json", "trivy-sbom-report.json"],
    }.get(scanner, ["reports/grype-report.json", "grype-report.json"])
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
            lowered = {n.lower(): n for n in names}
            # Try exact known paths first.
            for want in candidates:
                for lname, original in lowered.items():
                    if lname.endswith(want.lower()):
                        payload = parse_json_bytes(zf.read(original))
                        if payload is not None:
                            return payload, original
            # Fallback: any JSON that ends with the expected filename.
            fallback_suffix = "grype-report.json" if scanner == "grype" else "trivy-sbom-report.json"
            for lname, original in lowered.items():
                if lname.endswith(fallback_suffix):
                    payload = parse_json_bytes(zf.read(original))
                    if payload is not None:
                        return payload, original
    except Exception:
        return None, None
    return None, None


def extract_sbom_from_zip_bytes(zip_bytes):
    candidates = [
        "sbom/sbom-source.enriched.json",
        "sbom-source.enriched.json",
        "sbom/sbom-build.enriched.json",
        "sbom-build.enriched.json",
        "sbom/sbom-source.json",
        "sbom-source.json",
        "sbom/sbom-build.json",
        "sbom-build.json",
    ]
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            names = zf.namelist()
            lowered = {n.lower(): n for n in names}
            for want in candidates:
                for lname, original in lowered.items():
                    if lname.endswith(want.lower()):
                        payload = parse_json_bytes(zf.read(original))
                        if payload is not None:
                            return payload, original
            # Fallback: any JSON in sbom folder that looks like final SBOM output.
            for lname, original in lowered.items():
                if "/sbom/" in f"/{lname}" and lname.endswith(".json"):
                    payload = parse_json_bytes(zf.read(original))
                    if payload is not None and isinstance(payload, dict) and payload.get("components") is not None:
                        return payload, original
    except Exception:
        return None, None
    return None, None


def with_report_meta(payload, meta):
    if isinstance(payload, dict):
        out = dict(payload)
        out["_meta"] = meta
        return out
    return {"_meta": meta, "data": payload}


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


def read_root_component_name_from_sbom(sbom_path):
    """CycloneDX root component name from an SBOM file, if present."""
    if not sbom_path or not sbom_path.exists():
        return None
    data = parse_json(sbom_path)
    if not isinstance(data, dict):
        return None
    mc = data.get("metadata") or {}
    if not isinstance(mc, dict):
        return None
    comp = mc.get("component") or {}
    if isinstance(comp, dict):
        n = str(comp.get("name") or "").strip()
        return n or None
    return None


def _app_metadata_display_name(app_meta_path):
    if not app_meta_path:
        return None
    p = Path(app_meta_path)
    if not p.is_absolute():
        p = (REPO_ROOT / p).resolve()
    if not p.exists():
        return None
    try:
        normalized = parse_app_metadata_bytes(p.read_bytes(), p.name)
        return str(normalized.get("name") or "").strip() or None
    except Exception:
        return None


def write_scan_manifest_file(
    *,
    source_path_str,
    app_rel_path,
    execution_path,
    app_meta_path=None,
):
    """Persist which app was scanned and when (server-side generate)."""
    ensure_dirs()
    sbom_path = get_latest_sbom_path()
    root_name = read_root_component_name_from_sbom(sbom_path) if sbom_path else None
    app_meta_name = _app_metadata_display_name(app_meta_path)
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "generated_at": now,
        "source_path": source_path_str,
        "app_metadata_path": app_rel_path,
        "root_component_name": root_name,
        "app_metadata_name": app_meta_name,
        "execution_path": execution_path,
        "sbom_file": str(sbom_path.relative_to(REPO_ROOT)).replace("\\", "/") if sbom_path else None,
    }
    try:
        SCAN_MANIFEST_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass


def build_local_scan_meta():
    """Labels for last server-side SBOM/vuln generation (upload + generate)."""
    manifest = parse_json(SCAN_MANIFEST_PATH)
    if isinstance(manifest, dict) and manifest.get("execution_path"):
        return {
            "app_name": manifest.get("root_component_name") or manifest.get("app_metadata_name"),
            "generated_at": manifest.get("generated_at"),
            "scan_source_path": manifest.get("source_path"),
            "scan_execution_path": manifest.get("execution_path"),
            "app_metadata_path": manifest.get("app_metadata_path"),
            "scan_manifest": manifest,
        }
    sbom_path = get_latest_sbom_path()
    sbom = parse_json(sbom_path) if sbom_path else None
    mc = (sbom or {}).get("metadata") or {}
    comp = mc.get("component") or {}
    app_name = comp.get("name") if isinstance(comp, dict) else None
    out = {
        "app_name": app_name,
        "generated_at": None,
        "scan_source_path": None,
        "scan_execution_path": "legacy (no scan manifest; run Generate again to label this scan)",
        "scan_manifest": None,
    }
    gpath = REPORT_DIR / "grype-report.json"
    if gpath.exists():
        g = parse_json(gpath) or {}
        out["report_generated_at"] = g.get("generated") or file_mtime_iso(gpath)
    return out


def _hints_from_vuln_payload(payload):
    """Surface artifact / time hints from Grype or Trivy JSON for CI artifact views."""
    if not isinstance(payload, dict):
        return {}
    h = {}
    if payload.get("ArtifactName"):
        h["artifact_name"] = str(payload["ArtifactName"])
    if payload.get("GeneratedAt"):
        h["report_generated_at"] = str(payload["GeneratedAt"])
    elif payload.get("generated"):
        h["report_generated_at"] = str(payload["generated"])
    ds = payload.get("descriptor") or {}
    if isinstance(ds, dict) and ds.get("name"):
        h["scan_engine_label"] = str(ds["name"])
    return h


def _hints_from_sbom_payload(payload):
    """CycloneDX root component name from SBOM JSON (CI artifact)."""
    if not isinstance(payload, dict):
        return {}
    mc = payload.get("metadata") or {}
    if not isinstance(mc, dict):
        return {}
    comp = mc.get("component") or {}
    if isinstance(comp, dict) and comp.get("name"):
        return {"app_name": str(comp["name"])}
    return {}


def ensure_dirs():
    SBOM_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    TOOLS_BIN_DIR.mkdir(parents=True, exist_ok=True)


def clear_previous_build_artifacts():
    """Remove prior SBOM and scan outputs so a new upload or generate cannot mix results across apps."""
    ensure_dirs()
    for name in (
        "sbom-source.enriched.json",
        "sbom-build.enriched.json",
        "sbom-image.enriched.json",
        "sbom-source.json",
        "sbom-source.signed.json",
    ):
        p = SBOM_DIR / name
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass
    if REPORT_DIR.exists():
        for p in REPORT_DIR.iterdir():
            if p.is_file():
                try:
                    p.unlink()
                except Exception:
                    pass


def collect_source_diagnostics(source_dir):
    root = Path(source_dir).resolve()
    diag = {
        "exists": root.exists(),
        "source_path": str(root),
        "source_path_repo": None,
        "total_files": 0,
        "code_files": 0,
        "cpp_files": 0,
        "header_files": 0,
        "top_level_dirs": [],
        "has_macosx_dir": False,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        if str(root).startswith(str(REPO_ROOT)):
            diag["source_path_repo"] = os.path.relpath(str(root), str(REPO_ROOT)).replace("\\", "/")
    except Exception:
        pass
    if not root.exists():
        return diag

    code_exts = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".cmake", ".mk", ".txt", ".md"}
    cpp_exts = {".c", ".cc", ".cpp", ".cxx"}
    header_exts = {".h", ".hh", ".hpp", ".hxx"}
    skip_dir_names = {"__macosx", ".git", ".github", ".svn", ".hg", "__pycache__", "node_modules", "build", "dist"}
    max_walk = 50000
    walked = 0
    top_dirs = set()
    has_macosx = False

    for p in root.rglob("*"):
        walked += 1
        if walked > max_walk:
            break
        try:
            rel = p.relative_to(root)
        except Exception:
            continue
        rel_parts = [part.lower() for part in rel.parts]
        if "__macosx" in rel_parts:
            has_macosx = True
        if any(part in skip_dir_names for part in rel_parts):
            continue
        if p.is_dir():
            if rel.parts:
                top_dirs.add(rel.parts[0])
            continue
        if not p.is_file():
            continue
        diag["total_files"] += 1
        ext = p.suffix.lower()
        if ext in code_exts:
            diag["code_files"] += 1
        if ext in cpp_exts:
            diag["cpp_files"] += 1
        if ext in header_exts:
            diag["header_files"] += 1

    diag["top_level_dirs"] = sorted(top_dirs)[:20]
    diag["has_macosx_dir"] = has_macosx
    return diag


def write_source_diagnostics(diag):
    ensure_dirs()
    try:
        SOURCE_DIAG_PATH.write_text(json.dumps(diag, indent=2), encoding="utf-8")
    except Exception:
        pass


def resolve_syft_binary(log_callback=None, auto_install=True):
    syft_path = shutil.which("syft")
    if syft_path:
        return syft_path, "system"

    local_name = "syft.exe" if os.name == "nt" else "syft"
    local_path = TOOLS_BIN_DIR / local_name
    if local_path.exists():
        return str(local_path), "local-cache"

    if not auto_install:
        return None, "missing"

    auto_flag = (os.getenv("SBOM_AUTO_INSTALL_SYFT", "1") or "1").strip().lower()
    if auto_flag in ("0", "false", "no", "off"):
        return None, "auto-install-disabled"

    sys_name = platform.system().lower()
    arch = platform.machine().lower()
    os_map = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    os_token = os_map.get(sys_name)
    arch_token = arch_map.get(arch)
    if not os_token or not arch_token:
        return None, f"unsupported-platform:{sys_name}/{arch}"

    version = os.getenv("SYFT_VERSION", "v1.22.0").strip() or "v1.22.0"
    version_num = version[1:] if version.startswith("v") else version
    ext = "zip" if os_token == "windows" else "tar.gz"
    filename = f"syft_{version_num}_{os_token}_{arch_token}.{ext}"
    url = f"https://github.com/anchore/syft/releases/download/{version}/{filename}"
    try:
        if log_callback:
            log_callback(f"==> syft missing; downloading {filename}\n")
        req = Request(url=url, headers={"User-Agent": "sbom-mission-control"})
        with urlopen(req, timeout=120) as resp:
            archive_bytes = resp.read()

        TOOLS_BIN_DIR.mkdir(parents=True, exist_ok=True)
        if ext == "zip":
            with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
                target_member = next(
                    (n for n in zf.namelist() if Path(n).name.lower() in ("syft.exe", "syft")),
                    None,
                )
                if not target_member:
                    return None, "download-invalid-archive"
                local_path.write_bytes(zf.read(target_member))
        else:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
                target_member = next(
                    (m for m in tf.getmembers() if Path(m.name).name == "syft"),
                    None,
                )
                if not target_member:
                    return None, "download-invalid-archive"
                extracted = tf.extractfile(target_member)
                if extracted is None:
                    return None, "download-invalid-archive"
                local_path.write_bytes(extracted.read())

        if os.name != "nt":
            try:
                local_path.chmod(0o755)
            except Exception:
                pass
        if log_callback:
            log_callback(f"==> syft bootstrapped at {local_path}\n")
        return str(local_path), "bootstrap"
    except Exception as exc:
        return None, f"download-failed:{exc}"


def resolve_grype_binary(log_callback=None, auto_install=True):
    grype_path = shutil.which("grype")
    if grype_path:
        return grype_path, "system"

    local_name = "grype.exe" if os.name == "nt" else "grype"
    local_path = TOOLS_BIN_DIR / local_name
    if local_path.exists():
        return str(local_path), "local-cache"

    if not auto_install:
        return None, "missing"

    auto_flag = (os.getenv("SBOM_AUTO_INSTALL_GRYPE", "1") or "1").strip().lower()
    if auto_flag in ("0", "false", "no", "off"):
        return None, "auto-install-disabled"

    sys_name = platform.system().lower()
    arch = platform.machine().lower()
    os_map = {"linux": "linux", "darwin": "darwin", "windows": "windows"}
    arch_map = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    os_token = os_map.get(sys_name)
    arch_token = arch_map.get(arch)
    if not os_token or not arch_token:
        return None, f"unsupported-platform:{sys_name}/{arch}"

    version = os.getenv("GRYPE_VERSION", "v0.110.0").strip() or "v0.110.0"
    version_num = version[1:] if version.startswith("v") else version
    ext = "zip" if os_token == "windows" else "tar.gz"
    filename = f"grype_{version_num}_{os_token}_{arch_token}.{ext}"
    url = f"https://github.com/anchore/grype/releases/download/{version}/{filename}"
    try:
        if log_callback:
            log_callback(f"==> grype missing; downloading {filename}\n")
        req = Request(url=url, headers={"User-Agent": "sbom-mission-control"})
        with urlopen(req, timeout=120) as resp:
            archive_bytes = resp.read()

        TOOLS_BIN_DIR.mkdir(parents=True, exist_ok=True)
        if ext == "zip":
            with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as zf:
                target_name = "grype.exe" if os_token == "windows" else "grype"
                target_member = next((n for n in zf.namelist() if Path(n).name == target_name), None)
                if not target_member:
                    return None, "download-invalid-archive"
                local_path.write_bytes(zf.read(target_member))
        else:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
                target_member = next((m for m in tf.getmembers() if Path(m.name).name == "grype"), None)
                if not target_member:
                    return None, "download-invalid-archive"
                extracted = tf.extractfile(target_member)
                if extracted is None:
                    return None, "download-invalid-archive"
                local_path.write_bytes(extracted.read())

        if os.name != "nt":
            try:
                local_path.chmod(0o755)
            except Exception:
                pass
        if log_callback:
            log_callback(f"==> grype bootstrapped at {local_path}\n")
        return str(local_path), "bootstrap"
    except Exception as exc:
        return None, f"download-failed:{exc}"


def get_generate_capabilities():
    # Probe with auto-install enabled so hosted backends can self-heal
    # and immediately expose generate capability in the UI.
    syft_path, syft_source = resolve_syft_binary(auto_install=True)
    has_docker = shutil.which("docker") is not None
    has_bash = shutil.which("bash") is not None
    has_syft = bool(syft_path)
    docker_script = (REPO_ROOT / "scripts" / "docker-native-sbom.sh").exists()
    docker_ci_parity = has_docker and has_bash and docker_script
    can_generate = has_syft or has_docker
    msg = ""
    if not can_generate:
        msg = "Missing dependencies: syft and docker are not available on server."
    return {
        "can_generate": can_generate,
        "has_syft": has_syft,
        "has_docker": has_docker,
        "has_bash": has_bash,
        "docker_ci_parity": docker_ci_parity,
        "has_grype": bool(resolve_grype_binary(auto_install=False)[0]),
        "syft_source": syft_source,
        "message": msg,
    }


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


def _license_entries_from_spdx_or_name(lic: str):
    """Minimal CycloneDX 1.4+ license list entry for enrichment rows."""
    if not lic or str(lic).strip().lower() in ("unknown", ""):
        return []
    lid = str(lic).strip()
    if " " not in lid and re.match(r"^[A-Za-z0-9.+\-]+$", lid):
        return [{"license": {"id": lid}}]
    return [{"license": {"name": lid}}]


def _enrichment_supplier_license(payload, source_dir: Path, metadata_file=None):
    """
    Prefer explicit app metadata path (e.g. temp JSON in reports/ or uploaded canonical JSON),
    then app-metadata.json beside the source tree, then Syft root metadata.
    Used to populate supplier/license on hosted Syft scan file inventory rows.
    """
    paths_to_try = []
    if metadata_file is not None:
        try:
            mf = Path(metadata_file)
            if mf.is_file():
                paths_to_try.append(mf)
        except Exception:
            pass
    paths_to_try.append(source_dir / "app-metadata.json")
    for meta_path in paths_to_try:
        if not meta_path.exists():
            continue
        try:
            app = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(app, dict):
            continue
        sup = app.get("supplier") or {}
        name = str(sup.get("name") or "").strip()
        urls = sup.get("url") if isinstance(sup.get("url"), list) else []
        lic = str(app.get("license") or "").strip()
        if name:
            supplier = {"name": name, "url": urls}
            licenses = _license_entries_from_spdx_or_name(lic)
            return supplier, licenses
    meta = payload.get("metadata") or {}
    comp = meta.get("component") or {}
    sup = comp.get("supplier") or {}
    name = str(sup.get("name") or "").strip()
    if name:
        supplier = {"name": name, "url": sup.get("url") or []}
        licenses = comp.get("licenses")
        if isinstance(licenses, list) and len(licenses) > 0:
            return supplier, copy.deepcopy(licenses)
        return supplier, []
    return None, []


def _should_drop_hosted_noise_component(comp) -> bool:
    """Strip ccls-cache / Nix-store mirror paths and legacy include:* pseudo-libraries from SBOM lists."""
    if not isinstance(comp, dict):
        return False
    name = str(comp.get("name") or "")
    n = name.replace("\\", "/")
    nl = n.lower()
    if name.startswith("include:"):
        return True
    if ".ccls-cache/" in nl or nl.startswith(".ccls-cache/"):
        return True
    if "/ccls-cache/" in nl or nl.startswith("ccls-cache/"):
        return True
    # ccls mirrors use @@ segments; drop if it looks like a cache mirror, not project source.
    if "@@" in name and (".ccls-cache" in nl or "@nix@" in name or "/nix/store/" in nl):
        return True
    if "@nix@" in name or "/nix/store/" in nl:
        return True
    return False


def prune_hosted_sbom_noise(sbom_path: Path) -> int:
    """Remove junk components from Syft output before enrichment (defensive; works on old SBOMs too)."""
    payload = parse_json(sbom_path)
    if not isinstance(payload, dict):
        return 0
    comps = payload.get("components")
    if not isinstance(comps, list):
        return 0
    kept = [c for c in comps if not _should_drop_hosted_noise_component(c)]
    removed = len(comps) - len(kept)
    if removed <= 0:
        return 0
    payload["components"] = kept
    payload.setdefault("metadata", {})
    payload["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat()
    sbom_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return removed


def _is_junk_inventory_path(rel_posix: str) -> bool:
    """Skip ccls Nix mirror paths even if directory heuristics miss a variant."""
    r = rel_posix.replace("\\", "/")
    rl = r.lower()
    if "@@" in r:
        return True
    if "@nix@" in r or "/nix/store/" in rl:
        return True
    if ".ccls-cache" in rl or "/ccls-cache/" in rl:
        return True
    return False


def enrich_sbom_with_source_inventory(sbom_path, source_dir, app_metadata_path=None):
    payload = parse_json(sbom_path)
    if payload is None or not isinstance(payload, dict):
        return 0

    components = payload.get("components")
    if not isinstance(components, list):
        components = []

    # Keep scanner-derived rich inventories intact.
    # Hosted syft-only scans often return 0-1 components for plain C/C++ uploads.
    if len(components) > 20:
        return 0

    root = Path(source_dir).resolve()
    if not root.exists():
        return 0

    sup_inherit, lic_inherit = _enrichment_supplier_license(payload, root, app_metadata_path)

    code_exts = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".cmake", ".mk", ".txt", ".md"}
    skip_dir_names = {
        "__macosx",
        ".git",
        ".github",
        ".svn",
        ".hg",
        "__pycache__",
        "node_modules",
        "build",
        "dist",
        ".ccls-cache",
        ".clangd",
        ".vscode",
        ".idea",
        ".cursor",
        ".vs",
        ".venv",
        "venv",
    }
    max_components = 1000
    generated = []
    existing_names = {str((c or {}).get("name") or "").strip().lower() for c in components}
    existing_refs = {str((c or {}).get("bom-ref") or "").strip() for c in components}

    for f in root.rglob("*"):
        if not f.is_file():
            continue
        rel = f.relative_to(root)
        rel_parts = [p.lower() for p in rel.parts]
        if any(p in skip_dir_names for p in rel_parts):
            continue
        if f.suffix.lower() not in code_exts:
            continue
        rel_posix = rel.as_posix()
        if _is_junk_inventory_path(rel_posix):
            continue
        if rel_posix.lower() in existing_names:
            continue
        slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", rel_posix).strip("-").lower() or "source-file"
        file_ref = sha1(rel_posix.encode("utf-8")).hexdigest()[:12]
        bom_ref = f"source-file-{file_ref}"
        if bom_ref in existing_refs:
            continue
        row = {
            "type": "file",
            "name": rel_posix,
            "version": "0",
            "bom-ref": bom_ref,
            "purl": f"pkg:generic/{slug}@0",
            "properties": [
                {"name": "sbom-attestation:enrichment", "value": "source-file"},
            ],
        }
        if sup_inherit:
            row["supplier"] = copy.deepcopy(sup_inherit)
        if lic_inherit:
            row["licenses"] = copy.deepcopy(lic_inherit)
        generated.append(row)
        existing_names.add(rel_posix.lower())
        existing_refs.add(bom_ref)

        if len(generated) >= max_components:
            break

    if not generated:
        return 0

    payload["components"] = components + generated
    payload.setdefault("metadata", {})
    payload["metadata"]["timestamp"] = datetime.now(timezone.utc).isoformat()
    sbom_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return len(generated)


def count_vuln_report_totals():
    """Return (grype_match_count, trivy_vuln_count) from generated reports/."""
    g = parse_json(REPORT_DIR / "grype-report.json") or {}
    g_m = len(g.get("matches") or [])
    t = parse_json(REPORT_DIR / "trivy-sbom-report.json") or {}
    t_v = 0
    for r in t.get("Results") or []:
        if isinstance(r, dict):
            tv = r.get("Vulnerabilities") or []
            if isinstance(tv, list):
                t_v += len(tv)
    return g_m, t_v


def write_placeholder_vuln_reports():
    now = datetime.now(timezone.utc).isoformat()
    grype_stub = {
        "matches": [],
        "source": {"type": "sbom"},
        "distro": {"name": "unknown", "version": ""},
        "descriptor": {"name": "mission-control-local-scan", "version": "1"},
        "generated": now,
    }
    trivy_stub = {
        "ArtifactName": "sbom-source.enriched.json",
        "ArtifactType": "cyclonedx",
        "SchemaVersion": 2,
        "Results": [],
        "GeneratedAt": now,
    }
    (REPORT_DIR / "grype-report.json").write_text(json.dumps(grype_stub, indent=2), encoding="utf-8")
    (REPORT_DIR / "trivy-sbom-report.json").write_text(json.dumps(trivy_stub, indent=2), encoding="utf-8")


def write_trivy_report_from_grype(grype_payload, sbom_name):
    results = []
    per_target = {}
    for m in (grype_payload or {}).get("matches", []) or []:
        if not isinstance(m, dict):
            continue
        art = m.get("artifact") or {}
        vul = m.get("vulnerability") or {}
        name = str(art.get("name") or "-")
        ent = per_target.setdefault(name, [])
        ent.append(
            {
                "VulnerabilityID": str(vul.get("id") or "UNKNOWN"),
                "PkgName": name,
                "InstalledVersion": str(art.get("version") or "-"),
                "FixedVersion": str(((vul.get("fix") or {}).get("versions") or [""])[0] or ""),
                "Severity": _normalize_severity(vul.get("severity")),
                "Title": str(vul.get("description") or ""),
                "PrimaryURL": f"https://osv.dev/vulnerability/{vul.get('id')}" if vul.get("id") else "",
            }
        )
    for target, vulns in per_target.items():
        results.append({"Target": target, "Type": "library", "Vulnerabilities": vulns})
    payload = {
        "ArtifactName": str(sbom_name),
        "ArtifactType": "cyclonedx",
        "SchemaVersion": 2,
        "Results": results,
        "GeneratedAt": datetime.now(timezone.utc).isoformat(),
    }
    (REPORT_DIR / "trivy-sbom-report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _normalize_severity(raw):
    s = str(raw or "").strip().upper()
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}:
        return s
    return "UNKNOWN"


def _build_osv_queries_from_sbom(sbom_payload, max_queries=250):
    queries = []
    component_meta = []
    for comp in (sbom_payload or {}).get("components", []) or []:
        if not isinstance(comp, dict):
            continue
        purl = str(comp.get("purl") or "").strip()
        version = str(comp.get("version") or "").strip()
        name = str(comp.get("name") or "").strip() or "(unknown)"
        if not purl:
            continue
        q = {"package": {"purl": purl}}
        if version:
            q["version"] = version
        queries.append(q)
        component_meta.append({"name": name, "version": version or "-", "purl": purl})
        if len(queries) >= max_queries:
            break
    return queries, component_meta


def write_grype_vuln_reports_from_sbom(sbom_path, log_callback=None):
    grype_bin, grype_src = resolve_grype_binary(log_callback=log_callback, auto_install=True)
    if not grype_bin:
        return {"ok": False, "reason": "grype-unavailable"}
    cmd = [grype_bin, f"sbom:{sbom_path}", "-o", "json"]
    try:
        if log_callback:
            code, output = run_cmd_stream(cmd, on_output=log_callback)
        else:
            code, output = run_cmd(cmd)
    except Exception as exc:
        if log_callback:
            log_callback(f"==> grype execution error: {exc}\n")
        return {"ok": False, "reason": f"grype-exec-error:{exc}"}
    if code != 0:
        snippet = (output or "").strip().replace("\n", " ")[:240]
        return {"ok": False, "reason": f"grype-scan-failed:{snippet}"}
    payload = parse_json_text(output)
    if not isinstance(payload, dict):
        return {"ok": False, "reason": "grype-invalid-json"}
    (REPORT_DIR / "grype-report.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    write_trivy_report_from_grype(payload, Path(sbom_path).name)
    return {
        "ok": True,
        "mode": "grype-db",
        "queried_components": len((parse_json(sbom_path) or {}).get("components", []) or []),
        "matches": len(payload.get("matches", []) or []),
        "scanner_source": grype_src,
    }


def write_osv_vuln_reports_from_sbom(sbom_path):
    sbom_payload = parse_json(sbom_path)
    if not isinstance(sbom_payload, dict):
        return {"ok": False, "reason": "invalid-sbom"}

    queries, component_meta = _build_osv_queries_from_sbom(sbom_payload)
    if not queries:
        write_placeholder_vuln_reports()
        return {"ok": True, "mode": "osv-online", "queried_components": 0, "matches": 0}

    req = Request(
        url="https://api.osv.dev/v1/querybatch",
        data=json.dumps({"queries": queries}).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "sbom-mission-control",
        },
        method="POST",
    )

    try:
        with urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        payload = parse_json_text(raw) or {}
    except Exception:
        write_placeholder_vuln_reports()
        return {"ok": False, "reason": "osv-request-failed"}

    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        results = []

    grype_matches = []
    trivy_results = []
    total_matches = 0

    for i, item in enumerate(results):
        if i >= len(component_meta):
            break
        meta = component_meta[i]
        vulns = []
        if isinstance(item, dict):
            vulns = item.get("vulns") or []
        if not isinstance(vulns, list) or not vulns:
            continue

        tri_vulns = []
        for v in vulns:
            if not isinstance(v, dict):
                continue
            vuln_id = str(v.get("id") or "").strip() or "UNKNOWN"
            db_sev = ((v.get("database_specific") or {}).get("severity") if isinstance(v.get("database_specific"), dict) else None)
            sev = _normalize_severity(db_sev)
            fixed = []
            for aff in (v.get("affected") or []):
                if not isinstance(aff, dict):
                    continue
                for r in (aff.get("ranges") or []):
                    if not isinstance(r, dict):
                        continue
                    for ev in (r.get("events") or []):
                        if isinstance(ev, dict) and ev.get("fixed"):
                            fixed.append(str(ev.get("fixed")))
            fix_ver = fixed[0] if fixed else "-"
            summary = str(v.get("summary") or "")
            url = f"https://osv.dev/vulnerability/{vuln_id}"

            grype_matches.append(
                {
                    "vulnerability": {
                        "id": vuln_id,
                        "severity": sev,
                        "description": summary,
                        "fix": {"versions": [] if fix_ver == "-" else [fix_ver]},
                    },
                    "artifact": {
                        "name": meta["name"],
                        "version": meta["version"],
                        "purl": meta["purl"],
                    },
                }
            )
            tri_vulns.append(
                {
                    "VulnerabilityID": vuln_id,
                    "PkgName": meta["name"],
                    "InstalledVersion": meta["version"],
                    "FixedVersion": "" if fix_ver == "-" else fix_ver,
                    "Severity": sev,
                    "Title": summary,
                    "PrimaryURL": url,
                }
            )
            total_matches += 1

        if tri_vulns:
            trivy_results.append(
                {
                    "Target": meta["name"],
                    "Type": "library",
                    "Vulnerabilities": tri_vulns,
                }
            )

    now = datetime.now(timezone.utc).isoformat()
    grype_payload = {
        "matches": grype_matches,
        "source": {"type": "sbom"},
        "distro": {"name": "unknown", "version": ""},
        "descriptor": {"name": "osv-online-lookup", "version": "1"},
        "generated": now,
    }
    trivy_payload = {
        "ArtifactName": str(sbom_path.name),
        "ArtifactType": "cyclonedx",
        "SchemaVersion": 2,
        "Results": trivy_results,
        "GeneratedAt": now,
    }
    (REPORT_DIR / "grype-report.json").write_text(json.dumps(grype_payload, indent=2), encoding="utf-8")
    (REPORT_DIR / "trivy-sbom-report.json").write_text(json.dumps(trivy_payload, indent=2), encoding="utf-8")
    return {
        "ok": True,
        "mode": "osv-online",
        "queried_components": len(queries),
        "matches": total_matches,
    }


def run_generate_pipeline(body, log_callback=None):
    ensure_dirs()
    clear_previous_build_artifacts()
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
        source_rel = os.path.relpath(str(source_dir), str(REPO_ROOT)).replace("\\", "/")
        source_diag = collect_source_diagnostics(source_dir)
        source_diag.update(
            {
                "context": "generate",
                "requested_mode": str(body.get("mode") or "native").strip().lower() or "native",
                "requested_runtime": str(body.get("container_runtime") or "auto").strip().lower() or "auto",
            }
        )
        write_source_diagnostics(source_diag)

        # Use the full pipeline script so uploaded apps produce:
        # merged/enriched SBOM + validation + vulnerability reports, matching local/CI behavior.
        generate_script = REPO_ROOT / "generate-sbom.ps1"
        if not generate_script.exists():
            return {
                "status": "error",
                "message": f"Missing generate script: {generate_script}",
                "exit_code": 1,
            }

        requested_meta = body.get("app_metadata_path")
        app_meta_path = None
        if requested_meta:
            candidate = (REPO_ROOT / str(requested_meta)).resolve()
            if candidate.exists():
                app_meta_path = candidate
        if app_meta_path is None:
            candidate = source_dir / "app-metadata.json"
            if candidate.exists():
                app_meta_path = candidate
        cleanup_meta = None
        if app_meta_path is None:
            cleanup_meta = build_temp_metadata(body.get("app_name") or source_dir.name, source_rel)
            app_meta_path = cleanup_meta
        app_meta_rel = os.path.relpath(str(app_meta_path), str(REPO_ROOT)).replace("\\", "/")
        def _cleanup_temp_metadata():
            if cleanup_meta is not None and cleanup_meta.exists():
                try:
                    cleanup_meta.unlink()
                except Exception:
                    pass

        mode = str(body.get("mode") or "native").strip().lower()
        if mode not in ("native", "container"):
            mode = "native"
        runtime = str(body.get("container_runtime") or "auto").strip().lower()
        if runtime not in ("auto", "docker", "podman"):
            runtime = "auto"

        pwsh_cmd = shutil.which("pwsh") or shutil.which("powershell")
        if pwsh_cmd:
            gen_cmd = [
                pwsh_cmd,
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(generate_script),
                "-Mode",
                mode,
                "-ContainerRuntime",
                runtime,
                "-SourcePath",
                source_rel,
                "-AppMetadataPath",
                app_meta_rel,
            ]

            if log_callback:
                code, output = run_cmd_stream(gen_cmd, on_output=log_callback)
            else:
                code, output = run_cmd(gen_cmd)

            _cleanup_temp_metadata()

            if code != 0:
                source_diag.update({"execution_path": "powershell-pipeline", "status": "error"})
                write_source_diagnostics(source_diag)
                return {
                    "status": "error",
                    "message": "SBOM pipeline run failed",
                    "log": output,
                    "exit_code": code,
                    "source_diagnostics": source_diag,
                }

            source_diag.update({"execution_path": "powershell-pipeline", "status": "ok"})
            write_source_diagnostics(source_diag)
            write_scan_manifest_file(
                source_path_str=source_path,
                app_rel_path=app_meta_rel,
                execution_path="powershell-pipeline",
                app_meta_path=app_meta_path,
            )
            return {
                "status": "ok",
                "message": "SBOM generated, validated, and scanned successfully",
                "log": output,
                "exit_code": 0,
                "source_path": source_path,
                "app_metadata_path": app_meta_rel,
                "source_diagnostics": source_diag,
            }

        # Docker + bash: same pipeline as GitLab / generate-sbom.ps1 native (Syft+Trivy+merge+Grype+Trivy vuln), no host PowerShell.
        docker_bin = shutil.which("docker")
        bash_bin = shutil.which("bash")
        docker_script = REPO_ROOT / "scripts" / "docker-native-sbom.sh"
        enable_docker_full = os.getenv("ENABLE_DOCKER_FULL_PIPELINE", "1").strip().lower() not in (
            "0",
            "false",
            "no",
        )
        if (
            docker_bin
            and bash_bin
            and docker_script.exists()
            and enable_docker_full
        ):
            env_extra = {
                "REPO_ROOT": str(REPO_ROOT),
                "SOURCE_PATH": str(Path(source_rel).as_posix()),
                "APP_METADATA_PATH": str(Path(app_meta_rel).as_posix()),
            }
            if log_callback:
                log_callback(
                    "==> Docker CI-parity pipeline (scripts/docker-native-sbom.sh) — same tools as GitLab CI\n"
                )
            code, output = run_cmd_stream(
                [bash_bin, str(docker_script)],
                on_output=log_callback,
                env_extra=env_extra,
            )
            if code == 0:
                _cleanup_temp_metadata()
                sbom_path = SBOM_DIR / "sbom-source.enriched.json"
                signed_sbom_path = SBOM_DIR / "sbom-source.signed.json"
                sign_cmd = [
                    "bash",
                    str(REPO_ROOT / "scripts" / "sign-sbom.sh"),
                    str(sbom_path),
                    str(signed_sbom_path),
                    str(SBOM_DIR / "pki"),
                ]
                if log_callback:
                    sign_code, sign_output = run_cmd_stream(sign_cmd, on_output=log_callback)
                else:
                    sign_code, sign_output = run_cmd(sign_cmd)
                if sign_code != 0:
                    source_diag.update({"execution_path": "docker-ci-parity", "status": "error"})
                    write_source_diagnostics(source_diag)
                    return {
                        "status": "error",
                        "message": "SBOM signing failed after Docker pipeline",
                        "log": f"{output}\n{sign_output}",
                        "exit_code": sign_code,
                        "source_diagnostics": source_diag,
                    }
                if signed_sbom_path.exists():
                    shutil.move(str(signed_sbom_path), str(sbom_path))
                g_m, t_v = count_vuln_report_totals()
                source_diag.update({"execution_path": "docker-ci-parity", "status": "ok"})
                source_diag.update(
                    {
                        "vuln_scan_mode": "docker-grype+trivy-sbom",
                        "vuln_queried_components": len(
                            (parse_json(sbom_path) or {}).get("components") or []
                        ),
                        "vuln_matches": g_m + t_v,
                        "vuln_reason": "",
                    }
                )
                write_source_diagnostics(source_diag)
                write_scan_manifest_file(
                    source_path_str=source_path,
                    app_rel_path=app_meta_rel,
                    execution_path="docker-ci-parity",
                    app_meta_path=app_meta_path,
                )
                return {
                    "status": "ok",
                    "message": "SBOM generated via Docker CI-parity pipeline (Syft+Trivy+Grype; matches GitLab CI scan style)",
                    "log": f"{output}\n{sign_output}",
                    "exit_code": 0,
                    "source_path": source_path,
                    "app_metadata_path": app_meta_rel,
                    "source_diagnostics": source_diag,
                }
            if log_callback:
                log_callback(
                    f"==> Docker CI-parity pipeline failed (exit {code}); falling back to Syft-only hosted path.\n"
                )
            clear_previous_build_artifacts()

        # Hosted fallback (Render/Linux without PowerShell):
        # still generate and sign the SBOM so component listing works.
        sbom_path = SBOM_DIR / "sbom-source.enriched.json"
        signed_sbom_path = SBOM_DIR / "sbom-source.signed.json"

        syft_bin, syft_source = resolve_syft_binary(log_callback=log_callback, auto_install=True)
        docker_bin = shutil.which("docker")
        if syft_bin:
            if log_callback and syft_source:
                log_callback(f"==> Using syft ({syft_source})\n")
            gen_cmd = [
                syft_bin,
                str(source_dir),
                "-o",
                f"cyclonedx-json={sbom_path}",
            ]
        elif docker_bin:
            gen_cmd = [
                docker_bin,
                "run",
                "--rm",
                "-v",
                f"{REPO_ROOT}:/work",
                "anchore/syft:latest",
                f"dir:/work/{source_rel}",
                "-o",
                "cyclonedx-json=/work/sbom/sbom-source.enriched.json",
            ]
        else:
            _cleanup_temp_metadata()
            source_diag.update({"execution_path": "hosted-syft-scan", "status": "error"})
            write_source_diagnostics(source_diag)
            return {
                "status": "error",
                "message": "SBOM generation requires either syft or docker on hosted backend",
                "log": "Missing dependencies: syft, docker, and pwsh/powershell are not available.",
                "exit_code": 1,
                "source_diagnostics": source_diag,
            }

        if log_callback:
            code, output = run_cmd_stream(gen_cmd, on_output=log_callback)
        else:
            code, output = run_cmd(gen_cmd)
        if code != 0:
            _cleanup_temp_metadata()
            source_diag.update({"execution_path": "hosted-syft-scan", "status": "error"})
            write_source_diagnostics(source_diag)
            return {
                "status": "error",
                "message": "SBOM generation failed",
                "log": output,
                "exit_code": code,
                "source_diagnostics": source_diag,
            }

        noise_removed = prune_hosted_sbom_noise(sbom_path)
        if log_callback and noise_removed > 0:
            log_callback(
                f"==> Removed {noise_removed} junk/synthetic component(s) (e.g. .ccls-cache, nix-store mirrors, legacy include:*)\n"
            )

        added_components = enrich_sbom_with_source_inventory(sbom_path, source_dir, app_meta_path)
        if log_callback and added_components > 0:
            log_callback(
                f"==> Added {added_components} source-file inventory row(s) (supplier/license from app metadata when available; no #include pseudo-libraries)\n"
            )

        sign_cmd = [
            "bash",
            str(REPO_ROOT / "scripts" / "sign-sbom.sh"),
            str(sbom_path),
            str(signed_sbom_path),
            str(SBOM_DIR / "pki"),
        ]
        if log_callback:
            sign_code, sign_output = run_cmd_stream(sign_cmd, on_output=log_callback)
        else:
            sign_code, sign_output = run_cmd(sign_cmd)

        _cleanup_temp_metadata()

        if sign_code != 0:
            source_diag.update({"execution_path": "hosted-syft-scan", "status": "error"})
            write_source_diagnostics(source_diag)
            return {
                "status": "error",
                "message": "SBOM signing failed",
                "log": f"{output}\n{sign_output}",
                "exit_code": sign_code,
                "source_diagnostics": source_diag,
            }
        if signed_sbom_path.exists():
            shutil.move(str(signed_sbom_path), str(sbom_path))

        # Hosted fallback: prefer strong Grype DB scan; fallback to OSV lookup when unavailable.
        try:
            vuln_scan = write_grype_vuln_reports_from_sbom(sbom_path, log_callback=log_callback)
            if not vuln_scan.get("ok"):
                vuln_scan = write_osv_vuln_reports_from_sbom(sbom_path)
        except Exception as exc:
            # Never let hosted fallback vulnerability step crash /api/generate.
            vuln_scan = {"ok": False, "mode": "fallback-error", "reason": str(exc), "queried_components": 0, "matches": 0}
            write_placeholder_vuln_reports()
        if log_callback:
            mode = vuln_scan.get("mode") or "fallback"
            qn = vuln_scan.get("queried_components", 0)
            mn = vuln_scan.get("matches", 0)
            rs = vuln_scan.get("reason")
            if rs:
                log_callback(f"==> Vulnerability lookup ({mode}): queried={qn}, matches={mn}, reason={rs}\n")
            else:
                log_callback(f"==> Vulnerability lookup ({mode}): queried={qn}, matches={mn}\n")

        source_diag.update({"execution_path": "hosted-syft-scan", "status": "ok"})
        source_diag.update(
            {
                "vuln_scan_mode": vuln_scan.get("mode") if isinstance(vuln_scan, dict) else "fallback",
                "vuln_queried_components": (vuln_scan or {}).get("queried_components", 0) if isinstance(vuln_scan, dict) else 0,
                "vuln_matches": (vuln_scan or {}).get("matches", 0) if isinstance(vuln_scan, dict) else 0,
                "vuln_reason": (vuln_scan or {}).get("reason", "") if isinstance(vuln_scan, dict) else "",
            }
        )
        write_source_diagnostics(source_diag)
        write_scan_manifest_file(
            source_path_str=source_path,
            app_rel_path=app_meta_rel,
            execution_path="hosted-syft-scan",
            app_meta_path=app_meta_path,
        )
        return {
            "status": "ok",
            "message": "SBOM generated successfully (hosted Syft scan)",
            "log": f"{output}\n{sign_output}",
            "exit_code": 0,
            "source_path": source_path,
            "app_metadata_path": app_meta_rel,
            "source_diagnostics": source_diag,
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
    code_exts = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".cmake", ".txt", ".md"}
    skip_dir_names = {"__macosx", ".git", ".github", ".svn", ".hg", "__pycache__", "node_modules"}

    def _eligible_dirs(root):
        out = []
        for p in root.iterdir():
            if not p.is_dir():
                continue
            n = p.name.lower()
            if n in skip_dir_names or n.startswith("."):
                continue
            out.append(p)
        return out

    def _score_dir(root):
        code_files = 0
        all_files = 0
        try:
            for f in root.rglob("*"):
                if not f.is_file():
                    continue
                all_files += 1
                if f.suffix.lower() in code_exts:
                    code_files += 1
        except Exception:
            return (0, 0)
        return (code_files, all_files)

    # Prefer a single non-noise top-level folder (common zip layout).
    children = _eligible_dirs(extract_root)
    if len(children) == 1:
        return children[0]

    # Otherwise choose the best candidate by "has code files" and then file count.
    candidates = children[:] if children else [extract_root]
    best = max(candidates, key=_score_dir)
    best_score = _score_dir(best)

    # If every candidate appears empty, keep the extract root.
    if best_score == (0, 0):
        return extract_root
    return best


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


@app.errorhandler(Exception)
def handle_unexpected_error(err):
    # Ensure API callers always receive JSON, even on unexpected server faults.
    if has_request_context() and (request.path or "").startswith("/api/"):
        if isinstance(err, HTTPException):
            return jsonify({"status": "error", "message": err.description or str(err)}), int(err.code or 500)
        return jsonify({"status": "error", "message": f"Internal server error: {err}"}), 500
    raise err


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
    1. Request token (header/query/body via Connect)
    2. Environment variable (Render)
    """
    token = get_requested_token()
    if token:
        return token

    # fallback to backend env
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


def github_download_bytes(url, token=""):
    headers = {
        "Accept": "application/octet-stream",
        "User-Agent": "sbom-mission-control",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(url=url, method="GET", headers=headers)
    try:
        with urlopen(req, timeout=180) as resp:
            return resp.status, resp.read()
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body.encode("utf-8", errors="replace")
    except URLError as e:
        return 599, str(e.reason or e).encode("utf-8", errors="replace")
    except Exception as exc:
        return 500, str(exc).encode("utf-8", errors="replace")


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
    except HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
        except Exception:
            err_body = ""
        if not err_body:
            err_body = e.reason or str(e)
        return e.code, err_body
    except URLError as e:
        return 599, str(e.reason or e)
    except Exception as exc:
        return 500, str(exc)


def gitlab_error_message(text):
    """Turn GitLab JSON error (or plain text) into a short user-facing string."""
    if not text or not str(text).strip():
        return "GitLab request failed"
    raw = str(text).strip()
    try:
        obj = json.loads(raw)
    except Exception:
        return raw[:800]
    msg = obj.get("message")
    if isinstance(msg, dict):
        parts = []
        for k, v in msg.items():
            if isinstance(v, list):
                parts.append(f"{k}: {', '.join(str(x) for x in v)}")
            else:
                parts.append(f"{k}: {v}")
        return "; ".join(parts) if parts else raw[:800]
    if isinstance(msg, list):
        return "; ".join(str(x) for x in msg)
    if msg:
        return str(msg)
    err = obj.get("error") or obj.get("errors")
    if err:
        return str(err)[:800]
    return raw[:800]


def gitlab_api_binary(path, token=""):
    base = "https://gitlab.com/api/v4"
    url = f"{base}/{path.lstrip('/')}"
    headers = {"Accept": "application/octet-stream"}
    if token:
        headers["PRIVATE-TOKEN"] = token
    req = Request(url=url, method="GET", headers=headers)
    try:
        with urlopen(req, timeout=180) as resp:
            return resp.status, resp.read()
    except HTTPError as e:
        body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body.encode("utf-8", errors="replace")
    except URLError as e:
        return 599, str(e.reason or e).encode("utf-8", errors="replace")
    except Exception as exc:
        return 500, str(exc).encode("utf-8", errors="replace")


def fetch_github_report_from_artifacts(repo, scanner, token="", run_id=None):
    run_ids = []
    if run_id:
        run_ids.append(int(run_id))
    else:
        status, out = github_rest_request(f"repos/{repo}/actions/runs?per_page=20", "GET", token)
        if status >= 300:
            return None, f"GitHub runs lookup failed ({status})"
        runs_json = parse_json_text(out) or {}
        runs = runs_json.get("workflow_runs") or []
        for run in runs:
            if (run.get("conclusion") or "").lower() == "success":
                rid = run.get("id")
                if rid:
                    run_ids.append(int(rid))
        # Fallback to latest runs if no successful run has artifacts yet.
        if not run_ids:
            for run in runs[:5]:
                rid = run.get("id")
                if rid:
                    run_ids.append(int(rid))
    if not run_ids:
        return None, "No GitHub workflow runs found"

    for rid in run_ids[:8]:
        status, out = github_rest_request(f"repos/{repo}/actions/runs/{rid}/artifacts?per_page=30", "GET", token)
        if status >= 300:
            continue
        payload = parse_json_text(out) or {}
        artifacts = payload.get("artifacts") or []
        for artifact in artifacts:
            if artifact.get("expired"):
                continue
            archive_url = artifact.get("archive_download_url")
            if not archive_url:
                continue
            a_status, raw_zip = github_download_bytes(archive_url, token=token)
            if a_status >= 300:
                continue
            report_payload, entry = extract_report_from_zip_bytes(raw_zip, scanner)
            if report_payload is not None:
                return {
                    "payload": report_payload,
                    "run_id": rid,
                    "artifact_name": artifact.get("name") or "",
                    "zip_entry": entry or "",
                }, None
    return None, "No matching vulnerability report found in GitHub artifacts"


def fetch_gitlab_report_from_artifacts(project, scanner, token="", pipeline_id=None):
    encoded_project = quote(project, safe="")
    pipeline_ids = []
    if pipeline_id:
        pipeline_ids.append(int(pipeline_id))
    else:
        status, out = gitlab_api(f"projects/{encoded_project}/pipelines?status=success&per_page=20", token=token)
        if status >= 300:
            return None, f"GitLab pipelines lookup failed ({status})"
        pipelines = parse_json_text(out) or []
        for p in pipelines:
            pid = p.get("id")
            if pid:
                pipeline_ids.append(int(pid))
    if not pipeline_ids:
        return None, "No GitLab successful pipelines found"

    for pid in pipeline_ids[:8]:
        status, out = gitlab_api(f"projects/{encoded_project}/pipelines/{pid}/jobs?per_page=100", token=token)
        if status >= 300:
            continue
        jobs = parse_json_text(out) or []
        for job in jobs:
            artifacts_file = (job.get("artifacts_file") or {}).get("filename")
            if not artifacts_file:
                continue
            jid = job.get("id")
            if not jid:
                continue
            z_status, raw_zip = gitlab_api_binary(f"projects/{encoded_project}/jobs/{jid}/artifacts", token=token)
            if z_status >= 300:
                continue
            report_payload, entry = extract_report_from_zip_bytes(raw_zip, scanner)
            if report_payload is not None:
                return {
                    "payload": report_payload,
                    "pipeline_id": pid,
                    "job_id": jid,
                    "job_name": job.get("name") or "",
                    "zip_entry": entry or "",
                }, None
    return None, "No matching vulnerability report found in GitLab artifacts"


def fetch_github_sbom_from_artifacts(repo, token="", run_id=None):
    run_ids = []
    if run_id:
        run_ids.append(int(run_id))
    else:
        status, out = github_rest_request(f"repos/{repo}/actions/runs?per_page=20", "GET", token)
        if status >= 300:
            return None, f"GitHub runs lookup failed ({status})"
        runs_json = parse_json_text(out) or {}
        runs = runs_json.get("workflow_runs") or []
        for run in runs:
            rid = run.get("id")
            if rid:
                run_ids.append(int(rid))
    if not run_ids:
        return None, "No GitHub workflow runs found"

    for rid in run_ids[:10]:
        status, out = github_rest_request(f"repos/{repo}/actions/runs/{rid}/artifacts?per_page=30", "GET", token)
        if status >= 300:
            continue
        payload = parse_json_text(out) or {}
        artifacts = payload.get("artifacts") or []
        for artifact in artifacts:
            if artifact.get("expired"):
                continue
            archive_url = artifact.get("archive_download_url")
            if not archive_url:
                continue
            a_status, raw_zip = github_download_bytes(archive_url, token=token)
            if a_status >= 300:
                continue
            sbom_payload, entry = extract_sbom_from_zip_bytes(raw_zip)
            if sbom_payload is not None:
                return {
                    "payload": sbom_payload,
                    "run_id": rid,
                    "artifact_name": artifact.get("name") or "",
                    "zip_entry": entry or "",
                }, None
    return None, "No SBOM JSON found in GitHub artifacts"


def fetch_gitlab_sbom_from_artifacts(project, token="", pipeline_id=None):
    encoded_project = quote(project, safe="")
    pipeline_ids = []
    if pipeline_id:
        pipeline_ids.append(int(pipeline_id))
    else:
        status, out = gitlab_api(f"projects/{encoded_project}/pipelines?per_page=20", token=token)
        if status >= 300:
            return None, f"GitLab pipelines lookup failed ({status})"
        pipelines = parse_json_text(out) or []
        for p in pipelines:
            pid = p.get("id")
            if pid:
                pipeline_ids.append(int(pid))
    if not pipeline_ids:
        return None, "No GitLab pipelines found"

    for pid in pipeline_ids[:10]:
        status, out = gitlab_api(f"projects/{encoded_project}/pipelines/{pid}/jobs?per_page=100", token=token)
        if status >= 300:
            continue
        jobs = parse_json_text(out) or []
        for job in jobs:
            artifacts_file = (job.get("artifacts_file") or {}).get("filename")
            if not artifacts_file:
                continue
            jid = job.get("id")
            if not jid:
                continue
            z_status, raw_zip = gitlab_api_binary(f"projects/{encoded_project}/jobs/{jid}/artifacts", token=token)
            if z_status >= 300:
                continue
            sbom_payload, entry = extract_sbom_from_zip_bytes(raw_zip)
            if sbom_payload is not None:
                return {
                    "payload": sbom_payload,
                    "pipeline_id": pid,
                    "job_id": jid,
                    "job_name": job.get("name") or "",
                    "zip_entry": entry or "",
                }, None
    return None, "No SBOM JSON found in GitLab artifacts"


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


@app.route("/version")
def version():
    return jsonify(
        {
            "status": "ok",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            # Render commonly provides this for each deploy; if absent, keep fallback fields.
            "commit": os.getenv("RENDER_GIT_COMMIT") or os.getenv("SOURCE_VERSION") or "unknown",
            "service": os.getenv("RENDER_SERVICE_NAME") or "",
            "instance": os.getenv("RENDER_INSTANCE_ID") or "",
        }
    )


@app.route("/api/status")
def status():
    return jsonify(get_local_snapshot())


@app.route("/api/capabilities")
def capabilities():
    return jsonify(get_generate_capabilities())


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

    clear_previous_build_artifacts()

    source_root = pick_source_root(extract_root)
    app_meta = source_root / "app-metadata.json"
    meta_upload = request.files.get("app_metadata")
    if meta_upload and meta_upload.filename:
        ext = Path(meta_upload.filename).suffix.lower()
        if ext not in (".json", ".csv", ".xml"):
            return jsonify(
                {"status": "error", "message": "app_metadata must be a .json, .csv, or .xml file"}
            ), 400
        try:
            raw_b = meta_upload.read()
            data = parse_app_metadata_bytes(raw_b, meta_upload.filename)
            app_meta = source_root / "app-metadata.json"
            app_meta.write_bytes(app_metadata_to_json_bytes(data))
        except Exception as exc:
            return jsonify({"status": "error", "message": f"Invalid app metadata: {exc}"}), 400
    detected_name = source_root.name
    source_diag = collect_source_diagnostics(source_root)
    source_diag.update(
        {
            "context": "upload",
            "extract_root": rel_to_repo(extract_root),
            "selected_root": rel_to_repo(source_root),
            "uploaded_file_count": count,
        }
    )
    write_source_diagnostics(source_diag)
    return jsonify(
        {
            "status": "ok",
            "source_path": rel_to_repo(source_root),
            "app_metadata_path": rel_to_repo(app_meta) if app_meta.exists() else "",
            "detected_app_name": detected_name,
            "message": "Project uploaded successfully",
            "source_diagnostics": source_diag,
        }
    )


@app.route("/api/source-diagnostics")
def source_diagnostics():
    payload = parse_json(SOURCE_DIAG_PATH)
    if payload is None:
        return jsonify({"status": "error", "message": "No source diagnostics available yet"}), 404
    return jsonify(payload)


@app.route("/api/upload-metadata", methods=["POST"])
def upload_metadata():
    ensure_dirs()
    f = request.files.get("metadata_file")
    if not f or not f.filename:
        return jsonify({"status": "error", "message": "Missing metadata_file upload"}), 400
    ext = Path(f.filename).suffix.lower()
    if ext not in (".json", ".csv", ".xml"):
        return jsonify(
            {"status": "error", "message": "Metadata upload must be .json, .csv, or .xml"}
        ), 400
    try:
        raw_bytes = f.read()
        data = parse_app_metadata_bytes(raw_bytes, f.filename)
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Invalid metadata file: {exc}"}), 400
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    target = UPLOAD_DIR / f"app-metadata-{ts}.json"
    target.write_bytes(app_metadata_to_json_bytes(data))
    return jsonify(
        {
            "status": "ok",
            "app_metadata_path": rel_to_repo(target),
            "metadata_format": ext.lstrip("."),
            "app_name": data.get("name"),
            "message": "Metadata uploaded successfully (stored as canonical JSON)",
        }
    )


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
            title="Select app metadata (JSON, CSV, or XML)",
            filetypes=[
                ("App metadata", "*.json *.csv *.xml"),
                ("JSON", "*.json"),
                ("CSV", "*.csv"),
                ("XML", "*.xml"),
                ("All files", "*.*"),
            ],
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
    body = request.get_json(silent=True) or {}
    source_path = (body.get("source_path") or "").strip()
    if source_path:
        result = run_generate_pipeline(body)
        status = 200 if result.get("status") == "ok" else 500
        return jsonify(result), status

    grype = REPORT_DIR / "grype-report.json"
    trivy = REPORT_DIR / "trivy-sbom-report.json"
    if grype.exists() or trivy.exists():
        return jsonify(
            {
                "status": "ok",
                "message": "Using existing local vulnerability reports",
                "reports": {
                    "grype": grype.exists(),
                    "trivy": trivy.exists(),
                },
            }
        )
    return jsonify({"status": "error", "message": "No source_path provided and no local reports found"}), 404

@app.route("/api/something_else")   
def something_else():
    ...

@app.route("/api/sbom")
def get_sbom():
    path = get_latest_sbom_path()
    if not path:
        return jsonify({"status": "error", "message": "No SBOM file found"}), 404
    return send_from_directory(str(path.parent), path.name, mimetype="application/json")


@app.route("/api/sbom/unified")
def get_unified_sbom():
    source = (request.args.get("source") or "auto").strip().lower()
    provider = get_requested_provider()
    repo = get_requested_repo()
    token = get_requested_token()
    run_id = (request.args.get("run_id") or "").strip()
    pipeline_id = (request.args.get("pipeline_id") or "").strip()

    local_path = get_latest_sbom_path()

    # Auto / CI: only CI artifacts — never fall back to server-local SBOM (avoids mixing apps).
    if source in ("auto", "ci"):
        if provider == "gitlab":
            ci_token = token or os.getenv("GITLAB_TOKEN", "").strip()
            ci_result, ci_error = fetch_gitlab_sbom_from_artifacts(
                project=repo,
                token=ci_token,
                pipeline_id=pipeline_id or None,
            )
            if ci_result and ci_result.get("payload") is not None:
                pid = ci_result.get("pipeline_id")
                gl_sbom = {
                    "source": "gitlab-artifact",
                    "provider": "gitlab",
                    "project": repo,
                    "pipeline_id": pid,
                    "job_id": ci_result.get("job_id"),
                    "job_name": ci_result.get("job_name"),
                    "zip_entry": ci_result.get("zip_entry"),
                }
                if pid:
                    enc = quote(repo, safe="")
                    gl_sbom["pipeline_url"] = f"https://gitlab.com/{enc}/-/pipelines/{pid}"
                gl_sbom.update(_hints_from_sbom_payload(ci_result["payload"]))
                return jsonify(with_report_meta(ci_result["payload"], gl_sbom))
            if source == "ci":
                return jsonify({"status": "error", "message": ci_error or "No CI SBOM found"}), 404
        else:
            ci_token = token or os.getenv("GITHUB_TOKEN", "").strip()
            ci_result, ci_error = fetch_github_sbom_from_artifacts(
                repo=repo,
                token=ci_token,
                run_id=run_id or None,
            )
            if ci_result and ci_result.get("payload") is not None:
                rid = ci_result.get("run_id")
                sbom_gh = {
                    "source": "github-artifact",
                    "provider": "github",
                    "project": repo,
                    "run_id": rid,
                    "artifact_name": ci_result.get("artifact_name"),
                    "zip_entry": ci_result.get("zip_entry"),
                }
                if rid:
                    sbom_gh["run_url"] = f"https://github.com/{repo}/actions/runs/{rid}"
                    sbom_gh["artifacts_url"] = f"https://github.com/{repo}/actions/runs/{rid}#artifacts"
                sbom_gh.update(_hints_from_sbom_payload(ci_result["payload"]))
                return jsonify(with_report_meta(ci_result["payload"], sbom_gh))
            if source == "ci":
                return jsonify({"status": "error", "message": ci_error or "No CI SBOM found"}), 404

    if source == "auto":
        return jsonify(
            {
                "status": "error",
                "message": "No CI SBOM found. Use source=local for the last server-side generate after upload.",
            }
        ), 404

    if source not in ("auto", "local", "ci"):
        return jsonify({"status": "error", "message": "source must be 'auto', 'local', or 'ci'"}), 400

    if source == "local":
        if local_path and local_path.exists():
            payload = parse_json(local_path)
            if payload is not None:
                meta = {
                    "source": "local",
                    "provider": provider,
                    "project": repo,
                    "path": str(local_path.relative_to(REPO_ROOT)),
                }
                meta.update(build_local_scan_meta())
                return jsonify(with_report_meta(payload, meta))
            return jsonify({"status": "error", "message": "Local SBOM exists but is not valid JSON"}), 500
        return jsonify({"status": "error", "message": "No local SBOM file found"}), 404

    return jsonify({"status": "error", "message": "No SBOM available"}), 404


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


@app.route("/api/report/unified")
def get_unified_report():
    scanner = (request.args.get("scanner") or "grype").strip().lower()
    if scanner not in ("grype", "trivy"):
        return jsonify({"status": "error", "message": "scanner must be 'grype' or 'trivy'"}), 400

    source = (request.args.get("source") or "auto").strip().lower()
    provider = get_requested_provider()
    repo = get_requested_repo()
    token = get_requested_token()
    run_id = (request.args.get("run_id") or "").strip()
    pipeline_id = (request.args.get("pipeline_id") or "").strip()

    local_paths = {
        "grype": REPORT_DIR / "grype-report.json",
        "trivy": REPORT_DIR / "trivy-sbom-report.json",
    }
    local_path = local_paths[scanner]

    if source == "local":
        if not local_path.exists():
            return jsonify({"status": "error", "message": f"No local report found for scanner '{scanner}'"}), 404
        payload = parse_json(local_path)
        if payload is None:
            return jsonify({"status": "error", "message": "Local report exists but is not valid JSON"}), 500
        meta = {
            "source": "local",
            "scanner": scanner,
            "path": str(local_path.relative_to(REPO_ROOT)),
        }
        meta.update(build_local_scan_meta())
        return jsonify(with_report_meta(payload, meta))

    if source not in ("auto", "ci"):
        return jsonify({"status": "error", "message": "source must be 'auto', 'local', or 'ci'"}), 400

    # Match /api/sbom/unified: try CI artifacts first so hosted UI does not always show stale Render-local scans.
    if provider == "gitlab":
        ci_token = token or os.getenv("GITLAB_TOKEN", "").strip()
        ci_result, ci_error = fetch_gitlab_report_from_artifacts(
            project=repo,
            scanner=scanner,
            token=ci_token,
            pipeline_id=pipeline_id or None,
        )
        if ci_result and ci_result.get("payload") is not None:
            pid = ci_result.get("pipeline_id")
            gl_meta = {
                "source": "gitlab-artifact",
                "scanner": scanner,
                "project": repo,
                "pipeline_id": pid,
                "job_id": ci_result.get("job_id"),
                "job_name": ci_result.get("job_name"),
                "zip_entry": ci_result.get("zip_entry"),
            }
            if pid:
                enc = quote(repo, safe="")
                gl_meta["pipeline_url"] = f"https://gitlab.com/{enc}/-/pipelines/{pid}"
            gl_meta.update(_hints_from_vuln_payload(ci_result["payload"]))
            return jsonify(with_report_meta(ci_result["payload"], gl_meta))
        if source == "ci":
            return jsonify({"status": "error", "message": ci_error or "No CI report found"}), 404
    else:
        ci_token = token or os.getenv("GITHUB_TOKEN", "").strip()
        ci_result, ci_error = fetch_github_report_from_artifacts(
            repo=repo,
            scanner=scanner,
            token=ci_token,
            run_id=run_id or None,
        )
        if ci_result and ci_result.get("payload") is not None:
            rid = ci_result.get("run_id")
            gh_meta = {
                "source": "github-artifact",
                "scanner": scanner,
                "project": repo,
                "run_id": rid,
                "artifact_name": ci_result.get("artifact_name"),
                "zip_entry": ci_result.get("zip_entry"),
            }
            if rid:
                gh_meta["run_url"] = f"https://github.com/{repo}/actions/runs/{rid}"
                gh_meta["artifacts_url"] = f"https://github.com/{repo}/actions/runs/{rid}#artifacts"
            gh_meta.update(_hints_from_vuln_payload(ci_result["payload"]))
            return jsonify(with_report_meta(ci_result["payload"], gh_meta))
        if source == "ci":
            return jsonify({"status": "error", "message": ci_error or "No CI report found"}), 404

    if source == "auto":
        return jsonify(
            {
                "status": "error",
                "message": "No CI vulnerability report found. Use source=local for the last server-side scan (after upload/generate).",
            }
        ), 404

    return jsonify({"status": "error", "message": "No CI report found"}), 404


@app.route("/api/project")
def project_info():
    """Default branch + path for Launch UI (avoids GitLab 400 when ref does not exist)."""
    provider = get_requested_provider()
    repo = get_requested_repo()
    if provider == "gitlab":
        token = get_requested_token() or os.getenv("GITLAB_TOKEN", "")
        if not token:
            return jsonify(
                {
                    "default_branch": "main",
                    "path_with_namespace": repo,
                    "message": "Connect with a GitLab token to read default branch",
                }
            )
        encoded = quote(repo, safe="")
        status, out = gitlab_api(f"projects/{encoded}", token=token)
        if status >= 300:
            return jsonify(
                {
                    "default_branch": "main",
                    "path_with_namespace": repo,
                    "message": gitlab_error_message(out),
                }
            )
        try:
            data = json.loads(out)
        except Exception:
            data = {}
        return jsonify(
            {
                "default_branch": data.get("default_branch") or "main",
                "path_with_namespace": data.get("path_with_namespace") or repo,
            }
        )

    token = _github_token_for_request()
    status, out = github_rest_request(f"repos/{repo}", "GET", token)
    if status >= 300:
        return jsonify({"default_branch": "main", "full_name": repo, "message": "Could not read repository metadata"})
    try:
        data = json.loads(out)
    except Exception:
        data = {}
    return jsonify(
        {
            "default_branch": data.get("default_branch") or "main",
            "full_name": data.get("full_name") or repo,
        }
    )


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
            return jsonify({"message": gitlab_error_message(out) or "Failed to fetch GitLab pipelines"}), 500
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
    variables = body.get("variables") or []
    var_map = {}
    if isinstance(variables, list):
        for item in variables:
            if not isinstance(item, dict):
                continue
            k = str(item.get("key") or "").strip()
            v = str(item.get("value") or "").strip()
            if k:
                var_map[k] = v
    app_dir = str(body.get("app_dir") or var_map.get("APP_DIR") or "example-app").strip() or "example-app"
    app_version = str(body.get("app_version") or var_map.get("APP_VERSION") or "1.0.0").strip() or "1.0.0"

    if provider == "gitlab":
        encoded_project = quote(repo, safe="")
        trigger_note = None
        trigger_token = str(body.get("trigger_token") or "").strip() or os.getenv("GITLAB_TRIGGER_TOKEN", "")
        if trigger_token:
            query = urlencode(
                {
                    "token": trigger_token,
                    "ref": str(ref),
                    "variables[APP_DIR]": app_dir,
                    "variables[APP_VERSION]": app_version,
                }
            )
            status, out = gitlab_api(f"projects/{encoded_project}/trigger/pipeline?{query}", method="POST")
        else:
            if not token:
                return jsonify({"message": "GitLab token required to trigger pipeline. Set GITLAB_TOKEN or provide token in Connect."}), 400
            status, out = gitlab_api(
                f"projects/{encoded_project}/pipeline",
                method="POST",
                token=token,
                data={
                    "ref": str(ref),
                    "variables": [
                        {"key": "APP_DIR", "value": app_dir},
                        {"key": "APP_VERSION", "value": app_version},
                    ],
                },
            )
            if status >= 300:
                msg = gitlab_error_message(out)
                http_status = status if 300 <= status < 600 else 500
                # Developer tokens often cannot set pipeline variables; retry ref-only (uses .gitlab-ci.yml defaults).
                if http_status in (400, 403) and (
                    "variable" in msg.lower()
                    and ("permission" in msg.lower() or "insufficient" in msg.lower())
                ):
                    status, out = gitlab_api(
                        f"projects/{encoded_project}/pipeline",
                        method="POST",
                        token=token,
                        data={"ref": str(ref)},
                    )
                    if status < 300:
                        trigger_note = (
                            "Pipeline started using CI defaults from .gitlab-ci.yml "
                            "(this token cannot override pipeline variables; Maintainer or a trigger token can)."
                        )
                    else:
                        msg2 = gitlab_error_message(out)
                        st2 = status if 300 <= status < 600 else 500
                        if st2 >= 500:
                            return jsonify({"message": msg2 or msg or "Failed to trigger GitLab pipeline"}), 500
                        return jsonify({"message": msg2 or msg or "Failed to trigger GitLab pipeline"}), st2
                else:
                    if http_status >= 500:
                        return jsonify({"message": msg or "Failed to trigger GitLab pipeline"}), 500
                    return jsonify({"message": msg or "Failed to trigger GitLab pipeline"}), http_status
        if status >= 300:
            msg = gitlab_error_message(out)
            http_status = status if 300 <= status < 600 else 500
            if http_status >= 500:
                return jsonify({"message": msg or "Failed to trigger GitLab pipeline"}), 500
            return jsonify({"message": msg or "Failed to trigger GitLab pipeline"}), http_status
        try:
            created = json.loads(out)
        except Exception:
            created = {}
        return jsonify(
            {
                "id": created.get("id"),
                "status": map_gitlab_status(created.get("status") or "pending"),
                "html_url": created.get("web_url"),
                "message": trigger_note or "Pipeline trigger submitted",
            }
        )

    token = _github_token_for_request()
    ref_full = str(ref) if str(ref).startswith("refs/") else f"refs/heads/{ref}"
    wf_enc = quote(workflow, safe="")

    if token:
        dispatch_path = f"repos/{repo}/actions/workflows/{wf_enc}/dispatches"
        code, body = github_rest_request(
            dispatch_path,
            "POST",
            token,
            json_body={
                "ref": ref_full,
                "inputs": {
                    "app_dir": app_dir,
                    "app_version": app_version,
                },
            },
        )
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
