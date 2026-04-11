"""
Parse app dependency metadata from JSON, CSV, or XML into the canonical
app-metadata shape used by merge-sbom.ps1 and the SBOM pipeline.
"""

from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def _local_tag(elem: ET.Element) -> str:
    return (elem.tag or "").split("}")[-1].strip().lower()


def _urls_from_cell(val: Any) -> List[str]:
    if val is None:
        return []
    s = str(val).strip()
    if not s:
        return []
    parts = re.split(r"[|;,\n]+", s)
    return [p.strip() for p in parts if p.strip()]


def _parse_supplier_block(el: ET.Element) -> Dict[str, Any]:
    name = ""
    urls: List[str] = []
    for child in el:
        t = _local_tag(child)
        txt = (child.text or "").strip()
        if t == "name" and txt:
            name = txt
        elif t == "url":
            if txt:
                urls.append(txt)
        elif t == "urls":
            urls.extend(_urls_from_cell(txt))
    name_attr = el.get("name")
    if name_attr and not name:
        name = str(name_attr).strip()
    u_attr = el.get("url")
    if u_attr:
        urls.extend(_urls_from_cell(u_attr))
    return {"name": name or "Unknown", "url": urls}


def _xml_root_to_dict(root: ET.Element) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for child in root:
        if not isinstance(child.tag, str):
            continue
        t = _local_tag(child)
        txt = (child.text or "").strip()
        if t == "supplier":
            out["supplier"] = _parse_supplier_block(child)
            continue
        if len(child) and t != "supplier":
            # nested non-supplier: flatten first text child only for known keys
            continue
        if txt:
            out[t.replace("-", "_")] = txt
    return out


def parse_app_metadata_xml(content: str) -> Dict[str, Any]:
    root = ET.fromstring(content)
    data = _xml_root_to_dict(root)
    # Also allow attributes on root (name=, version=)
    for attr in ("name", "version", "license", "language", "author"):
        v = root.get(attr)
        if v and not data.get(attr):
            data[attr] = v.strip()
    return data


def parse_app_metadata_csv(content: str) -> Dict[str, Any]:
    s = content.lstrip("\ufeff")
    if not s.strip():
        return {}
    rdr = csv.DictReader(io.StringIO(s))
    rows = list(rdr)
    if not rows:
        return {}
    row = rows[0]
    # Normalize header keys to lowercase strip
    lc = {((k or "").strip().lower()): (v.strip() if isinstance(v, str) else v) for k, v in row.items() if k}
    return dict(lc)


def parse_app_metadata_json(content: str) -> Dict[str, Any]:
    return json.loads(content)


def normalize_app_metadata_dict(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Merge parsed (possibly flat CSV / partial XML) into canonical app-metadata.json shape."""
    lc = {str(k).strip().lower(): v for k, v in raw.items() if k is not None}

    name = str(lc.get("name") or lc.get("component_name") or "custom-cpp-app").strip() or "custom-cpp-app"
    version = str(lc.get("version") or "1.0.0").strip() or "1.0.0"
    description = str(lc.get("description") or f"{name} (app metadata)").strip()
    language = str(lc.get("language") or "C++").strip() or "C++"
    author = (str(lc.get("author") or "Unknown")).strip() or "Unknown"
    repository = (str(lc.get("repository") or lc.get("repo") or "")).strip()
    build_system = str(lc.get("build_system") or lc.get("build") or "unknown").strip() or "unknown"
    entry_point = str(lc.get("entry_point") or "main").strip() or "main"
    source_file = str(lc.get("source_file") or "src/main.cpp").strip() or "src/main.cpp"
    license_id = str(lc.get("license") or "MIT").strip() or "MIT"
    component_type = str(lc.get("component_type") or "application").strip() or "application"

    if isinstance(raw.get("supplier"), dict):
        sup_nm = raw["supplier"].get("name")
    else:
        sup_nm = lc.get("supplier_name") or lc.get("supplier")
    supplier_name = str(sup_nm or "Unknown").strip() or "Unknown"
    url_cell = lc.get("supplier_url") or lc.get("supplier_urls") or ""
    urls: List[str] = []
    if isinstance(raw.get("supplier"), dict):
        u = raw["supplier"].get("url")
        if isinstance(u, list):
            urls.extend(str(x).strip() for x in u if str(x).strip())
        elif isinstance(u, str) and u.strip():
            urls.extend(_urls_from_cell(u))
    urls.extend(_urls_from_cell(url_cell))
    # de-dupe preserve order
    seen = set()
    uniq = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            uniq.append(u)

    purl = str(lc.get("purl") or "").strip()
    cpe = str(lc.get("cpe") or "").strip()

    out: Dict[str, Any] = {
        "name": name,
        "component_type": component_type,
        "version": version,
        "description": description,
        "language": language,
        "author": author,
        "license": license_id,
        "build_system": build_system,
        "entry_point": entry_point,
        "source_file": source_file,
        "repository": repository,
        "supplier": {"name": supplier_name, "url": uniq},
    }
    if purl:
        out["purl"] = purl
    if cpe:
        out["cpe"] = cpe
    return out


def parse_app_metadata_bytes(content: bytes, filename: str) -> Dict[str, Any]:
    if not content:
        raise ValueError("Empty file")
    ext = (filename or "").rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    text = content.decode("utf-8-sig")

    if ext == "json" or (ext == "" and text.strip().startswith("{")):
        raw = parse_app_metadata_json(text)
        if not isinstance(raw, dict):
            raise ValueError("JSON metadata must be an object")
    elif ext == "csv":
        raw = parse_app_metadata_csv(text)
    elif ext == "xml":
        raw = parse_app_metadata_xml(text)
    else:
        # Best-effort by content
        t = text.strip()
        if t.startswith("{") or t.startswith("["):
            parsed = json.loads(text)
            if not isinstance(parsed, dict):
                raise ValueError("JSON metadata must be an object")
            raw = parsed
        elif t.startswith("<"):
            raw = parse_app_metadata_xml(text)
        else:
            raw = parse_app_metadata_csv(text)

    return normalize_app_metadata_dict(raw)


def app_metadata_to_json_bytes(data: Dict[str, Any]) -> bytes:
    return (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
