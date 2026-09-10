"""
SOC-Insight application server.

Serves the JSON API the frontend consumes, plus the static frontend itself.
State lives in one in-memory Pipeline instance (see src/soc_insight/pipeline.py) --
this is a local security lab, not a multi-user production service.

Run with:
    python app.py
Then open http://127.0.0.1:5000
"""
from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running this file directly (python app.py) without installing the
# package or setting PYTHONPATH: src/ holds the soc_insight package.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from flask import Flask, jsonify, request, send_from_directory

from soc_insight.analysis import get_default_provider
from soc_insight.ingestion.parsers import FileTooLargeError
from soc_insight.pipeline import Pipeline
from soc_insight.reports import generate_report

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
DEMO_DATA_DIR = BASE_DIR / "data" / "scenarios"

app = Flask(__name__, static_folder=None)
pipeline = Pipeline()


def _load_demo():
    pipeline.load_demo_data(str(DEMO_DATA_DIR))
    pipeline.run_pipeline()


_load_demo()


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    # Only ever serves files that already exist under frontend/; Flask's
    # send_from_directory rejects path traversal attempts on its own.
    if (FRONTEND_DIR / filename).is_file():
        return send_from_directory(FRONTEND_DIR, filename)
    return send_from_directory(FRONTEND_DIR, "index.html")


# ---------------------------------------------------------------------------
# Dashboard / overview
# ---------------------------------------------------------------------------
@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(pipeline.dashboard_summary())


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------
@app.route("/api/incidents")
def api_incidents():
    severity = request.args.get("severity")
    status = request.args.get("status")
    incidents = pipeline.incidents
    if severity:
        incidents = [i for i in incidents if i.severity == severity.upper()]
    if status:
        incidents = [i for i in incidents if i.status == status.upper()]
    return jsonify([pipeline.incident_to_dict(i) for i in incidents])


@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    return jsonify(pipeline.incident_to_dict(incident))


@app.route("/api/incidents/<incident_id>/status", methods=["POST"])
def api_incident_status(incident_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    valid = {"NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"}
    if status not in valid:
        return jsonify({"error": f"status must be one of {sorted(valid)}"}), 400
    incident.status = status
    if status == "FALSE_POSITIVE":
        incident.classification = "FALSE_POSITIVE"
    return jsonify(pipeline.incident_to_dict(incident))


@app.route("/api/incidents/<incident_id>/classification", methods=["POST"])
def api_incident_classification(incident_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    body = request.get_json(silent=True) or {}
    classification = body.get("classification")
    valid = {"TRUE_POSITIVE", "FALSE_POSITIVE", "BENIGN_ACTIVITY", "UNRESOLVED"}
    if classification not in valid:
        return jsonify({"error": f"classification must be one of {sorted(valid)}"}), 400
    incident.classification = classification
    return jsonify(pipeline.incident_to_dict(incident))


@app.route("/api/incidents/<incident_id>/notes", methods=["POST"])
def api_incident_notes(incident_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    body = request.get_json(silent=True) or {}
    note_text = (body.get("note") or "").strip()
    if not note_text:
        return jsonify({"error": "note text is required"}), 400
    if len(note_text) > 4000:
        return jsonify({"error": "note is too long (4000 character limit)"}), 400
    incident.analyst_notes.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "author": (body.get("author") or "analyst")[:80],
        "note": note_text,
    })
    return jsonify(pipeline.incident_to_dict(incident))


@app.route("/api/incidents/<incident_id>/evidence/<event_id>", methods=["POST"])
def api_classify_evidence(incident_id, event_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    body = request.get_json(silent=True) or {}
    classification = body.get("classification")
    valid = {"CONFIRMED", "SUSPICIOUS", "BENIGN", "UNKNOWN"}
    if classification not in valid:
        return jsonify({"error": f"classification must be one of {sorted(valid)}"}), 400
    incident.evidence_classifications[event_id] = classification
    return jsonify(pipeline.incident_to_dict(incident))


@app.route("/api/incidents/<incident_id>/report")
def api_incident_report(incident_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    incident_dict = pipeline.incident_to_dict(incident)
    all_iocs = [ioc.to_dict() for ioc in pipeline.iocs]
    report_text = generate_report(incident_dict, all_iocs, provider=get_default_provider())
    return jsonify({"incident_id": incident_id, "report": report_text})


@app.route("/api/incidents/<incident_id>/analysis")
def api_incident_analysis(incident_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    incident_dict = pipeline.incident_to_dict(incident)
    provider = get_default_provider()
    return jsonify({
        "summary": provider.summarize_incident(incident_dict),
        "evidence_explanations": provider.explain_evidence(incident_dict),
        "investigation_suggestions": provider.investigation_suggestions(incident_dict),
        "executive_summary": provider.executive_summary(incident_dict),
        "technical_summary": provider.technical_summary(incident_dict),
    })


@app.route("/api/incidents/<incident_id>/attack-chain")
def api_attack_chain(incident_id):
    incident = pipeline.get_incident(incident_id)
    if not incident:
        return jsonify({"error": "incident not found"}), 404
    from soc_insight.incidents import attack_chain
    return jsonify(attack_chain(incident))


# ---------------------------------------------------------------------------
# Events / event explorer
# ---------------------------------------------------------------------------
@app.route("/api/events")
def api_events():
    limit = min(int(request.args.get("limit", 200)), 2000)
    events = sorted(pipeline.events, key=lambda e: e.timestamp, reverse=True)[:limit]
    return jsonify([e.to_dict() for e in events])


@app.route("/api/events/<event_id>")
def api_event_detail(event_id):
    event = pipeline.get_event(event_id)
    if not event:
        return jsonify({"error": "event not found"}), 404
    return jsonify(event.to_dict())


@app.route("/api/ingestion-issues")
def api_ingestion_issues():
    return jsonify([i.to_dict() for i in pipeline.ingestion_issues])


# ---------------------------------------------------------------------------
# Threat hunting
# ---------------------------------------------------------------------------
@app.route("/api/hunt")
def api_hunt():
    query = request.args.get("q", "").strip()
    if not query:
        return jsonify({"query": "", "match_count": 0, "events": [], "related_incidents": []})
    return jsonify(pipeline.search(query))


# ---------------------------------------------------------------------------
# Detection rules / MITRE / IOCs
# ---------------------------------------------------------------------------
@app.route("/api/rules")
def api_rules():
    return jsonify(pipeline.rules_catalog())


@app.route("/api/mitre")
def api_mitre():
    return jsonify(pipeline.mitre_matrix())


@app.route("/api/iocs")
def api_iocs():
    ioc_type = request.args.get("type")
    iocs = pipeline.iocs
    if ioc_type:
        iocs = [i for i in iocs if i.ioc_type == ioc_type]
    return jsonify([i.to_dict() for i in iocs])


# ---------------------------------------------------------------------------
# Data ingestion (upload a new synthetic log file and re-run detection)
# ---------------------------------------------------------------------------
ALLOWED_UPLOAD_EXTENSIONS = {".json", ".ndjson", ".jsonl", ".csv", ".log", ".txt"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


@app.route("/api/ingest", methods=["POST"])
def api_ingest():
    if "file" not in request.files:
        return jsonify({"error": "no file uploaded (multipart field 'file')"}), 400
    upload = request.files["file"]
    filename = os.path.basename(upload.filename or "")
    if not filename:
        return jsonify({"error": "missing filename"}), 400
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return jsonify({"error": f"unsupported file extension '{ext}'"}), 400

    raw_bytes = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(raw_bytes) > MAX_UPLOAD_BYTES:
        return jsonify({"error": "file exceeds the 10 MB ingestion limit"}), 413

    try:
        result = pipeline.ingest_bytes(raw_bytes, filename)
    except FileTooLargeError as e:
        return jsonify({"error": str(e)}), 413

    stats = pipeline.run_pipeline()
    return jsonify({"ingested": result, "pipeline": stats})


@app.route("/api/reset-demo", methods=["POST"])
def api_reset_demo():
    global pipeline
    pipeline = Pipeline()
    _load_demo()
    return jsonify(pipeline.dashboard_summary())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False)
