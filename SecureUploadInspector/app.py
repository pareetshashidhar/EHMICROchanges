"""
SecureUpload Inspector - Application Entrypoint and Routing
===========================================================
Flask web application implementing SOC dashboard, file ingestion,
paginated history, settings management, and security reporting.
"""

import os
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    jsonify, Response, abort
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from werkzeug.exceptions import RequestEntityTooLarge

from config import get_config, Config
from storage.database import (
    init_db,
    get_dashboard_statistics,
    list_inspections,
    list_inspections_paginated,
    get_inspection_by_id,
    get_all_settings,
    get_setting,
    save_setting,
)
from storage.audit_log import log_audit_event
from services.inspection_service import inspect_and_record_file
from services.report_service import generate_inspection_report, export_json_report

def create_app(config_class: type[Config] | None = None) -> Flask:
    """Application factory for SecureUpload Inspector."""
    app = Flask(__name__)
    
    # Load configuration profile
    active_config = config_class or get_config()
    app.config.from_object(active_config)

    # Ensure required runtime folders exist outside public web root
    if app.config["DATABASE_PATH"] != ":memory:":
        Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True)
    Path(app.config["ACCEPTED_STORAGE_DIR"]).mkdir(parents=True, exist_ok=True)
    Path(app.config["QUARANTINE_DIR"]).mkdir(parents=True, exist_ok=True)

    # Initialize SQLite database schema & defaults
    init_db(app.config["DATABASE_PATH"])

    # Enable CSRF Protection
    csrf = CSRFProtect(app)

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none';"
        )
        return response

    # ------------------------------------------------------------------
    # Application Routes
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        """Render SOC overview dashboard using live database statistics."""
        stats = get_dashboard_statistics(app.config["DATABASE_PATH"])
        return render_template("dashboard.html", stats=stats)

    @app.route("/upload", methods=["GET", "POST"])
    def upload_page():
        """File upload form view (GET) and inspection processor (POST)."""
        db_path = app.config["DATABASE_PATH"]

        if request.method == "POST":
            # Check if file part is present
            if "file" not in request.files:
                if request.is_json or request.headers.get("Accept") == "application/json":
                    return jsonify({"error": "No file part provided in request."}), 400
                flash("No file part provided in request.", "error")
                return redirect(request.url), 400

            uploaded_files = request.files.getlist("file")
            # Filter out empty entries
            valid_files = [f for f in uploaded_files if f and f.filename and f.filename.strip()]

            if not valid_files:
                if request.is_json or request.headers.get("Accept") == "application/json":
                    return jsonify({"error": "No file was selected for inspection."}), 400
                flash("No file was selected for inspection.", "warning")
                return redirect(request.url), 400

            # Check per-request file count limit
            max_files = int(get_setting(db_path, "max_files_per_request", app.config["MAX_FILES_PER_REQUEST"]))
            if len(valid_files) > max_files:
                err_msg = f"Request exceeded maximum permissible file count ({len(valid_files)} > {max_files})."
                if request.is_json or request.headers.get("Accept") == "application/json":
                    return jsonify({"error": err_msg}), 400
                flash(err_msg, "error")
                return redirect(request.url), 400

            client_ip = request.remote_addr or "127.0.0.1"
            inspected_records = []

            for u_file in valid_files:
                raw_filename = u_file.filename
                browser_mime = u_file.content_type
                file_bytes = u_file.read()

                try:
                    record = inspect_and_record_file(
                        file_source=file_bytes,
                        original_filename=raw_filename,
                        browser_mime=browser_mime,
                        client_ip=client_ip,
                        config=active_config
                    )
                    inspected_records.append(record)
                except Exception as e:
                    app.logger.error(f"Inspection error on file {raw_filename}: {e}")
                    # Sanitized error display: do not expose internal paths or tracebacks
                    if request.is_json or request.headers.get("Accept") == "application/json":
                        return jsonify({"error": "Failed to process file inspection due to internal error."}), 500
                    flash(f"Error inspecting '{raw_filename}'. Please verify file integrity.", "error")
                    return redirect(request.url), 500

            # Response for JSON API clients
            if request.is_json or request.headers.get("Accept") == "application/json":
                if len(inspected_records) == 1:
                    rec = inspected_records[0]
                    status_code = 200 if rec["decision"] == "ACCEPTED" else 422
                    return jsonify(rec), status_code
                else:
                    return jsonify({"inspections": inspected_records}), 200

            # Flash notifications for HTML client
            for rec in inspected_records:
                name = rec["original_filename"]
                if rec["decision"] == "ACCEPTED":
                    flash(f"Inspection Complete: '{name}' conforms to upload security policies.", "success")
                elif rec["decision"] == "REJECTED":
                    flash(f"Security Alert: '{name}' was REJECTED due to policy violations.", "danger")
                else:
                    flash(f"Review Required: '{name}' flagged with security warnings.", "warning")

            # Redirect to results page for the single file, or history if multiple
            if len(inspected_records) == 1:
                return redirect(url_for("results_page", inspection_id=inspected_records[0]["id"]))
            return redirect(url_for("history_page"))

        # GET request: load active configuration for display in upload view
        active_settings = get_all_settings(db_path)
        return render_template("upload.html", settings=active_settings)

    @app.route("/results/<inspection_id>")
    def results_page(inspection_id: str):
        """Display immediate results following upload."""
        record = get_inspection_by_id(app.config["DATABASE_PATH"], inspection_id)
        if not record:
            abort(404, description=f"Inspection record '{inspection_id}' not found.")
        return render_template("results.html", record=record)

    @app.route("/inspection/<inspection_id>")
    def inspection_detail(inspection_id: str):
        """Display comprehensive inspection report and audit trail."""
        record = get_inspection_by_id(app.config["DATABASE_PATH"], inspection_id)
        if not record:
            abort(404, description=f"Inspection record '{inspection_id}' not found.")
        return render_template("inspection_detail.html", record=record)

    @app.route("/inspection/<inspection_id>/report")
    def inspection_report_text(inspection_id: str):
        """Export formatted plain-text cybersecurity inspection audit report."""
        record = get_inspection_by_id(app.config["DATABASE_PATH"], inspection_id)
        if not record:
            abort(404, description=f"Inspection record '{inspection_id}' not found.")
        report_text = generate_inspection_report(record)
        return Response(report_text, mimetype="text/plain", headers={
            "Content-Disposition": f"inline; filename=audit-report-{inspection_id[:8]}.txt"
        })

    @app.route("/inspection/<inspection_id>/report.json")
    @app.route("/inspection/<inspection_id>/json")
    def inspection_report_json(inspection_id: str):
        """Export machine-readable JSON security audit record."""
        record = get_inspection_by_id(app.config["DATABASE_PATH"], inspection_id)
        if not record:
            abort(404, description=f"Inspection record '{inspection_id}' not found.")
        json_report = export_json_report(record)
        return Response(json_report, mimetype="application/json", headers={
            "Content-Disposition": f"attachment; filename=inspection-{inspection_id[:8]}.json"
        })

    @app.route("/history")
    def history_page():
        """Browse paginated and searchable audit log of past inspections."""
        db_path = app.config["DATABASE_PATH"]
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 10, type=int)
        decision_filter = request.args.get("decision", "ALL")
        type_filter = request.args.get("file_type", "ALL")
        search_query = request.args.get("q", "")

        pagination = list_inspections_paginated(
            db_path=db_path,
            page=page,
            per_page=per_page,
            decision_filter=decision_filter,
            type_filter=type_filter,
            search_query=search_query
        )

        return render_template(
            "history.html",
            inspections=pagination["items"],
            pagination=pagination,
            current_decision=decision_filter,
            current_type=type_filter,
            current_query=search_query
        )

    @app.route("/settings", methods=["GET", "POST"], endpoint="settings_page")
    def settings_page():
        """View (GET) and safely update (POST) system security policies."""
        db_path = app.config["DATABASE_PATH"]
        predefined_extensions = app.config["PREDEFINED_ALLOWED_EXTENSIONS"]

        if request.method == "POST":
            # 1. Validate max file size
            try:
                max_size_mb = int(request.form.get("max_file_size_mb", 10))
                if max_size_mb < 1 or max_size_mb > 50:
                    flash("Maximum file size must be an integer between 1 MB and 50 MB.", "error")
                    current_settings = get_all_settings(db_path)
                    return render_template(
                        "settings.html",
                        settings=current_settings,
                        predefined_extensions=sorted(list(predefined_extensions)),
                        config=app.config
                    ), 400
            except (ValueError, TypeError):
                flash("Invalid maximum file size value submitted.", "error")
                current_settings = get_all_settings(db_path)
                return render_template(
                    "settings.html",
                    settings=current_settings,
                    predefined_extensions=sorted(list(predefined_extensions)),
                    config=app.config
                ), 400

            # 2. Validate max files per request
            try:
                max_files = int(request.form.get("max_files_per_request", 5))
                if max_files < 1 or max_files > 10:
                    flash("Maximum files per request must be between 1 and 10.", "error")
                    current_settings = get_all_settings(db_path)
                    return render_template(
                        "settings.html",
                        settings=current_settings,
                        predefined_extensions=sorted(list(predefined_extensions)),
                        config=app.config
                    ), 400
            except (ValueError, TypeError):
                flash("Invalid max files per request value submitted.", "error")
                current_settings = get_all_settings(db_path)
                return render_template(
                    "settings.html",
                    settings=current_settings,
                    predefined_extensions=sorted(list(predefined_extensions)),
                    config=app.config
                ), 400

            # 3. Validate allowed extensions against predefined safe set
            submitted_exts = request.form.getlist("allowed_extensions")
            if not submitted_exts:
                flash("At least one permitted extension must be selected.", "error")
                current_settings = get_all_settings(db_path)
                return render_template(
                    "settings.html",
                    settings=current_settings,
                    predefined_extensions=sorted(list(predefined_extensions)),
                    config=app.config
                ), 400

            for ext in submitted_exts:
                if ext not in predefined_extensions:
                    flash(f"Unauthorized extension '{ext}'. Only predefined safe extensions are permitted.", "error")
                    current_settings = get_all_settings(db_path)
                    return render_template(
                        "settings.html",
                        settings=current_settings,
                        predefined_extensions=sorted(list(predefined_extensions)),
                        config=app.config
                    ), 400

            # 4. Booleans: require_review_ambiguous, discard_rejected
            require_review = request.form.get("require_review_ambiguous") in ("on", "true", "1")
            discard_rejected = request.form.get("discard_rejected") in ("on", "true", "1")

            # Save validated settings into SQLite
            save_setting(db_path, "max_file_size_mb", max_size_mb)
            save_setting(db_path, "max_files_per_request", max_files)
            save_setting(db_path, "allowed_extensions", sorted(list(submitted_exts)))
            save_setting(db_path, "require_review_ambiguous", require_review)
            save_setting(db_path, "discard_rejected", discard_rejected)

            # Log audit event
            log_audit_event(
                db_path=db_path,
                event_type="CONFIGURATION_UPDATE",
                severity="INFO",
                details={
                    "max_file_size_mb": max_size_mb,
                    "max_files_per_request": max_files,
                    "allowed_extensions": submitted_exts,
                    "require_review_ambiguous": require_review,
                    "discard_rejected": discard_rejected,
                    "client_ip": request.remote_addr or "127.0.0.1"
                },
                log_file_path=app.config["AUDIT_LOG_PATH"]
            )

            flash("Security policies and upload configuration updated successfully.", "success")
            return redirect(url_for("settings_page"))

        # GET request: load current settings
        current_settings = get_all_settings(db_path)
        return render_template(
            "settings.html",
            settings=current_settings,
            predefined_extensions=sorted(list(predefined_extensions)),
            config=app.config
        )

    @app.route("/policies", endpoint="policies_page")
    def policies_page():
        """Alias route for policies page."""
        return settings_page()

    @app.route("/about")
    def about_page():
        """View project architecture, threat model, and academic rationale."""
        return render_template("about.html")

    # ------------------------------------------------------------------
    # Error Handlers
    # ------------------------------------------------------------------

    @app.errorhandler(400)
    def bad_request_error(e):
        return render_template(
            "error.html",
            error_code=400,
            error_title="Bad Request",
            error_message="The request was invalid or lacked required security parameters."
        ), 400

    @app.errorhandler(CSRFError)
    def csrf_token_error(e):
        return render_template(
            "error.html",
            error_code=400,
            error_title="CSRF Token Missing or Expired",
            error_message="Form security validation failed. Please refresh the page and try again."
        ), 400

    @app.errorhandler(404)
    def not_found_error(e):
        return render_template(
            "error.html",
            error_code=404,
            error_title="Resource Not Found",
            error_message="The requested inspection or endpoint does not exist."
        ), 404

    @app.errorhandler(RequestEntityTooLarge)
    @app.errorhandler(413)
    def file_too_large_error(e):
        max_mb = app.config.get("MAX_FILE_SIZE", 10485760) // (1024 * 1024)
        return render_template(
            "error.html",
            error_code=413,
            error_title="File Size Boundary Exceeded",
            error_message=f"The uploaded file exceeds the maximum permissible limit of {max_mb} MB."
        ), 413

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template(
            "error.html",
            error_code=500,
            error_title="Internal Processing Error",
            error_message="An internal error occurred while processing the security inspection."
        ), 500

    return app

# WSGI Application Instance
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="127.0.0.1", port=port, debug=False)
