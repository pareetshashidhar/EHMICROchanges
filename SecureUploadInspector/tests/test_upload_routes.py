"""
SecureUpload Inspector - Route & Web Ingestion Tests
====================================================
Tests Flask endpoints, multipart upload handling, JSON API, settings configuration,
CSRF behavior, HTML escaping, and error responses.
"""

import io
from flask import url_for

def test_dashboard_route_status_200(client):
    """Verify home dashboard renders with status 200."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"SecureUpload" in response.data
    assert b"Security Operations Dashboard" in response.data

def test_upload_page_get_status_200(client):
    """Verify upload page renders with file picker and policies."""
    response = client.get("/upload")
    assert response.status_code == 200
    assert b"Secure File Ingestion" in response.data
    assert b"upload-dropzone" in response.data

def test_upload_post_valid_png_redirects_to_results(client, sample_png_bytes):
    """Verify valid PNG upload completes and redirects to results view."""
    data = {
        "file": (io.BytesIO(sample_png_bytes), "sample_badge.png", "image/png")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 302
    assert "/results/" in response.headers["Location"]

def test_upload_post_valid_jpeg_accepted(client, sample_jpeg_bytes):
    """Verify genuine JPEG upload is accepted."""
    data = {
        "file": (io.BytesIO(sample_jpeg_bytes), "photo.jpg", "image/jpeg")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    res_json = response.get_json()
    assert res_json["decision"] == "ACCEPTED"
    assert res_json["detected_type"] == "jpeg"

def test_upload_post_probable_text(client, sample_text_bytes):
    """Verify plain text file is processed with cautious text heuristics."""
    data = {
        "file": (io.BytesIO(sample_text_bytes), "audit_notes.txt", "text/plain")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
        headers={"Accept": "application/json"}
    )
    # Plain text may receive ACCEPTED or REVIEW_REQUIRED (with cautious heuristic)
    assert response.status_code in (200, 422)
    res_json = response.get_json()
    assert res_json["detected_type"] == "probable_text"

def test_upload_post_spoofed_executable_rejected(client, sample_exe_bytes):
    """Verify upload of disguised executable results in REJECTED record."""
    data = {
        "file": (io.BytesIO(sample_exe_bytes), "document.pdf", "application/pdf")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 302
    results_url = response.headers["Location"]
    detail_res = client.get(results_url)
    assert detail_res.status_code == 200
    assert b"REJECTED" in detail_res.data

def test_upload_post_extension_signature_mismatch(client, sample_png_bytes):
    """Verify extension claiming to be PDF but having PNG bytes is rejected."""
    data = {
        "file": (io.BytesIO(sample_png_bytes), "report.pdf", "application/pdf")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 422
    res_json = response.get_json()
    assert res_json["decision"] == "REJECTED"
    assert any(f["rule_id"] == "POL-AGREE-001" for f in res_json["findings"])

def test_upload_post_disallowed_extension_rejected(client, sample_pdf_bytes):
    """Verify disallowed extension is rejected."""
    data = {
        "file": (io.BytesIO(sample_pdf_bytes), "exploit.exe", "application/octet-stream")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 422
    assert response.get_json()["decision"] == "REJECTED"

def test_upload_post_missing_file_part_returns_400(client):
    """Verify request missing file part returns 400 Bad Request."""
    response = client.post("/upload", data={}, content_type="multipart/form-data")
    assert response.status_code == 400

def test_upload_post_empty_filename_returns_400(client):
    """Verify request with empty filename returns 400 Bad Request."""
    data = {
        "file": (io.BytesIO(b"content"), "", "application/pdf")
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 400

def test_upload_post_zero_byte_file_rejected(client, sample_zero_bytes):
    """Verify zero-byte upload receives REJECTED verdict."""
    data = {
        "file": (io.BytesIO(sample_zero_bytes), "zero.pdf", "application/pdf")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 422
    assert response.get_json()["decision"] == "REJECTED"

def test_upload_post_multiple_files_within_limit(client, sample_pdf_bytes, sample_png_bytes):
    """Verify uploading multiple files within the configured limit succeeds."""
    data = {
        "file": [
            (io.BytesIO(sample_pdf_bytes), "doc1.pdf", "application/pdf"),
            (io.BytesIO(sample_png_bytes), "doc2.png", "image/png"),
        ]
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 200
    res_json = response.get_json()
    assert "inspections" in res_json
    assert len(res_json["inspections"]) == 2

def test_upload_post_multiple_files_exceeding_limit(client, sample_pdf_bytes):
    """Verify uploading more files than MAX_FILES_PER_REQUEST returns 400."""
    data = {
        "file": [
            (io.BytesIO(sample_pdf_bytes), f"file_{i}.pdf", "application/pdf")
            for i in range(10)  # 10 files exceeds default limit of 5
        ]
    }
    response = client.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 400

def test_upload_post_path_traversal_filename_rejected(client, sample_pdf_bytes):
    """Verify upload with path traversal in filename receives REJECTED decision."""
    data = {
        "file": (io.BytesIO(sample_pdf_bytes), "../../etc/shadow.pdf", "application/pdf")
    }
    response = client.post(
        "/upload",
        data=data,
        content_type="multipart/form-data",
        headers={"Accept": "application/json"}
    )
    assert response.status_code == 422
    assert response.get_json()["decision"] == "REJECTED"

def test_html_escaping_in_results_view(client, sample_pdf_bytes):
    """Verify malicious script tags in filenames are safely escaped in HTML."""
    xss_filename = "<script>alert('XSS')</script>.pdf"
    data = {
        "file": (io.BytesIO(sample_pdf_bytes), xss_filename, "application/pdf")
    }
    post_res = client.post("/upload", data=data, content_type="multipart/form-data")
    assert post_res.status_code == 302
    results_url = post_res.headers["Location"]
    detail_res = client.get(results_url)
    assert detail_res.status_code == 200
    # Ensure unescaped tag is NOT present
    assert b"<script>alert('XSS')</script>" not in detail_res.data
    # Escaped version or sanitized entity should be present
    assert b"&lt;script&gt;" in detail_res.data or b"alert" in detail_res.data

def test_results_page_nonexistent_returns_404(client):
    """Verify invalid inspection ID triggers 404 error page."""
    response = client.get("/results/nonexistent-uuid-999")
    assert response.status_code == 404
    assert b"Resource Not Found" in response.data

def test_settings_page_get_status_200(client):
    """Verify settings page renders with active configuration."""
    response = client.get("/settings")
    assert response.status_code == 200
    assert b"Configurable Upload Policy Controls" in response.data
    assert b"max_file_size_mb" in response.data

def test_settings_page_post_valid_updates(client):
    """Verify valid settings submission updates configuration and redirects."""
    data = {
        "max_file_size_mb": "15",
        "max_files_per_request": "4",
        "allowed_extensions": [".pdf", ".png", ".txt"],
        "require_review_ambiguous": "true",
        "discard_rejected": "true"
    }
    response = client.post("/settings", data=data)
    assert response.status_code == 302

    # Verify updated settings reflected on GET
    get_res = client.get("/settings")
    assert b"value=\"15\"" in get_res.data

def test_settings_page_post_invalid_size_rejected(client):
    """Verify invalid file size (< 1 or > 50) returns 400 Bad Request."""
    data = {
        "max_file_size_mb": "999",  # Exceeds max 50MB
        "max_files_per_request": "5",
        "allowed_extensions": [".pdf"],
    }
    response = client.post("/settings", data=data)
    assert response.status_code == 400

def test_settings_page_post_unauthorized_extension_rejected(client):
    """Verify attempting to add an unsafe extension like .exe returns 400."""
    data = {
        "max_file_size_mb": "10",
        "max_files_per_request": "5",
        "allowed_extensions": [".pdf", ".exe"],  # .exe is NOT in predefined safe set
    }
    response = client.post("/settings", data=data)
    assert response.status_code == 400

def test_csrf_protection_blocks_post_without_token(client_with_csrf, sample_pdf_bytes):
    """Verify POST request without CSRF token returns 400 when CSRF is enabled."""
    data = {
        "file": (io.BytesIO(sample_pdf_bytes), "test.pdf", "application/pdf")
    }
    response = client_with_csrf.post("/upload", data=data, content_type="multipart/form-data")
    assert response.status_code == 400
    assert b"CSRF Token Missing or Expired" in response.data
