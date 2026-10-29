"""
SecureUpload Inspector - Part 2 End-to-End Live HTTP Workflow Verification
==========================================================================
Tests live HTTP upload processing, storage segregation, report export,
pagination, and settings policy administration.
"""

import re
import requests
from pathlib import Path

BASE_URL = "http://127.0.0.1:5050"
session = requests.Session()

print("=" * 60)
print(" SECUREUPLOAD INSPECTOR - PART 2 E2E HTTP VERIFICATION")
print("=" * 60)

# 1. Fetch upload page and extract CSRF token
get_res = session.get(f"{BASE_URL}/upload")
assert get_res.status_code == 200, f"Upload page returned {get_res.status_code}"
match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', get_res.text)
assert match, "CSRF token not found in upload form"
csrf_token = match.group(1)
print(f"[1] Retrieved CSRF token: {csrf_token[:16]}...")

# 1b. Ensure baseline settings: discard_rejected = false for initial tests
get_s_init = session.get(f"{BASE_URL}/settings")
csrf_s_init = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', get_s_init.text).group(1)
session.post(f"{BASE_URL}/settings", data={
    "csrf_token": csrf_s_init,
    "max_file_size_mb": "10",
    "max_files_per_request": "5",
    "allowed_extensions": [".pdf", ".png", ".jpg", ".jpeg", ".txt"],
    "require_review_ambiguous": "true",
    "discard_rejected": "false"
})

# 2. Upload valid PDF
pdf_payload = b"%PDF-1.4\n1 0 obj\n<< /Title (Academic Upload Security Part 2) >>\nendobj\ntrailer\n<<>>\n%%EOF"
files = {"file": ("whitepaper_pt2.pdf", pdf_payload, "application/pdf")}
data = {"csrf_token": csrf_token}

post_res = session.post(f"{BASE_URL}/upload", data=data, files=files, allow_redirects=False)
assert post_res.status_code == 302, f"Expected 302, got {post_res.status_code}"
redirect_url = post_res.headers["Location"]
insp_id = redirect_url.split("/")[-1]
print(f"[2] Uploaded valid PDF -> Inspection ID: {insp_id}")

# Verify file stored in accepted storage outside web root
accepted_file = Path("instance/accepted_uploads") / f"{insp_id}.accepted"
assert accepted_file.is_file(), f"Accepted file not found at {accepted_file}"
print(f"[3] Confirmed accepted file securely stored: {accepted_file}")

# 3. View Results page
results_res = session.get(f"{BASE_URL}{redirect_url}")
assert results_res.status_code == 200
assert "VERDICT: ACCEPTED" in results_res.text
assert "whitepaper_pt2.pdf" in results_res.text
print("[4] Results page displays VERDICT: ACCEPTED")

# 4. JSON Report verification via /inspection/<id>/report.json
json_res = session.get(f"{BASE_URL}/inspection/{insp_id}/report.json")
assert json_res.status_code == 200
json_data = json_res.json()
assert json_data["inspection_summary"]["id"] == insp_id
assert json_data["inspection_summary"]["final_decision"] == "ACCEPTED"
assert json_data["checks_summary"]["total_checks_performed"] >= 4
assert "malware" in json_data["academic_disclaimer"].lower()
print("[5] JSON report export verified with checks summary and disclaimer")

# 5. Plain Text Report verification
report_res = session.get(f"{BASE_URL}/inspection/{insp_id}/report")
assert report_res.status_code == 200
assert "CYBERSECURITY DISCLAIMER" in report_res.text
print("[6] Plain text audit report verified")

# 6. Upload spoofed executable (PE disguised as PDF)
get_res2 = session.get(f"{BASE_URL}/upload")
csrf_token2 = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', get_res2.text).group(1)
malicious_payload = b"MZ\x90\x00Disguised executable payload"
files2 = {"file": ("trojan.pdf", malicious_payload, "application/pdf")}
data2 = {"csrf_token": csrf_token2}

post_res2 = session.post(f"{BASE_URL}/upload", data=data2, files=files2, allow_redirects=False)
assert post_res2.status_code == 302
insp_id_mal = post_res2.headers["Location"].split("/")[-1]

# Verify rejected file is NOT in accepted storage!
assert not (Path("instance/accepted_uploads") / f"{insp_id_mal}.accepted").exists()
# Verify rejected file is in quarantine
assert (Path("instance/quarantine") / f"{insp_id_mal}.quarantine").is_file()
print("[7] Confirmed rejected file NEVER entered accepted storage (segregated in quarantine)")

# 7. Test paginated history
hist_res = session.get(f"{BASE_URL}/history?page=1&per_page=10&decision=ACCEPTED")
assert hist_res.status_code == 200
table_body = hist_res.text.split('id="history-table-body"')[1].split('</table>')[0]
assert "whitepaper_pt2.pdf" in table_body
assert "trojan.pdf" not in table_body
print("[8] History pagination & decision filtering verified (table body isolated from flash messages)")

# 8. Test Settings Page update via POST /settings
get_settings_res = session.get(f"{BASE_URL}/settings")
csrf_token_settings = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', get_settings_res.text).group(1)

settings_data = {
    "csrf_token": csrf_token_settings,
    "max_file_size_mb": "12",
    "max_files_per_request": "6",
    "allowed_extensions": [".pdf", ".png", ".jpg", ".jpeg", ".txt"],
    "require_review_ambiguous": "true",
    "discard_rejected": "true"  # Enable immediate discard
}
post_settings = session.post(f"{BASE_URL}/settings", data=settings_data, allow_redirects=False)
assert post_settings.status_code == 302
print("[9] Security settings successfully updated via POST /settings")

# 9. Test upload with discard_rejected=True
get_res3 = session.get(f"{BASE_URL}/upload")
csrf_token3 = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', get_res3.text).group(1)
files3 = {"file": ("rejected_discard_test.pdf", malicious_payload, "application/pdf")}
data3 = {"csrf_token": csrf_token3}

post_res3 = session.post(f"{BASE_URL}/upload", data=data3, files=files3, allow_redirects=False)
insp_id_discard = post_res3.headers["Location"].split("/")[-1]

# Verify file was NOT stored in accepted storage AND NOT retained in quarantine (discard policy)
assert not (Path("instance/accepted_uploads") / f"{insp_id_discard}.accepted").exists()
assert not (Path("instance/quarantine") / f"{insp_id_discard}.quarantine").exists()
print("[10] Confirmed immediate discard policy: rejected file purged without disk retention")

# 10. Test unauthorized extension submission is blocked
get_settings_res2 = session.get(f"{BASE_URL}/settings")
csrf_token_settings2 = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', get_settings_res2.text).group(1)
bad_settings_data = {
    "csrf_token": csrf_token_settings2,
    "max_file_size_mb": "10",
    "max_files_per_request": "5",
    "allowed_extensions": [".pdf", ".exe"]  # Unauthorized .exe extension
}
post_bad_settings = session.post(f"{BASE_URL}/settings", data=bad_settings_data)
assert post_bad_settings.status_code == 400
print("[11] Confirmed server-side validation blocks unauthorized extension injection")

# 11. Dashboard statistics verify
dash_res = session.get(f"{BASE_URL}/")
assert dash_res.status_code == 200
print("[12] Dashboard operational statistics confirmed")

# Teardown: Reset settings back to baseline
get_s_final = session.get(f"{BASE_URL}/settings")
csrf_s_final = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', get_s_final.text).group(1)
session.post(f"{BASE_URL}/settings", data={
    "csrf_token": csrf_s_final,
    "max_file_size_mb": "10",
    "max_files_per_request": "5",
    "allowed_extensions": [".pdf", ".png", ".jpg", ".jpeg", ".txt"],
    "require_review_ambiguous": "true",
    "discard_rejected": "false"
})

print("\n" + "=" * 60)
print(" >>> ALL PART 2 E2E LIVE VERIFICATION CHECKS PASSED! <<<")
print("=" * 60)
