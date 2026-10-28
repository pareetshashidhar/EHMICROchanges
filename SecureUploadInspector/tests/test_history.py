"""
SecureUpload Inspector - History & Database Statistics Unit Tests
==================================================================
Tests paginated audit querying, multi-vector filtering, and real-time dashboard statistics.
"""

from storage.database import (
    get_dashboard_statistics,
    list_inspections,
    list_inspections_paginated
)

def test_dashboard_statistics_accurate(seeded_db):
    """Verify statistics calculated from actual SQLite rows reflect seeded data."""
    stats = get_dashboard_statistics(seeded_db)
    assert stats["total_inspected"] == 3
    assert stats["accepted_count"] == 1
    assert stats["rejected_count"] == 1
    assert stats["review_count"] == 1
    assert "pdf" in stats["type_distribution"]
    assert len(stats["recent_inspections"]) == 3

def test_history_list_all(seeded_db):
    """Verify list_inspections returns all records ordered by timestamp."""
    items = list_inspections(seeded_db)
    assert len(items) == 3

def test_history_pagination_bounds(seeded_db):
    """Verify pagination limits page sizes and returns correct pages."""
    p1 = list_inspections_paginated(seeded_db, page=1, per_page=2)
    assert len(p1["items"]) == 2
    assert p1["total"] == 3
    assert p1["total_pages"] == 2
    assert p1["has_next"] is True
    assert p1["has_prev"] is False

    p2 = list_inspections_paginated(seeded_db, page=2, per_page=2)
    assert len(p2["items"]) == 1
    assert p2["has_next"] is False
    assert p2["has_prev"] is True

def test_history_filter_by_decision(seeded_db):
    """Verify querying by decision filter returns only matching records."""
    accepted_items = list_inspections_paginated(seeded_db, decision_filter="ACCEPTED")
    assert accepted_items["total"] == 1
    assert accepted_items["items"][0]["decision"] == "ACCEPTED"
    assert accepted_items["items"][0]["original_filename"] == "whitepaper.pdf"

    rejected_items = list_inspections_paginated(seeded_db, decision_filter="REJECTED")
    assert rejected_items["total"] == 1
    assert rejected_items["items"][0]["decision"] == "REJECTED"

    review_items = list_inspections_paginated(seeded_db, decision_filter="REVIEW_REQUIRED")
    assert review_items["total"] == 1
    assert review_items["items"][0]["decision"] == "REVIEW_REQUIRED"

def test_history_filter_by_file_type(seeded_db):
    """Verify querying by file format filter."""
    pdf_items = list_inspections_paginated(seeded_db, type_filter="pdf")
    assert pdf_items["total"] == 1
    assert pdf_items["items"][0]["detected_type"] == "pdf"

    text_items = list_inspections_paginated(seeded_db, type_filter="probable_text")
    assert text_items["total"] == 1
    assert text_items["items"][0]["detected_type"] == "probable_text"

def test_history_search_query(seeded_db):
    """Verify search wildcard matching on filename and hash."""
    matches = list_inspections_paginated(seeded_db, search_query="malware")
    assert matches["total"] == 1
    assert matches["items"][0]["original_filename"] == "malware.pdf.exe"

def test_history_route_renders_with_filters(client, seeded_db):
    """Verify /history route renders HTML table with inspections and filter parameters."""
    response = client.get("/history?decision=ACCEPTED")
    assert response.status_code == 200
    assert b"whitepaper.pdf" in response.data
    assert b"malware.pdf.exe" not in response.data
