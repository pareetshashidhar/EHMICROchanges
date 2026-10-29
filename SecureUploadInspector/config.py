"""
SecureUpload Inspector - Configuration Module
=============================================
Defines application configuration classes, security policy thresholds,
and file validation limits.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    # Debug mode is explicitly FALSE by default for security
    DEBUG = False
    TESTING = False
    
    SECRET_KEY = os.environ.get("SECRET_KEY", "academic-secureupload-default-secret-key-3849")
    
    # CSRF Protection
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    
    # File Upload Limits
    # Default 10 MB per single file (configurable via settings up to 50 MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024 
    # Flask maximum request content length (default 12 MB)
    MAX_CONTENT_LENGTH = 12 * 1024 * 1024
    MAX_FILES_PER_REQUEST = 5
    MAX_FILENAME_LENGTH = 255
    
    # Predefined safe extension allowlist (users cannot add arbitrary unsafe extensions like .exe, .sh)
    PREDEFINED_ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
    ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".txt"}
    
    # Types that strictly require matching magic bytes signatures
    STRICT_SIGNATURE_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
    
    # Text types evaluated cautiously via heuristics
    TEXT_EXTENSIONS = {".txt"}
    
    # Policy rules
    REJECT_ZERO_BYTE_FILES = True
    ENFORCE_EXTENSION_SIGNATURE_MATCH = True
    REJECT_PATH_TRAVERSAL = True
    REJECT_DOUBLE_EXTENSIONS = True
    REQUIRE_REVIEW_AMBIGUOUS = True
    
    # Secure storage configuration:
    # If True, rejected files are purged immediately; if False, stored in private quarantine
    DISCARD_REJECTED = False
    
    # Bounded disk quota for local storage safety (100 MB default)
    MAX_STORAGE_QUOTA_BYTES = 100 * 1024 * 1024
    
    # Pagination
    DEFAULT_PAGE_SIZE = 10
    MAX_PAGE_SIZE = 100
    
    # Risk Assessment Weights (Capped at 100, heuristic validation score only)
    # Note: Risk score reflects validation anomalies and policy violations;
    # it is NOT a probability of malware.
    RISK_WEIGHTS = {
        "CRITICAL": 45,
        "HIGH": 30,
        "MEDIUM": 15,
        "LOW": 5,
        "INFO": 0
    }
    MAX_RISK_SCORE = 100

    # Paths (All stored safely outside the static/ web root)
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(BASE_DIR / "instance" / "secureupload.db"))
    ACCEPTED_STORAGE_DIR = os.environ.get("ACCEPTED_STORAGE_DIR", str(BASE_DIR / "instance" / "accepted_uploads"))
    QUARANTINE_DIR = os.environ.get("QUARANTINE_DIR", str(BASE_DIR / "instance" / "quarantine"))
    AUDIT_LOG_PATH = os.environ.get("AUDIT_LOG_PATH", str(BASE_DIR / "instance" / "audit.log"))

class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    """Testing configuration with CSRF disabled and isolated paths."""
    DEBUG = False
    TESTING = True
    WTF_CSRF_ENABLED = False
    DATABASE_PATH = ":memory:"
    ACCEPTED_STORAGE_DIR = str(BASE_DIR / "instance" / "test_accepted")
    QUARANTINE_DIR = str(BASE_DIR / "instance" / "test_quarantine")
    AUDIT_LOG_PATH = str(BASE_DIR / "instance" / "test_audit.log")

class ProductionConfig(Config):
    """Production configuration requiring strong secret key and strict CSRF."""
    DEBUG = False
    TESTING = False
    WTF_CSRF_ENABLED = True

CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig
}

def get_config(config_name: str | None = None) -> type[Config]:
    """Retrieve configuration class by name."""
    env = config_name or os.environ.get("FLASK_ENV", "development").lower()
    return CONFIG_MAP.get(env, DevelopmentConfig)
