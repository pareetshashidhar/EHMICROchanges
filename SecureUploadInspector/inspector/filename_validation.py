"""
SecureUpload Inspector - Filename Validation and Sanitization Module
====================================================================
Audits filenames for path traversal attacks, prohibited characters,
null-byte injection, excessive length, and suspicious double extensions.

SECURITY POLICIES ENFORCED:
1. Reject dangerous path-like filenames outright rather than attempting
   to strip traversal sequences into an accepted file.
2. Differentiate between benign compound filenames (e.g. report.2026.pdf, data.backup.txt)
   and suspicious double extensions attempting evasion (e.g. invoice.pdf.exe, image.png.php).
"""

from dataclasses import dataclass, asdict
import os
import re
from pathlib import PureWindowsPath, PurePosixPath
from typing import Optional

# Maximum permissible filename length (standard POSIX and NTFS safety bound)
DEFAULT_MAX_FILENAME_LENGTH = 255

# Allowed characters: alphanumeric, dots, underscores, dashes, and single spaces
SAFE_FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\. ]+$")

# Characters explicitly forbidden in filenames across cross-platform boundaries
# Prohibits Windows reserved characters, control codes, and shell metacharacters
PROHIBITED_CHARS_PATTERN = re.compile(r'[\x00-\x1f\x7f<>:"/\\|?*;\$`&!#~]')

# Traversal sequence indicators
PATH_TRAVERSAL_PATTERNS = [
    "..",
    "../",
    r"..\\",
    "/",
    "\\",
    "%2e%2e",
    "%2f",
    "%5c",
]

# Prohibited dangerous secondary/executable extensions
EXECUTABLE_SCRIPT_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf",
    ".msi", ".scr", ".pif", ".cpl", ".hta", ".jar", ".com",
    ".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
    ".asp", ".aspx", ".ashx", ".asmx",
    ".jsp", ".jspx",
    ".py", ".pyw", ".rb", ".pl", ".cgi", ".sh", ".bash",
    ".svg",  # SVG can contain embedded XML/JavaScript payloads
    ".shtml", ".xhtml"
}

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
}

@dataclass
class FilenameValidationResult:
    """Structured result of filename security auditing."""
    is_valid: bool
    original_filename: str
    cleaned_basename: str
    extension: str
    issues: list[str]
    is_path_traversal: bool
    is_double_extension: bool
    double_extension_risk: str  # 'NONE', 'BENIGN_COMPOUND', 'SUSPICIOUS_EXECUTABLE'
    rejection_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


def _check_double_extension(filename: str) -> tuple[bool, str, list[str]]:
    """
    Examine multiple extension dots in a filename according to documented security rules.
    
    Rule:
    - If filename contains multiple segments split by dots (e.g., name.ext1.ext2):
      - If ANY component extension is in EXECUTABLE_SCRIPT_EXTENSIONS:
        Mark as SUSPICIOUS_EXECUTABLE (e.g. invoice.pdf.exe or shell.php.png).
      - If intermediate components are benign words/numbers/dates (e.g. archive.2026.pdf, log.backup.txt):
        Mark as BENIGN_COMPOUND.
    
    Returns:
        (has_double_ext, risk_category, explanations)
    """
    parts = filename.split(".")
    # Filter empty parts (e.g. leading dot or trailing dot)
    valid_parts = [p.lower() for p in parts if p]

    if len(valid_parts) <= 2:
        return False, "NONE", []

    # File has multiple extensions / dots
    all_exts = [f".{part}" for part in valid_parts[1:]]
    suspicious_matches = [ext for ext in all_exts if ext in EXECUTABLE_SCRIPT_EXTENSIONS]

    if suspicious_matches:
        return (
            True,
            "SUSPICIOUS_EXECUTABLE",
            [
                f"Suspicious double extension detected containing executable/script type: "
                f"{', '.join(suspicious_matches)}. High risk of file-type masquerading."
            ]
        )

    return (
        True,
        "BENIGN_COMPOUND",
        [
            f"Filename contains multiple dot segments ({'.'.join(valid_parts[1:])}), "
            f"classified as benign compound naming convention."
        ]
    )


def validate_filename(
    filename: Optional[str],
    max_length: int = DEFAULT_MAX_FILENAME_LENGTH,
    allowed_extensions: Optional[set[str]] = None
) -> FilenameValidationResult:
    """
    Perform deep validation of an untrusted filename.
    
    Enforces strict security checks against:
    - Empty or null filenames
    - Null bytes (\\x00)
    - Path traversal attacks (rejecting rather than silently rewriting)
    - Excessive length
    - Reserved platform names (CON, NUL, etc.)
    - Dangerous character sets
    - Suspicious double extensions
    - Disallowed extensions
    
    Args:
        filename: Raw client-supplied filename string
        max_length: Maximum permitted length (default 255)
        allowed_extensions: Set of permitted lowercase extensions with leading dot (e.g. {'.pdf', '.png'})
        
    Returns:
        FilenameValidationResult with complete security analysis.
    """
    issues: list[str] = []
    is_path_traversal = False
    
    # 1. Null or empty check
    if not filename or not filename.strip():
        return FilenameValidationResult(
            is_valid=False,
            original_filename="",
            cleaned_basename="",
            extension="",
            issues=["Filename is empty or whitespace only."],
            is_path_traversal=False,
            is_double_extension=False,
            double_extension_risk="NONE",
            rejection_reason="Empty filename is rejected by security policy."
        )

    raw_name = filename.strip()

    # 2. Null byte injection check
    if "\x00" in raw_name or "%00" in raw_name:
        issues.append("Filename contains null byte injection sequence (\\x00 / %00).")
        return FilenameValidationResult(
            is_valid=False,
            original_filename=raw_name,
            cleaned_basename="",
            extension="",
            issues=issues,
            is_path_traversal=False,
            is_double_extension=False,
            double_extension_risk="NONE",
            rejection_reason="Null byte injection attempt detected in filename."
        )

    # 3. Path traversal detection
    # Check for forward/back slashes, parent directory tokens, drive letters, UNC prefixes
    has_traversal_tokens = any(token in raw_name for token in PATH_TRAVERSAL_PATTERNS)
    is_absolute_posix = raw_name.startswith("/")
    is_windows_path = bool(re.match(r"^[a-zA-Z]:[\\/]", raw_name) or raw_name.startswith(r"\\"))
    
    posix_path = PurePosixPath(raw_name)
    win_path = PureWindowsPath(raw_name)

    if has_traversal_tokens or is_absolute_posix or is_windows_path or posix_path.is_absolute() or win_path.is_absolute() or ".." in posix_path.parts or ".." in win_path.parts:
        is_path_traversal = True
        issues.append(
            f"Path traversal sequence detected in filename '{raw_name}'. "
            "Security policy explicitly rejects path-like filenames."
        )

    # 4. Extract safe leaf basename
    # Note: Even if rejected, we derive basename for analytical reporting
    leaf_name = os.path.basename(raw_name.replace("\\", "/"))
    if not leaf_name:
        issues.append("Unable to resolve a valid file leaf name.")
        leaf_name = "invalid_filename"

    # 5. Length verification
    if len(raw_name) > max_length:
        issues.append(f"Filename length ({len(raw_name)} characters) exceeds maximum allowed limit of {max_length}.")

    # 6. Windows Reserved Device Names check (e.g. CON.txt, NUL.pdf)
    root_stem = leaf_name.split(".")[0].upper()
    if root_stem in WINDOWS_RESERVED_NAMES:
        issues.append(f"Filename root '{root_stem}' matches Windows reserved system device name.")

    # 7. Prohibited characters check
    prohibited_matches = PROHIBITED_CHARS_PATTERN.findall(leaf_name)
    if prohibited_matches:
        unique_prohibited = sorted(list(set(prohibited_matches)))
        issues.append(f"Filename contains prohibited or unsafe characters: {', '.join(repr(c) for c in unique_prohibited)}")

    # 8. Double extension analysis
    is_double_ext, double_risk, double_explanations = _check_double_extension(leaf_name)
    issues.extend(double_explanations)
    if double_risk == "SUSPICIOUS_EXECUTABLE":
        issues.append("Double extension contains executable/script payload signature.")

    # 9. Extension policy validation
    # Extract extension from leaf_name
    parts = leaf_name.rsplit(".", 1)
    extension = f".{parts[1].lower()}" if len(parts) > 1 else ""

    if not extension:
        issues.append("Filename has no extension. Extensionless files fail upload policy.")
    elif allowed_extensions is not None and extension not in allowed_extensions:
        issues.append(f"Extension '{extension}' is not permitted by upload policy. Allowed: {sorted(list(allowed_extensions))}.")

    # Determine validity and rejection reason
    # Mandatory rejections: path traversal, prohibited chars, null byte, suspicious executable double ext, disallowed ext, reserved names, over length
    is_valid = (
        len(issues) == 0 or
        (len(issues) == 1 and is_double_ext and double_risk == "BENIGN_COMPOUND")
    )
    
    # If only benign compound naming was noted, is_valid remains True unless other errors exist
    if is_double_ext and double_risk == "BENIGN_COMPOUND":
        filtered_critical_issues = [i for i in issues if not i.startswith("Filename contains multiple dot segments")]
        is_valid = len(filtered_critical_issues) == 0

    rejection_reason = None
    if not is_valid:
        if is_path_traversal:
            rejection_reason = "Path traversal attack detected in filename."
        elif double_risk == "SUSPICIOUS_EXECUTABLE":
            rejection_reason = "Executable double extension detected (possible evasion technique)."
        elif root_stem in WINDOWS_RESERVED_NAMES:
            rejection_reason = f"Filename uses reserved system device name: {root_stem}."
        elif not extension or (allowed_extensions and extension not in allowed_extensions):
            rejection_reason = f"File extension '{extension or '(none)'}' is prohibited by policy."
        elif len(raw_name) > max_length:
            rejection_reason = f"Filename length exceeds maximum threshold of {max_length} characters."
        else:
            rejection_reason = "Filename contains prohibited characters or formatting violations."

    return FilenameValidationResult(
        is_valid=is_valid,
        original_filename=raw_name,
        cleaned_basename=leaf_name,
        extension=extension,
        issues=issues,
        is_path_traversal=is_path_traversal,
        is_double_extension=is_double_ext,
        double_extension_risk=double_risk,
        rejection_reason=rejection_reason
    )
