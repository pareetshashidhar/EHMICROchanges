/**
 * SecureUpload Inspector - Interactive Application JavaScript
 * Vanilla JavaScript (No React, Next, or external libraries)
 */

document.addEventListener("DOMContentLoaded", () => {
    initDropzone();
    initCopyButtons();
    initHistoryFilter();
    initMobileSidebar();
});

/**
 * Initialize Drag and Drop Upload Zone
 */
function initDropzone() {
    const dropzone = document.getElementById("upload-dropzone");
    const fileInput = document.getElementById("file-input");
    const previewCard = document.getElementById("selected-file-card");
    const fileNameSpan = document.getElementById("selected-file-name");
    const fileSizeSpan = document.getElementById("selected-file-size");
    const submitBtn = document.getElementById("upload-submit-btn");
    const uploadForm = document.getElementById("upload-form");
    const browseBtn = document.getElementById("btn-browse-file");

    if (!dropzone || !fileInput) return;

    // Explicit browse button click handler
    if (browseBtn) {
        browseBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            fileInput.click();
        });
    }

    // Click anywhere in dropzone to select file
    dropzone.addEventListener("click", () => {
        fileInput.click();
    });

    // Drag-over styling
    ["dragenter", "dragover"].forEach(evtName => {
        dropzone.addEventListener(evtName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add("dragover");
        });
    });

    ["dragleave", "drop"].forEach(evtName => {
        dropzone.addEventListener(evtName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove("dragover");
        });
    });

    // Drop handler
    dropzone.addEventListener("drop", (e) => {
        const files = e.dataTransfer.files;
        if (files && files.length > 0) {
            fileInput.files = files;
            updateFilePreview(files[0]);
        }
    });

    // Native file picker change
    fileInput.addEventListener("change", () => {
        if (fileInput.files && fileInput.files.length > 0) {
            updateFilePreview(fileInput.files[0]);
        }
    });

    function updateFilePreview(file) {
        if (!file) return;
        if (previewCard) previewCard.style.display = "flex";
        if (fileNameSpan) fileNameSpan.textContent = file.name;
        if (fileSizeSpan) fileSizeSpan.textContent = formatBytes(file.size);
        if (submitBtn) submitBtn.disabled = false;

        // Client-side quick check
        const MAX_SIZE = 10 * 1024 * 1024; // 10MB
        if (file.size > MAX_SIZE) {
            if (fileSizeSpan) {
                fileSizeSpan.innerHTML = `<span style="color: var(--color-rejected)">${formatBytes(file.size)} (Exceeds 10MB limit)</span>`;
            }
        }
    }

    // Form submit showing real processing state
    if (uploadForm) {
        uploadForm.addEventListener("submit", (e) => {
            if (!fileInput.files || fileInput.files.length === 0) {
                e.preventDefault();
                alert("Please select a file to inspect.");
                return;
            }
            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `<span>Uploading and evaluating policies...</span>`;
            }
        });
    }
}

/**
 * Format bytes to readable string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

/**
 * Clipboard copy functionality for hashes and rule IDs
 */
function initCopyButtons() {
    document.querySelectorAll(".copy-btn").forEach(btn => {
        btn.addEventListener("click", async (e) => {
            e.preventDefault();
            const textToCopy = btn.getAttribute("data-copy-target");
            if (!textToCopy) return;

            try {
                await navigator.clipboard.writeText(textToCopy);
                const originalText = btn.innerHTML;
                btn.innerHTML = `<span>Copied!</span>`;
                btn.classList.add("btn-success");
                setTimeout(() => {
                    btn.innerHTML = originalText;
                    btn.classList.remove("btn-success");
                }, 1800);
            } catch (err) {
                console.error("Clipboard copy failed:", err);
            }
        });
    });
}

/**
 * History Table Search & Filter
 */
function initHistoryFilter() {
    const searchInput = document.getElementById("history-search");
    const decisionFilter = document.getElementById("history-decision-filter");
    const tableBody = document.getElementById("history-table-body");

    if (!tableBody || (!searchInput && !decisionFilter)) return;

    function filterRows() {
        const query = searchInput ? searchInput.value.toLowerCase().trim() : "";
        const decision = decisionFilter ? decisionFilter.value.toUpperCase() : "ALL";

        const rows = tableBody.querySelectorAll("tr.history-row");
        rows.forEach(row => {
            const filename = (row.getAttribute("data-filename") || "").toLowerCase();
            const hash = (row.getAttribute("data-hash") || "").toLowerCase();
            const rowDecision = (row.getAttribute("data-decision") || "").toUpperCase();

            const matchesQuery = !query || filename.includes(query) || hash.includes(query);
            const matchesDecision = decision === "ALL" || rowDecision === decision;

            if (matchesQuery && matchesDecision) {
                row.style.display = "";
            } else {
                row.style.display = "none";
            }
        });
    }

    if (searchInput) searchInput.addEventListener("input", filterRows);
    if (decisionFilter) decisionFilter.addEventListener("change", filterRows);
}

/**
 * Mobile sidebar drawer toggle
 */
function initMobileSidebar() {
    const toggleBtn = document.getElementById("mobile-menu-toggle");
    const sidebar = document.querySelector(".app-sidebar");
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener("click", () => {
            sidebar.classList.toggle("open");
        });
    }
}
