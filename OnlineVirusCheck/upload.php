<?php
include 'includes/session.php';
include 'includes/db.php';

// Check if file has been uploaded
if (isset($_FILES['fileToCheck']['name']) && $_FILES['fileToCheck']['error'] == UPLOAD_ERR_OK) {
    $allowedTypes = ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/pdf', 'application/x-msdownload']; // MIME types for docx, xlsx, pdf, exe
    $fileType = $_FILES['fileToCheck']['type'];
    
    if (in_array($fileType, $allowedTypes)) {
        // Continue with file processing and malware check
        echo "File is being processed...";
        // Include malware checking code here
    } else {
        echo "Invalid file type uploaded.";
    }
} else {
    echo "No file uploaded.";
}
?>