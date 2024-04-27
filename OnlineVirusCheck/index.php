<?php
include 'includes/session.php'; // Start secure session
include 'templates/header.php'; // HTML header

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Online Virus Check</title>
    <!-- Include Bootstrap CSS from a CDN -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
<div class="container">

<h1 class="mt-3">Welcome to Online Virus Check</h1>
<div class="my-4">
    <?php
    // Check if the admin is logged in
    if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
        // Display Log Out button if admin is logged in
        echo '<a href="logout.php" class="btn btn-danger">Log Out</a>';
    } else {
        // Display Admin Login button if admin is not logged in
        echo '<a href="admin_login.php" class="btn btn-primary">Admin Login</a>';
    }
    ?>
</div>
<form action="upload.php" method="post" enctype="multipart/form-data" onsubmit="return validateFile()" class="mb-3">
    <div class="form-group">
        <label for="fileToCheck">Select file to upload:</label>
        <input type="file" name="fileToCheck" id="fileToCheck" class="form-control-file" required>
    </div>
    <button type="submit" class="btn btn-success">Upload File</button>
</form>

<script>
function validateFile() {
    var fileInput = document.getElementById('fileToCheck');
    var filePath = fileInput.value;
    var allowedExtensions = /(\.exe|\.docx|\.xlsx|\.pdf)$/i; // allowed file types

    if (!allowedExtensions.exec(filePath)) {
        alert('Invalid file type. Only .exe, .docx, .xlsx, and .pdf files are allowed.');
        fileInput.value = ''; // Clear the file input
        return false;
    }
    return true;
}
</script>

<?php
include 'templates/footer.php'; // HTML footer
?>