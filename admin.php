<?php
include 'includes/session.php'; // Start secure session
include 'includes/db.php';
include 'templates/header.php'; // HTML header

// Redirect user to login page if not log in
if (! isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: admin_login.php');
    exit();
}

// Handle file upload logic after form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check for a valid malware name
    $malwareName = $_POST['malwareName'] ?? '';
    if (! preg_match('/^[a-zA-Z0-9]+$/', $malwareName)) {
        $error = "Malware name must contain only letters and digits.";
    } else {
        // Process the uploaded file if malware name is valid
        if (isset($_FILES['malwareFile']) && $_FILES['malwareFile']['error'] == UPLOAD_ERR_OK) {

            $allowedTypes = [
                'application/x-msdownload',
                'application/pdf',
                'application/zip'
            ]; // types for exe, pdf, and zip
            $fileType = $_FILES['malwareFile']['type'];

            if (in_array($fileType, $allowedTypes)) {
                $filePath = $_FILES['malwareFile']['tmp_name'];
                $fileContent = file_get_contents($filePath);
                $fileExtension = strtolower(pathinfo($_FILES['malwareFile']['name'], PATHINFO_EXTENSION));

                $conn = getDatabaseConnection();

                // Check if the malware name already exists in the database
                $stmt = $conn->prepare("SELECT COUNT(*) FROM malware_signatures WHERE name = ?");
                $stmt->bind_param("s", $malwareName);
                $stmt->execute();
                $stmt->store_result();
                $stmt->bind_result($count);
                $stmt->fetch();

                if ($count > 0) {
                    $error = "A malware signature with that name already exists.";
                } else {

                    // Default to the first 20 bytes
                    $headerLength = 20;

                    switch ($fileExtension) {
                        case 'exe':
                            $headerLength = 0x3C; // Header length before PE header in executable files
                            break;
                        case 'pdf':
                            // Dynamically find the first occurrence of 'obj' to determine the start of content
                            if (preg_match('/obj/i', $fileContent, $matches, PREG_OFFSET_CAPTURE, 10)) {
                                $headerLength = $matches[0][1]; // Position of the first 'obj'
                            } else {
                                $headerLength = 0; // Fallback if no 'obj' is found
                            }
                            break;
                        case 'zip':
                            $headerLength = 30; // Common header length for ZIP files
                            break;
                    }

                    $signature = substr($fileContent, $headerLength, 20); // Get 20 bytes after the header

                    // Save the malware name and signature into the database

                    $stmt = $conn->prepare("INSERT INTO malware_signatures (name, signature) VALUES (?, ?)");
                    $stmt->bind_param("sb", $malwareName, $signature);
                    $stmt->send_long_data(1, $signature);

                    if ($stmt->execute()) {
                        $error = "Malware signature uploaded successfully.";
                    } else {
                        $error = "Failed to upload malware signature. Error: " . $stmt->error;
                    }
                    $stmt->close();
                    $conn->close();
                }
            } else {
                $error = "Unsupported file type. Only .exe, .pdf, and .zip files are allowed.";
            }
        } else {
            $error = "Failed to upload file.";
        }
    }
}

?>

<h1>Admin Panel - Upload Malware</h1>
<div class="my-4">
    <?php
    // Check if the admin is logged in
    if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
        // Display Log Out button if admin is logged in
        echo '<a href="index.php" class="btn btn-danger">Home Page</a>';
        echo '  <a href="logout.php" class="btn btn-danger">Log Out</a>';
    }
    ?>
</div>
<form action="admin.php" method="post" enctype="multipart/form-data"
	onsubmit="return validateFile()">
	<div class="form-group">
		<label for="malwareName">Malware Name:</label> <input type="text"
			name="malwareName" id="malwareName" class="form-control" required
			pattern="[a-zA-Z0-9]+" required style="max-width: 300px;">
	</div>
	<div class="form-group">
		<label for="malwareFile">Select malware file to upload(.exe, .pdf,
			.zip files):</label> <input type="file" name="malwareFile"
			id="malwareFile" class="form-control-file" required>
	</div>
	<button type="submit" class="btn btn-primary">Upload Malware</button>
</form>
<?php 
if (! empty($error)) {
    echo "<div class='alert alert-info'>$error</div>";
}
?>
<script>
function validateFile() {
    var fileInput = document.getElementById('malwareFile');
    var filePath = fileInput.value;
    var allowedExtensions = /\.(exe|pdf|zip)$/i;
    var malwareName = document.getElementById('malwareName').value;

    // Check if the malware name contains only alphanumeric characters
    if (!malwareName.match(/^[a-zA-Z0-9]+$/)) {
        alert('Malware name must contain only alphanumeric characters.');
        return false;
    }

    // Check if the file extension is allowed
    if (!allowedExtensions.exec(filePath)) {
        alert('Invalid file type. Only .exe, .pdf, and .zip files are allowed.');
        fileInput.value = ''; // Clear the file input
        return false;
    }
    return true;
}
</script>

<?php
include 'templates/footer.php'; // HTML footer
?>
