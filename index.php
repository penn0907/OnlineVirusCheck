<?php
include 'includes/session.php'; // Start secure session
include 'includes/db.php';
include 'templates/header.php'; // HTML header

// Define an error message variable
$errorMessage = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_FILES['fileToCheck']) && $_FILES['fileToCheck']['error'] == UPLOAD_ERR_OK) {
        $fileTmpPath = $_FILES['fileToCheck']['tmp_name'];
        $fileName = $_FILES['fileToCheck']['name'];
        $fileExtension = strtolower(pathinfo($fileName, PATHINFO_EXTENSION));
        $allowedExtensions = ['exe', 'pdf', 'zip'];
        
        // Validate file extension
        if (!in_array($fileExtension, $allowedExtensions)) {
            $errorMessage = 'Invalid file type. Only .exe, .pdf, and .zip files are allowed.';
        } else {
            $fileContent = file_get_contents($fileTmpPath);
            // Skipping header based on file type and getting content to check
            switch ($fileExtension) {
                case 'exe':
                    $headerLength = 0x3C;
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
                    $headerLength = 30;
                    break;
                default:
                    $headerLength = 0;
                    break;
            }
            $signature = substr($fileContent, $headerLength, 20);
            $conn = getDatabaseConnection();
            $stmt = $conn->prepare("SELECT name FROM malware_signatures WHERE signature = ?");
            $stmt->bind_param("s", $signature);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $errorMessage = "Malware detected: " . htmlspecialchars($result->fetch_assoc()['name']);
            } else {
                $errorMessage = "No malware detected. File appears to be clean.";
            }
            $stmt->close();
        }
    } else {
        // Handle different types of errors
        switch ($_FILES['fileToCheck']['error']) {
            case UPLOAD_ERR_INI_SIZE:
            case UPLOAD_ERR_FORM_SIZE:
                $errorMessage = "File is too large.";
                break;
            case UPLOAD_ERR_NO_FILE:
                $errorMessage = "No file was uploaded.";
                break;
            default:
                $errorMessage = "Unknown upload error.";
                break;
        }
    }
}

?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Online Virus Check</title>
<!-- Include Bootstrap CSS from a CDN -->
<link rel="stylesheet"
	href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
	<div class="container">

		<h1 class="mt-3">Welcome to Online Virus Check</h1>
		<div class="my-4">
    <?php
    // Check if the admin is logged in
    if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
        // Display Log Out button if admin is logged in
        echo '<a href="admin.php" class="btn btn-danger">Admin Panel</a>';
        echo '  <a href="logout.php" class="btn btn-danger">Log Out</a>';
    } else {
        // Display Admin Login button if admin is not logged in
        echo '<a href="admin_login.php" class="btn btn-primary">Admin Login</a>';
    }
    ?>
</div>
		<form action="index.php" method="post" enctype="multipart/form-data"
			onsubmit="return validateFile()" class="mb-3">
			<div class="form-group">
				<label for="fileToCheck">Select file to upload(.exe, .pdf, .zip files):</label> <input
					type="file" name="fileToCheck" id="fileToCheck"
					class="form-control-file" required style="max-width: 300px;">
			</div>
			<button type="submit" class="btn btn-success">Upload File</button>
		</form>
		<?php
    if (!empty($errorMessage)) {
        echo "<div class='alert alert-info'>$errorMessage</div>";
    }
    ?>

		<script>
            function validateFile() {
                var fileInput = document.getElementById('fileToCheck');
                var filePath = fileInput.value;
                var allowedExtensions = /\.(exe|pdf|zip)$/i; // Updated allowed file types
            
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