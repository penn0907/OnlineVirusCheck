<?php
include 'includes/session.php'; // Start secure session
include 'includes/db.php';
include 'templates/header.php'; // HTML header

// Redirect user to login page if not log in
if (!isset($_SESSION['admin_logged_in']) || $_SESSION['admin_logged_in'] !== true) {
    header('Location: admin_login.php');
    exit();
}

// Handle file upload logic after form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Check for a valid malware name
    $malwareName = $_POST['malwareName'] ?? '';
    if (!preg_match('/^[a-zA-Z0-9]+$/', $malwareName)) {
        $error = "Malware name must contain only letters and digits.";
    } else {
        // Process the uploaded file if malware name is valid
        if (isset($_FILES['malwareFile']) && $_FILES['malwareFile']['error'] == UPLOAD_ERR_OK) {
            
            $allowedTypes = ['application/x-msdownload', 'application/pdf', 'application/zip']; // types for exe, pdf, and zip
            $fileType = $_FILES['malwareFile']['type'];
            
            if (in_array($fileType, $allowedTypes)) {
                $filePath = $_FILES['malwareFile']['tmp_name'];
                $fileContent = file_get_contents($filePath);
                $fileExtension = strtolower(pathinfo($_FILES['malwareFile']['name'], PATHINFO_EXTENSION));
                
                // Default to the first 20 bytes
                $headerLength = 20;
                
                switch ($fileExtension) {
                    case 'exe':
                        $headerLength = 0x3C; // Header length before PE header in executable files
                        break;
                    case 'pdf':
                        $headerLength = 5; // "%PDF-" is 5 bytes long
                        break;
                    case 'zip':
                        $headerLength = 30; // Common header length for ZIP files
                        break;
                }
                
                $signature = substr($fileContent, $headerLength, 20); // Get 20 bytes after the header
                
                // Save the malware name and signature into the database
                $conn = getDatabaseConnection();
                $stmt = $conn->prepare("INSERT INTO malware_signatures (name, signature) VALUES (?, ?)");
                $stmt->bind_param("sb", $malwareName, $signature);
                $stmt->send_long_data(1, $signature);
                
                if ($stmt->execute()) {
                    echo "Malware signature uploaded successfully.";
                } else {
                    echo "Failed to upload malware signature. Error: " . $stmt->error;
                }
                $stmt->close();
                $conn->close();
            } else {
                echo "Unsupported file type. Only .exe, .pdf, and .zip files are allowed.";
            }
            
           
        } else {
            $error = "Failed to upload file.";
        }
    }
}

if (!empty($error)) {
    echo "<p style='color:red;'>$error</p>";
}
?>

<h1>Admin Panel - Upload Malware</h1>
<div class="my-4">
    <?php
    // Check if the admin is logged in
    if (isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'] === true) {
        // Display Log Out button if admin is logged in
        echo '<a href="logout.php" class="btn btn-danger">Log Out</a>';
    }
    ?>
</div>
<form action="admin.php" method="post" enctype="multipart/form-data" onsubmit="return validateFile()">
    <div class="form-group">
        <label for="malwareName">Malware Name:</label>
        <input type="text" name="malwareName" id="malwareName" class="form-control" required pattern="[a-zA-Z0-9]+">
    </div>
    <div class="form-group">
        <label for="malwareFile">Select malware file to upload(.exe, .pdf, .zip files):</label>
        <input type="file" name="malwareFile" id="malwareFile" class="form-control-file" required>
    </div>
    <button type="submit" class="btn btn-primary">Upload Malware</button>
</form>

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
