<?php
include 'includes/session.php';
include 'includes/db.php';

// Process login logic
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);
    
    // Define minimum and maximum lengths
    $minUsernameLength = 5;
    $maxUsernameLength = 20;
    $minPasswordLength = 8;
    $maxPasswordLength = 64;
    
    // Check for length requirements
    if (empty($username) || empty($password)) {
        $error = "Both username and password are required.";
    } elseif (strlen($username) < $minUsernameLength || strlen($username) > $maxUsernameLength) {
        $error = "Username must be between $minUsernameLength and $maxUsernameLength characters.";
    } elseif (strlen($password) < $minPasswordLength || strlen($password) > $maxPasswordLength) {
        $error = "Password must be between $minPasswordLength and $maxPasswordLength characters.";
    } else {
        $conn = getDatabaseConnection();
        $stmt = $conn->prepare("SELECT password_hash FROM admins WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows == 1) {
            $row = $result->fetch_assoc();
            if (password_verify($password, $row['password_hash'])) {
                $_SESSION['admin_logged_in'] = true;
                $_SESSION['username'] = $username;
                header("Location: admin.php");
                exit();
            } else {
                $error = "Invalid password. Please try again.";
            }
        } else {
            $error = "Username not found. Please try again.";
        }
        $stmt->close();
        $conn->close();
    }
}
include 'templates/header.php'; // HTML header
?>


<div class="d-flex justify-content-center align-items-center" style="height: 60vh;">
    <form id="loginForm" action="admin_login.php" method="post" onsubmit="return validateLogin()" class="mb-3 main-centered">
        <div class="form-group">
            <label for="username">Username:</label>
            <input type="text" name="username" id="username" class="form-control" required style="max-width: 300px;">
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" name="password" id="password" class="form-control" required style="max-width: 300px;">
        </div>
    <?php if (!empty($error)) echo "<p class='error'>$error</p>"; ?>
        <button type="submit" class="btn btn-primary">Login</button>
    </form>
</div>

<script>
function validateLogin() {
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;

    // Define minimum and maximum lengths
    var minUsernameLength = 5; // minimum length for username
    var maxUsernameLength = 20; // maximum length for username
    var minPasswordLength = 8; // minimum length for password
    var maxPasswordLength = 64; // maximum length for password

    if (username.trim() === "" || password.trim() === "") {
        alert("Both username and password are required and cannot be empty.");
        return false;
    }
    if (username.length < minUsernameLength || username.length > maxUsernameLength) {
        alert("Username must be between " + minUsernameLength + " and " + maxUsernameLength + " characters.");
        return false;
    }
    if (password.length < minPasswordLength || password.length > maxPasswordLength) {
        alert("Password must be between " + minPasswordLength + " and " + maxPasswordLength + " characters.");
        return false;
    }
    return true;
}
</script>

<?php
include 'templates/footer.php'; // HTML footer
?>