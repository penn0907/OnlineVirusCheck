<?php
// Enforce HTTPS to ensure secure data transmission
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] != "on") {
    $redirect = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirect");
    exit();
}

// Start the session with secure settings
session_start([
    'cookie_lifetime' => 0,  // Session cookie will last until the browser is closed
    'cookie_secure' => true,  // Cookie will only be sent over HTTPS
    'cookie_httponly' => true,  // Cookie cannot be accessed by JavaScript
    'use_strict_mode' => true  // Mitigate session fixation attacks
]);

// Secure the session further by storing user's IP and user agent
if (!isset($_SESSION['initiated'])) {
    session_regenerate_id(true);
    $_SESSION['initiated'] = true;
    $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
    $_SESSION['ua'] = $_SERVER['HTTP_USER_AGENT'];
    $_SESSION['check'] = hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT']);
}

// Check if session is accessed from the same environment
if ($_SESSION['check'] != hash('ripemd128', $_SERVER['REMOTE_ADDR'] . $_SERVER['HTTP_USER_AGENT'])) {
    different_user();  // Call the function that handles session hijacking
}

// Function to handle if the session is hijacked or user's environment has changed
function different_user() {
    session_destroy();  // Destroy the session
    header('Location: login.php');  // Redirect to login page
    exit();  // Stop
}
?>