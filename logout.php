<?php
include 'includes/session.php';

// Unset all session related to admin login
unset($_SESSION['admin_logged_in']);

// destroy the session
session_destroy();

// Redirect to the main page or login page
header('Location: index.php');
exit();
?>