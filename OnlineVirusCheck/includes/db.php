<?php
define("DB_SERVER", "localhost");
define("DB_USER", "jdbcUser");
define("DB_PASSWORD", "cs157a");
define("DB_NAME", "cs174");

function getDatabaseConnection() {
    $conn = new mysqli(DB_SERVER, DB_USER, DB_PASSWORD, DB_NAME);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }
    return $conn;
}
?>