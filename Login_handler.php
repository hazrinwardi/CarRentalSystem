<?php
// Enable error reporting for debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Retrieve form data
    $user_name = $_POST['user_name'];
    $password = $_POST['password'];

    // Database connection
    $conn = new mysqli('localhost', 'root', '', 'login_db');

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Use prepared statements to prevent SQL injection
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE user_name = ?");
    if (!$stmt) {
        die("Prepare statement failed: " . $conn->error);
    }

    // Bind parameters
    $stmt->bind_param("s", $user_name);

    // Execute the statement
    $stmt->execute();

    // Bind result variables
    $stmt->bind_result($id, $hashed_password);

    // Check if the user exists and verify the password
    if ($stmt->fetch()) {
        if (password_verify($password, $hashed_password)) {
            // Password is correct, start session and redirect to protected page
            session_start();
            $_SESSION['user_id'] = $id;
            header("Location: car_rental.html");
            exit();
        } else {
            // Incorrect password, redirect to login failed page
            header("Location: login_failed.html");
            exit();
        }
    } else {
        // No user found, redirect to login failed page
        header("Location: login_failed.html");
        exit();
    }

    // Close connections
    $stmt->close();
    $conn->close();
} else {
    echo "Invalid request method";
}
?>
