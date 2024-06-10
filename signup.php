<?php
require_once "config.php";

$username = $password = $confirm_passsword = "";
$username_err = $password_err = $confirm_passsword_err = "";

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    // if username is empty check
    if (empty(trim($_POST['username']))) {
        $username_err = "Username cannot be blank";
    } else {
        $sql = "SELECT id FROM users WHERE username = ?";
        $stmt = mysqli_prepare($conn, $sql);
        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "s", $param_username);

            // value of param username set
            $param_username = trim($_POST['username']);

            //execute the statment
            if (mysqli_stmt_execute($stmt)) {
                mysqli_stmt_store_result($stmt);
                if (mysqli_stmt_num_rows($stmt) == 1) {
                    $username_err = "This username is already taken.";
                } else {
                    $username = trim($_POST['username']);
                }
            } else {
                echo "Soemthing went wrong.";
            }
        }
    }
    mysqli_stmt_close($stmt);

    //Check  password

    if (empty(trim($_POST['password']))) {
        $password_err = "Password cannot be blank.";
    } else if (strlen(trim($_POST['password'])) < 5) {
        $password_err = "Password cannot be lessThan 5 characters.";
    } else {
        $password = trim($_POST['password']);
    }

    //Check confirmation password field

    if (trim($_POST['password']) != trim($_POST['confirm_password'])) {
        $password_err = "Password and Confirm password do not match.";
        echo $password_err;
    }

    //If no errors, go ahead and insert to database..

    if (empty($username_err) && empty($password_err) && empty($confirm_password_err)) {
        $sql = "INSERT INTO users(username, password) VALUES (?,?)";
        $stmt = mysqli_prepare($conn, $sql);
        if ($stmt) {
            mysqli_stmt_bind_param($stmt, "ss", $param_username, $param_password);

            //Set  parameters

            $param_username = $username;
            $param_password = password_hash($password, PASSWORD_DEFAULT);

            // execute the query

            if (mysqli_stmt_execute($stmt)) {
                header("location: login.html");
            } else {
                echo "Something went wrong....cannot redirect...!!!!";
            }
        }
        mysqli_stmt_close($stmt);
    }
    mysqli_close($conn);
}
