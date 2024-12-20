<?php 
session_start();

// initializing variables
$username = "";
$email = "";
$errors = array();

//connect to my database on phpMyAdmin
$db = mysqli_connect('localhost',  'root',  '',  'final_project');

//REGISTER USERS
if (isset($_POST['reg_user'])){
    //receive all input values from the form
    $username = mysqli_real_escape_string($db, $_POST['username']);
    $email = mysqli_real_escape_string($db, $_POST['email']);
    $occupation = mysqli_real_escape_string($db, $_POST['occupation']);
    $password = mysqli_real_escape_string($db, $_POST['password']);
}

//CHECKS AND VALIDATES INFORMATION 
if (empty($username)) { array_push($errors, "Username is required"); }
if (empty($email)) { array_push($errors, "Email is required"); }
if (empty($password)) { array_push($errors, "Password is required"); }


//CHECKS TO MAKE SURE THERE IS NO SIMILAR EMAIL OR USERNAME
$user_check_query = "SELECT * FROM users WHERE username='$username' or email = '$email' LIMIT 1";
$result= mysqli_query($db, $user_check_query);
$user = mysqli_fetch_assoc($result);


if ($user['username'] === $username) {
        array_push($errors, "Username already exists");
}

if ($user['email'] === $email) {
    array_push($errors, "Email already exists");
}

if (count($errors) === 0) {
    $password = md5($password_1);

    $query = "INSERT INTO users (username, email, password)
                VALUES ('$username', '$email', '$password')";

mysqli_query($db, $query);
$_SESSION['username'] = $username;
$_SESSION['success'] = "You are now logged in.";
header('location: index2.php');
}


//LOGIN USER
if (isset($_POST['login_user'])) {
    $username = mysqli_real_escape_string($db, $_POST['username']);
    $password = mysqli_real_escape_string($db, $_POST['password']);

    if (empty($username)) {
        array_push($errors, "Username is required");
    }

    if (empty($password)) {
        array_push($errors, "Password is required");
    }

    if (count($errors) ===0) {
        $password = md5($password);
        $query = "SELECT * FROM users WHERE username='$username' AND password='$password' ";
        $results = mysqli_query($db, $query);
        if (mysqli_num_rows($results) ==1) {
            $_SESSION['username'] = $username;
            $_SESSION['success'] = "You are now logged in.";
            header('location: index2.php');
        }else{
            array_push($errors, "Wrong username/password combination");
        }
    }
}

?>