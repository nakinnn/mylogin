<?php

    session_start();
    require_once 'config/db.php';

    if (isset($_POST['signup'])){
        $firstname = $_POST['firstname'];
        $lastname = $_POST['lastname'];
        $username = $_POST['username'];
        $password = $_POST['password'];
        $c_password = $_POST['c_password'];
        $user_role = 'user';

        if (empty($firstname)) {
            $_SESSION['error'] = 'Please enter firstname.';
            header("location: ../signup");
        } else if (empty($lastname)) {
            $_SESSION['error'] = 'Please enter lastname.';
            header("location: ../signup");
        } else if (empty($username)) {
            $_SESSION['error'] = 'Please enter username.';
            header("location: ../signup");
        } else if (empty($password)) {
            $_SESSION['error'] = 'Please enter password.';
            header("location: ../signup");
        } else if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
            $_SESSION['error'] = 'Please enter new password(5 - 20 word).';
            header("location: ../signup");
        } else if (empty($c_password)) {
            $_SESSION['error'] = 'Please enter confirm_password.';
            header("location: ../signup");
        } else if ($password != $c_password) {
            $_SESSION['error'] = "Password doesn't match.";
            header("location: ../signup");
        } else{
            try{
            $check_username = $conn->prepare("SELECT username FROM users WHERE username = :username");
            $check_username->bindParam(":username", $username);
            $check_username->execute();
            $row = $check_username->fetch(PDO::FETCH_ASSOC);

            if($row['username'] == $username){
                $_SESSION['warning'] = "username was available.<a href='../signin'>click here</a>to sign in";
                header("location: ../signup");
            }else if(!isset($_SESSION['error'])){
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);
                $stmt = $conn->prepare("INSERT INTO users(firstname, lastname, username, password, user_role) VALUES(:firstname,:lastname,:username,:password,:user_role)");
                $stmt->bindParam(":firstname",$firstname);
                $stmt->bindParam(":lastname",$lastname);
                $stmt->bindParam(":username",$username);
                $stmt->bindParam(":password", $passwordHash);
                $stmt->bindParam(":user_role",$user_role);
                $stmt->execute();
                $_SESSION['success'] = "Sign up success <a href='../signin' class'alert-link'>click here</a> to sign in";
                header("location: ../signup");
            }else {
                $_SESSION['error'] = "something wrong";
                header("location: ../signup");
            }
            }catch(PDOException $e){
                echo $e->getMessage();
            }
        }
    }

?>