<?php

    session_start();
    require_once 'config/db.php';

    if (isset($_POST['signin'])){
        $username = $_POST['username'];
        $password = $_POST['password'];
        
       
        if (empty($username)) {
            $_SESSION['error'] = 'Please enter username.';
            header("location: signin.php");
        } else if (empty($password)) {
            $_SESSION['error'] = 'Please enter password.';
            header("location: signin.php");
        } else if (strlen($_POST['password']) > 20 || strlen($_POST['password']) < 5) {
            $_SESSION['error'] = 'Please enter new password(5 - 20 word).';
            header("location: signin.php");
        } else{
            try{
            $check_data = $conn->prepare("SELECT * FROM users WHERE username = :username");
            $check_data->bindParam(":username", $username);
            $check_data->execute();
            $row = $check_data->fetch(PDO::FETCH_ASSOC);
            if($check_data->rowCount()>0){
                if($username == $row['username']){
                    if(password_verify($password,$row['password'])){
                        if($row['user_role'] == 'admin'){
                            $_SESSION['admin_login'] = $row['id'];
                            header("location: ../admin");
                        }else {
                            $_SESSION['user_login'] = $row['id'];
                            header("location: ../userview");
                        }
                    }else {
                        $_SESSION['error'] = 'password was wrong';
                        header("location: ../signin");
                    }                 
                }else {
                    $_SESSION['error'] = "username was wrong";
                    header("location: ../signin");
                    }
            }else {
                $_SESSION['error'] = "username not available";
                header("location: ../signin");
            }
            }catch(PDOException $e){
                echo $e->getMessage();
            }

            
    }
}

?>