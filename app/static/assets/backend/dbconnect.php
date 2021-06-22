<?php
    // session_start();
    define('DB_SERVER', 'localhost');
    define('DB_USERNAME', 'root');
    define('DB_PASSWORD', '');
    define('DB_NAME', 'enqueue');

    $DB_SERVER = 'localhost';
    $DB_NAME = 'enqueue';
    $charset = 'utf8mb4';

    define('DSN', "mysql:host=$DB_SERVER;dbname=$DB_NAME;charset=$charset");
    // $DSN = "mysql:host=$DB_SERVER;dbname=$DB_NAME;charset=$charset";
    $OPTIONS = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    $pdo = new PDO(DSN, DB_USERNAME, DB_PASSWORD, $OPTIONS);
?>

<?php 
    /* Attempt to connect to MySQL database */
    $link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    
    // Check connection
    if($link === false){
        die("ERROR: Could Not Connect to Server. " . mysqli_connect_error());
    }
?>