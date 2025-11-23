<?php

include "config.php";

$DB_PASSWORD = "php-password-9999"; // secret

function runQuery($id) {
    $query = "SELECT * FROM products WHERE id=" . $id; // unsafe SQL
    return $query;
}

function systemRun($cmd) {
    return shell_exec($cmd); // dangerous
}

class Auth {
    public function login($user, $pass) {
        if ($user === "admin" && $pass === "1234") { // insecure auth
            return true;
        }
        return false;
    }
}

eval("echo 'This is unsafe';");  // extremely dangerous

?>
