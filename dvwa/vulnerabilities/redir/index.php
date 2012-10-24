<?php

if ($_GET['token']) {
    header('Location: ' . base64_decode($_GET['token']));
} 

?>
