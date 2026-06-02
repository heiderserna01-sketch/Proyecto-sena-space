<?php
session_start();
require_once 'conexion.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: Forgot-password.html');
    exit;
}

$email = trim($_POST['email'] ?? '');

if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo "<script>alert('Ingrese un correo válido.'); window.location='Forgot-password.html';</script>";
    exit;
}

$stmt = mysqli_prepare($conexion, "SELECT correo, nombre FROM admin WHERE correo = ? LIMIT 1");
if (!$stmt) {
    die('Error en la preparación de la consulta: ' . mysqli_error($conexion));
}

mysqli_stmt_bind_param($stmt, 's', $email);
if (!mysqli_stmt_execute($stmt)) {
    die('Error en la ejecución de la consulta: ' . mysqli_stmt_error($stmt));
}

mysqli_stmt_store_result($stmt);
if (mysqli_stmt_num_rows($stmt) === 0) {
    mysqli_stmt_close($stmt);
    mysqli_close($conexion);
    echo "<script>alert('El correo no está registrado en nuestra base de datos.'); window.location='Forgot-password.html';</script>";
    exit;
}

mysqli_stmt_bind_result($stmt, $dbEmail, $nombre);
mysqli_stmt_fetch($stmt);
mysqli_stmt_close($stmt);
mysqli_close($conexion);

$_SESSION['reset_email'] = $dbEmail;

echo "<script>alert('Correo válido. Ingresa la nueva contraseña.'); window.location='New_password.html';</script>";
?>