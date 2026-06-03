<?php
session_start();
require_once 'conexion.php';

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    header('Location: New_password.html');
    exit;
}

$resetEmail = $_SESSION['reset_email'] ?? '';
$sessionToken = $_SESSION['reset_token'] ?? '';
$token = trim($_POST['token'] ?? '');
$newPassword = trim($_POST['newPassword'] ?? '');
$confirmPassword = trim($_POST['confirmPassword'] ?? '');

if ($resetEmail === '' || $sessionToken === '' || $token === '' || !hash_equals($sessionToken, $token)) {
    echo "<script>alert('No se encontró un enlace válido para restablecer la contraseña. Vuelve a intentarlo.'); window.location='Forgot-password.html';</script>";
    exit;
}

if ($newPassword === '' || $confirmPassword === '') {
    echo "<script>alert('Debe ingresar y confirmar la nueva contraseña.'); window.location='New_password.html';</script>";
    exit;
}

if ($newPassword !== $confirmPassword) {
    echo "<script>alert('Las contraseñas no coinciden.'); window.location='New_password.html';</script>";
    exit;
}

if (strlen($newPassword) < 6) {
    echo "<script>alert('La contraseña debe tener al menos 6 caracteres.'); window.location='New_password.html';</script>";
    exit;
}

$hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
$stmt = mysqli_prepare($conexion, "UPDATE admin SET `contraseña` = ? WHERE correo = ?");
if (!$stmt) {
    die('Error en la preparación de la consulta: ' . mysqli_error($conexion));
}

mysqli_stmt_bind_param($stmt, 'ss', $hashedPassword, $resetEmail);
if (!mysqli_stmt_execute($stmt)) {
    die('Error en la ejecución de la consulta: ' . mysqli_stmt_error($stmt));
}

if (mysqli_stmt_affected_rows($stmt) === 0) {
    echo "<script>alert('No se actualizó la contraseña. Verifica que el correo exista.'); window.location='Forgot-password.html';</script>";
} else {
    unset($_SESSION['reset_email']);
    echo "<script>alert('Contraseña actualizada correctamente.'); window.location='Login.html';</script>";
}

mysqli_stmt_close($stmt);
mysqli_close($conexion);
?>