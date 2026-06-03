<?php
session_start();
require_once 'conexion.php';
require_once 'enviar.php';

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

$nombre = $nombre ?: $dbEmail;
$token = bin2hex(random_bytes(16));
$_SESSION['reset_email'] = $dbEmail;
$_SESSION['reset_token'] = $token;

$resetLink = sprintf(
    'http://%s/Proyecto-sena-space/New_password.html?token=%s',
    $_SERVER['HTTP_HOST'],
    urlencode($token)
);

$subject = 'Restablecer contraseña LOG-IN';
$body = "<p>Hola {$nombre},</p>"
    . "<p>Haz clic en este enlace para restablecer tu contraseña:</p>"
    . "<p><a href=\"{$resetLink}\">Restablecer contraseña</a></p>"
    . "<p>Si no solicitaste este cambio, ignora este correo.</p>";

if (sendEmail($dbEmail, $nombre, $subject, $body)) {
    echo "<script>alert('Se envió un enlace de restablecimiento a tu correo. Revisa tu bandeja de entrada.'); window.location='Login.html';</script>";
} else {
    echo "<script>alert('No se pudo enviar el correo de restablecimiento. Intenta más tarde.'); window.location='Forgot-password.html';</script>";
}
?>