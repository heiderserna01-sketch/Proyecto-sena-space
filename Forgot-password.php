<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
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

$dbEmail = (string) $dbEmail;
$nombre  = $nombre !== null ? (string) $nombre : null;

mysqli_stmt_close($stmt);

$nombre = $nombre ?: $dbEmail;

// Asegurar la tabla de resets
$createSql = "CREATE TABLE IF NOT EXISTS password_resets (
  correo varchar(100) NOT NULL,
  token varchar(64) NOT NULL,
  expires_at datetime NOT NULL,
  PRIMARY KEY (correo, token)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;";
if (!mysqli_query($conexion, $createSql)) {
    error_log('No se pudo crear password_resets: ' . mysqli_error($conexion));
}

$token = bin2hex(random_bytes(16));
$expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));

$insert = mysqli_prepare($conexion, "REPLACE INTO password_resets (correo, token, expires_at) VALUES (?, ?, ?)");
if ($insert) {
    mysqli_stmt_bind_param($insert, 'sss', $dbEmail, $token, $expiresAt);
    mysqli_stmt_execute($insert);
    mysqli_stmt_close($insert);
} else {
    error_log('Error preparando insert token: ' . mysqli_error($conexion));
}

$resetLink = sprintf(
    'http://%s/Proyecto-sena-space/New_password.html?token=%s&email=%s',
    $_SERVER['HTTP_HOST'],
    urlencode($token),
    urlencode($dbEmail)
);

// suministrar la ip cada que se hagan pruebas
// $resetLink = sprintf(
//     'http://aca-va-la-ip/Proyecto-sena-space/New_password.html?token=%s&email=%s',
//     urlencode($token),
//     urlencode($dbEmail)
// );

$subject = 'Restablecer password LOG-IN';
$body = "<p>Hola {$nombre},</p>"
    . "<p>Haz clic en este enlace para restablecer tu contraseña:</p>"
    . "<p><a href=\"{$resetLink}\">Restablecer contraseña</a></p>"
    . "<p>Si no solicitaste este cambio, ignora este correo.</p>";

if (sendEmail($dbEmail, $nombre, $subject, $body)) {
    echo "<script>alert('Se envió un enlace de restablecimiento a tu correo. Revisa tu bandeja de entrada.'); window.location='Login.html';</script>";
} else {
    echo "<script>alert('No se pudo enviar el correo de restablecimiento. Intenta más tarde.'); window.location='Forgot-password.html';</script>";
}

mysqli_close($conexion);
