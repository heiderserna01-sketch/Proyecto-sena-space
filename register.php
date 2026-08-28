<?php
require_once 'conexion.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: Register.html');
    exit;
}

$nombre = trim($_POST['registerName'] ?? '');
$apellido = trim($_POST['registerLastName'] ?? '');
$correo = trim($_POST['registerEmail'] ?? '');
$password = $_POST['registerPassword'] ?? '';
$confirmPassword = $_POST['confirmPassword'] ?? '';
$tipoDocumento = trim($_POST['tipo_documento'] ?? '');
$cedula = trim($_POST['cedula'] ?? '');
$userType = trim($_POST['userType'] ?? '');

if ($nombre === '' || $apellido === '' || $correo === '' || $password === '' || $confirmPassword === '' || $tipoDocumento === '' || $cedula === '' || $userType === '') {
    echo "<script>alert('Por favor completa todos los campos.'); window.location='Register.html';</script>";
    exit;
}

if (!filter_var($correo, FILTER_VALIDATE_EMAIL)) {
    echo "<script>alert('Ingresa un correo válido.'); window.location='Register.html';</script>";
    exit;
}

if ($password !== $confirmPassword) {
    echo "<script>alert('Las contraseñas no coinciden.'); window.location='Register.html';</script>";
    exit;
}   

if (!ctype_digit($cedula)) {
    echo "<script>alert('La cédula debe contener solo números.'); window.location='Register.html';</script>";
    exit;
}

if (strlen($cedula) > 15) {
    echo "<script>alert('La cédula es demasiado larga.'); window.location='Register.html';</script>";
    exit;
}

$cedulaStr = $cedula;

$sql = 'SELECT `correo`, `cedula` FROM `admin` WHERE `correo` = ? OR `cedula` = ? LIMIT 1';
$stmt = mysqli_prepare($conexion, $sql);
if (!$stmt) {
    die('Error en la consulta de verificación: ' . mysqli_error($conexion));
}

mysqli_stmt_bind_param($stmt, 'ss', $correo, $cedulaStr);
if (!mysqli_stmt_execute($stmt)) {
    die('Error en la ejecución de la consulta de verificación: ' . mysqli_stmt_error($stmt));
}

mysqli_stmt_bind_result($stmt, $existingCorreo, $existingCedula);
if (mysqli_stmt_fetch($stmt)) {
    mysqli_stmt_close($stmt);
    mysqli_close($conexion);
    if ($existingCorreo === $correo) {
        echo "<script>alert('Este correo ya está registrado.'); window.location='Register.html';</script>";
    } else {
        echo "<script>alert('Esta cédula ya está registrada.'); window.location='Register.html';</script>";
    }
    exit;
}

mysqli_stmt_close($stmt);

$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
$sql = 'INSERT INTO `admin` (`cedula`, `correo`, `nombre`, `apellido`, `tipo_usuario`, `tipo_documento`, `contraseña`) VALUES (?, ?, ?, ?, ?, ?, ?)';
$stmt = mysqli_prepare($conexion, $sql);
if (!$stmt) {
    die('Error en la preparación del registro: ' . mysqli_error($conexion));
}

mysqli_stmt_bind_param($stmt, 'sssssss', $cedulaStr, $correo, $nombre, $apellido, $userType, $tipoDocumento, $hashedPassword);

if (!mysqli_stmt_execute($stmt)) {
    $error = mysqli_stmt_error($stmt);
    mysqli_stmt_close($stmt);
    mysqli_close($conexion);
    echo "<script>alert('Error al registrar: $error'); window.location='Register.html';</script>";
    exit;
}

mysqli_stmt_close($stmt);
mysqli_close($conexion);

echo "<script>alert('Registro exitoso. Ahora puedes iniciar sesión.'); window.location='Login.html';</script>";