<?php
// Pengaturan Koneksi Database
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'root'); // Ganti dengan username database Anda
define('DB_PASSWORD', '');     // Ganti dengan password database Anda
define('DB_NAME', 'kopi'); // Ganti dengan nama database Anda

// Membuat koneksi
$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Cek koneksi
if ($conn->connect_error) {
    // Menghentikan script dan mengirim response error dalam format JSON
    header('Content-Type: application/json');
    http_response_code(500); // Internal Server Error
    die(json_encode(['success' => false, 'message' => 'Koneksi Database Gagal: ' . $conn->connect_error]));
}

// Mengatur header default untuk semua output agar berupa JSON
header('Content-Type: application/json');
?>