<?php
require_once 'db_config.php';
session_start(); // Mulai session untuk status login admin

// Mendapatkan aksi dari parameter GET, atau dari body request (untuk POST)
$input = json_decode(file_get_contents('php://input'), true);
$action = $_GET['action'] ?? $input['action'] ?? '';

// Router untuk menangani berbagai aksi
switch ($action) {
    // --- Public ---
    case 'get_all_data':
        get_all_data($conn);
        break;
    case 'create_order':
        create_order($conn, $input);
        break;
    case 'send_message':
        send_message($conn, $input);
        break;
    // --- Admin Login ---
    case 'login':
        handle_login($conn, $input);
        break;
    case 'logout':
        handle_logout();
        break;
    case 'check_auth':
        check_auth();
        break;
    // --- Admin Data ---
    case 'get_admin_data':
        get_admin_data($conn);
        break;
    case 'save_product':
        save_product($conn, $input);
        break;
    case 'delete_product':
        delete_product($conn, $input);
        break;
    case 'save_user':
        save_user($conn, $input);
        break;
    case 'delete_user':
        delete_user($conn, $input);
        break;
    case 'save_settings':
        save_settings($conn, $input);
        break;
    case 'update_order_status':
        update_order_status($conn, $input);
        break;
    case 'add_to_queue':
        add_to_queue($conn, $input);
        break;
    case 'update_queue_status':
        update_queue_status($conn, $input);
        break;
    case 'delete_queue':
        delete_queue($conn, $input);
        break;
    default:
        echo json_encode(['success' => false, 'message' => 'Aksi tidak valid.']);
}

$conn->close();

// --- Kumpulan Fungsi ---

function get_all_data($conn) {
    $data = [];
    // 1. Ambil Settings
    $settingsResult = $conn->query("SELECT setting_key, setting_value FROM settings");
    $settings = [];
    while($row = $settingsResult->fetch_assoc()) {
        $settings[$row['setting_key']] = $row['setting_value'];
    }
    $data['settings'] = $settings;

    // 2. Ambil Products
    $productsResult = $conn->query("SELECT * FROM products ORDER BY id ASC");
    $products = [];
    while($row = $productsResult->fetch_assoc()) {
        $row['available'] = (bool)$row['available'];
        $products[] = $row;
    }
    $data['products'] = $products;

    // 3. Ambil Antrian Aktif
    $queueResult = $conn->query("SELECT q.*, o.customer_name, o.customer_phone FROM queue q JOIN orders o ON q.order_id = o.id WHERE q.status IN ('waiting', 'called') ORDER BY q.created_at ASC");
    $data['queue'] = $queueResult->fetch_all(MYSQLI_ASSOC);
    
    echo json_encode(['success' => true, 'data' => $data]);
}

function handle_login($conn, $input) {
    $username = $input['username'] ?? '';
    $password = $input['password'] ?? '';

    $stmt = $conn->prepare("SELECT id, fullName, role FROM users WHERE username = ? AND password = ?");
    $stmt->bind_param("ss", $username, $password);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($user = $result->fetch_assoc()) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_role'] = $user['role'];
        $_SESSION['user_fullName'] = $user['fullName'];
        echo json_encode(['success' => true, 'user' => $user]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Username atau password salah.']);
    }
}

function handle_logout() {
    session_destroy();
    echo json_encode(['success' => true, 'message' => 'Logout berhasil.']);
}

function check_auth() {
    if (isset($_SESSION['user_id'])) {
        echo json_encode(['success' => true, 'user' => ['fullName' => $_SESSION['user_fullName'], 'role' => $_SESSION['user_role']]]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Tidak terautentikasi.']);
    }
}

function create_order($conn, $input) {
    $conn->begin_transaction();
    try {
        $stmt = $conn->prepare("INSERT INTO orders (order_number, customer_name, customer_phone, total_amount, status) VALUES (?, ?, ?, ?, 'pending')");
        $order_number = "ORD-" . time();
        $stmt->bind_param("sssi", $order_number, $input['customerName'], $input['customerPhone'], $input['totalAmount']);
        $stmt->execute();
        $order_id = $conn->insert_id;

        $stmt_items = $conn->prepare("INSERT INTO order_items (order_id, product_id, quantity, price) VALUES (?, ?, ?, ?)");
        foreach ($input['items'] as $item) {
            $stmt_items->bind_param("iiii", $order_id, $item['id'], $item['quantity'], $item['price']);
            $stmt_items->execute();
        }
        $conn->commit();
        echo json_encode(['success' => true, 'message' => 'Pesanan berhasil dibuat.', 'orderNumber' => $order_number]);
    } catch (Exception $e) {
        $conn->rollback();
        echo json_encode(['success' => false, 'message' => 'Gagal membuat pesanan: ' . $e->getMessage()]);
    }
}

function send_message($conn, $input) {
    // Di aplikasi nyata, ini akan mengirim email. Di sini kita simpan ke DB.
    // Anda bisa membuat tabel 'messages' jika mau, atau abaikan.
    // INSERT INTO messages (name, email, message) VALUES (...)
    echo json_encode(['success' => true, 'message' => 'Pesan terkirim (simulasi).']);
}

// --- FUNGSI ADMIN ---

function get_admin_data($conn) {
    if (!isset($_SESSION['user_id'])) {
        http_response_code(401);
        echo json_encode(['success' => false, 'message' => 'Unauthorized']);
        return;
    }
    $data = [];
    $data['orders'] = $conn->query("SELECT * FROM orders ORDER BY created_at DESC")->fetch_all(MYSQLI_ASSOC);
    $data['users'] = $conn->query("SELECT id, username, fullName, role FROM users ORDER BY fullName ASC")->fetch_all(MYSQLI_ASSOC);
    $data['queue'] = $conn->query("SELECT q.*, o.customer_name FROM queue q JOIN orders o ON q.order_id = o.id ORDER BY q.created_at DESC")->fetch_all(MYSQLI_ASSOC);
    echo json_encode(['success' => true, 'data' => $data]);
}

function save_product($conn, $input) {
    $product = $input['product'];
    $is_new = !isset($product['id']) || empty($product['id']);
    $available = $product['available'] ? 1 : 0;

    if ($is_new) {
        $stmt = $conn->prepare("INSERT INTO products (name, category, description, price, available) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssid", $product['name'], $product['category'], $product['description'], $product['price'], $available);
    } else {
        $stmt = $conn->prepare("UPDATE products SET name = ?, category = ?, description = ?, price = ?, available = ? WHERE id = ?");
        $stmt->bind_param("sssidi", $product['name'], $product['category'], $product['description'], $product['price'], $available, $product['id']);
    }
    
    if ($stmt->execute()) {
        $new_id = $is_new ? $conn->insert_id : $product['id'];
        echo json_encode(['success' => true, 'message' => 'Produk berhasil disimpan.', 'newId' => $new_id]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal menyimpan produk.']);
    }
}

function delete_product($conn, $input) {
    $id = $input['id'] ?? 0;
    $stmt = $conn->prepare("DELETE FROM products WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Produk berhasil dihapus.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal menghapus produk.']);
    }
}

function save_user($conn, $input) {
    $user = $input['user'];
    $is_new = !isset($user['id']) || empty($user['id']);

    if ($is_new) {
        $stmt = $conn->prepare("INSERT INTO users (username, password, fullName, role) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $user['username'], $user['password'], $user['fullName'], $user['role']);
    } else {
        $stmt = $conn->prepare("UPDATE users SET username = ?, password = ?, fullName = ?, role = ? WHERE id = ?");
        $stmt->bind_param("ssssi", $user['username'], $user['password'], $user['fullName'], $user['role'], $user['id']);
    }
    
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Pengguna berhasil disimpan.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal menyimpan pengguna.']);
    }
}

function delete_user($conn, $input) {
    $id = $input['id'] ?? 0;
    $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Pengguna berhasil dihapus.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal menghapus pengguna.']);
    }
}

function save_settings($conn, $input) {
    $settings = $input['settings'];
    $stmt = $conn->prepare("UPDATE settings SET setting_value = ? WHERE setting_key = ?");
    foreach ($settings as $key => $value) {
        $stmt->bind_param("ss", $value, $key);
        $stmt->execute();
    }
    echo json_encode(['success' => true, 'message' => 'Pengaturan berhasil disimpan.']);
}

function update_order_status($conn, $input) {
    $stmt = $conn->prepare("UPDATE orders SET status = ? WHERE id = ?");
    $stmt->bind_param("si", $input['status'], $input['id']);
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Status pesanan diperbarui.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal memperbarui status.']);
    }
}

function add_to_queue($conn, $input) {
    // 1. Dapatkan nomor antrian terakhir
    $result = $conn->query("SELECT queue_number FROM queue ORDER BY id DESC LIMIT 1");
    $last_queue = $result->fetch_assoc();
    $new_queue_number = 'A001';
    if ($last_queue) {
        $num = (int)substr($last_queue['queue_number'], 1) + 1;
        $new_queue_number = 'A' . str_pad($num, 3, '0', STR_PAD_LEFT);
    }
    
    // 2. Masukkan ke antrian
    $stmt = $conn->prepare("INSERT INTO queue (order_id, queue_number, status) VALUES (?, ?, 'waiting')");
    $stmt->bind_param("is", $input['id'], $new_queue_number);
    if ($stmt->execute()) {
        // 3. Update status pesanan
        $conn->query("UPDATE orders SET status = 'waiting' WHERE id = " . $input['id']);
        echo json_encode(['success' => true, 'message' => 'Pesanan ditambahkan ke antrian.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal menambah antrian.']);
    }
}

function update_queue_status($conn, $input) {
    $stmt = $conn->prepare("UPDATE queue SET status = ? WHERE id = ?");
    $stmt->bind_param("si", $input['status'], $input['id']);
    if ($stmt->execute()) {
        // Jika selesai, update juga tabel order
        if ($input['status'] == 'completed') {
            $order_id_result = $conn->query("SELECT order_id FROM queue WHERE id = " . $input['id']);
            $order_id = $order_id_result->fetch_assoc()['order_id'];
            $conn->query("UPDATE orders SET status = 'completed' WHERE id = " . $order_id);
        }
        echo json_encode(['success' => true, 'message' => 'Status antrian diperbarui.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal memperbarui antrian.']);
    }
}

function delete_queue($conn, $input) {
    $stmt = $conn->prepare("DELETE FROM queue WHERE id = ?");
    $stmt->bind_param("i", $input['id']);
    if ($stmt->execute()) {
        echo json_encode(['success' => true, 'message' => 'Antrian dihapus.']);
    } else {
        echo json_encode(['success' => false, 'message' => 'Gagal menghapus antrian.']);
    }
}

?>