<?php
declare(strict_types=1);

/* ============================================================================
   1. DATABASE CONFIGURATION
   ============================================================================ */
define('DB_HOST', 'localhost');
define('DB_NAME', 'badminton_inventory');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

/* ============================================================================
   2. DATABASE CONNECTION
   ============================================================================ */
function getDB(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = sprintf('mysql:host=%s;dbname=%s;charset=%s', DB_HOST, DB_NAME, DB_CHARSET);
    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];

    try {
        $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
        return $pdo;
    } catch (PDOException $e) {
        error_log('Database connection error: ' . $e->getMessage());
        http_response_code(500);
        exit('Unable to connect to the inventory database. Please ensure MariaDB is running and badminton_inventory exists.');
    }
}

/* ============================================================================
   3. SESSION MANAGEMENT
   ============================================================================ */
function startSecureSession(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443);

    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    session_start();
}

startSecureSession();

/* ============================================================================
   4. SECURITY HELPERS
   ============================================================================ */
function e(?string $value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function setFlash(string $type, string $message): void
{
    $_SESSION['flash'] = [
        'type'    => in_array($type, ['success', 'danger', 'warning', 'info'], true) ? $type : 'info',
        'message' => $message,
    ];
}

function pullFlash(): ?array
{
    if (!isset($_SESSION['flash']) || !is_array($_SESSION['flash'])) {
        return null;
    }
    $flash = $_SESSION['flash'];
    unset($_SESSION['flash']);
    return $flash;
}

function redirectTo(string $page, array $params = []): never
{
    $query = array_merge(['page' => $page], $params);
    header('Location: index.php?' . http_build_query($query));
    exit;
}

function sanitizeOptionalImageUrl(?string $url): ?string
{
    $url = trim((string)($url ?? ''));
    if ($url === '') {
        return null;
    }
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return '__INVALID__';
    }
    $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
    if (!in_array($scheme, ['http', 'https'], true)) {
        return '__INVALID__';
    }
    return $url;
}

/* ============================================================================
   5. CSRF HELPERS
   ============================================================================ */
function getCsrfToken(): string
{
    if (empty($_SESSION['csrf_token']) || !is_string($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrfInput(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(getCsrfToken()) . '">';
}

function verifyCsrfToken(?string $token): bool
{
    if (!is_string($token) || $token === '' || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/* ============================================================================
   6. AUTHENTICATION
   ============================================================================ */
function isAuthenticated(): bool
{
    return !empty($_SESSION['user']) && is_array($_SESSION['user']) && !empty($_SESSION['user']['id']);
}

function currentUser(): ?array
{
    return isAuthenticated() ? $_SESSION['user'] : null;
}

function attemptLogin(string $username, string $password): bool
{
    $username = trim($username);
    if ($username === '' || $password === '') {
        return false;
    }

    $pdo = getDB();
    $stmt = $pdo->prepare('SELECT id, full_name, username, password, role FROM users WHERE username = :username LIMIT 1');
    $stmt->execute([':username' => $username]);
    $user = $stmt->fetch();

    if (!$user || !password_verify($password, (string)$user['password'])) {
        return false;
    }

    if (password_needs_rehash((string)$user['password'], PASSWORD_DEFAULT)) {
        $newHash = password_hash($password, PASSWORD_DEFAULT);
        $upd = $pdo->prepare('UPDATE users SET password = :password WHERE id = :id');
        $upd->execute([':password' => $newHash, ':id' => $user['id']]);
    }

    session_regenerate_id(true);
    $_SESSION['user'] = [
        'id'        => (int)$user['id'],
        'full_name' => (string)$user['full_name'],
        'username'  => (string)$user['username'],
        'role'      => $user['role'] === 'admin' ? 'admin' : 'user',
    ];
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

    return true;
}

function logoutUser(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            (bool)$params['secure'],
            (bool)$params['httponly']
        );
    }
    session_destroy();
}

/* ============================================================================
   7. ROLE AND PERMISSION HELPERS
   ============================================================================ */
function isAdmin(): bool
{
    $user = currentUser();
    return $user !== null && ($user['role'] ?? '') === 'admin';
}

function requireAuth(): void
{
    if (!isAuthenticated()) {
        setFlash('warning', 'Please sign in to access the Badminton Inventory Management System.');
        redirectTo('login');
    }
}

function requireAdmin(): void
{
    requireAuth();
    if (!isAdmin()) {
        http_response_code(403);
        setFlash('danger', 'Access denied. Administrator privileges are required for that action.');
        redirectTo('dashboard');
    }
}

function computeStockStatus(int $stockQty, int $minStock): string
{
    if ($stockQty <= 0) {
        return 'Out of Stock';
    }
    if ($stockQty <= $minStock) {
        return 'Low Stock';
    }
    return 'In Stock';
}

function stockStatusBadgeClass(string $status): string
{
    return match ($status) {
        'Out of Stock' => 'bg-danger-subtle text-danger border border-danger-subtle',
        'Low Stock'    => 'bg-warning-subtle text-dark border border-warning',
        default        => 'bg-success-subtle text-success border border-success-subtle',
    };
}

/* ============================================================================
   8. CRUD OPERATIONS (PRODUCTS & USERS)
   ============================================================================ */
function validateProductPayload(array $input): array
{
    $errors = [];

    $productName = trim((string)($input['product_name'] ?? ''));
    $category    = trim((string)($input['category'] ?? ''));
    $brand       = trim((string)($input['brand'] ?? ''));
    $description = trim((string)($input['description'] ?? ''));
    $imageRaw    = (string)($input['product_image'] ?? '');

    $purchaseRaw = trim((string)($input['purchase_price'] ?? ''));
    $sellingRaw  = trim((string)($input['selling_price'] ?? ''));
    $stockRaw    = trim((string)($input['stock_quantity'] ?? ''));
    $minStockRaw = trim((string)($input['minimum_stock'] ?? ''));

    if ($productName === '') {
        $errors[] = 'Product name is required.';
    } elseif (mb_strlen($productName) > 150) {
        $errors[] = 'Product name must not exceed 150 characters.';
    }

    $allowedCategories = ['Racket', 'String', 'Shuttlecock'];
    if (!in_array($category, $allowedCategories, true)) {
        $errors[] = 'Please select a valid category (Racket, String, or Shuttlecock).';
    }

    if (mb_strlen($brand) > 100) {
        $errors[] = 'Brand must not exceed 100 characters.';
    }

    if ($purchaseRaw === '' || !is_numeric($purchaseRaw) || (float)$purchaseRaw < 0) {
        $errors[] = 'Purchase price must be a valid number and cannot be negative.';
    }

    if ($sellingRaw === '' || !is_numeric($sellingRaw) || (float)$sellingRaw < 0) {
        $errors[] = 'Selling price must be a valid number and cannot be negative.';
    }

    if ($stockRaw === '' || filter_var($stockRaw, FILTER_VALIDATE_INT) === false || (int)$stockRaw < 0) {
        $errors[] = 'Stock quantity must be a whole number and cannot be negative.';
    }

    if ($minStockRaw === '' || filter_var($minStockRaw, FILTER_VALIDATE_INT) === false || (int)$minStockRaw < 0) {
        $errors[] = 'Minimum stock alert must be a whole number and cannot be negative.';
    }

    $cleanImage = sanitizeOptionalImageUrl($imageRaw);
    if ($cleanImage === '__INVALID__') {
        $errors[] = 'Product image URL must be a valid http or https link.';
        $cleanImage = null;
    }

    return [
        'errors' => $errors,
        'data'   => [
            'product_name'   => $productName,
            'category'       => $category,
            'brand'          => $brand,
            'description'    => $description !== '' ? $description : null,
            'purchase_price' => number_format(max(0.0, (float)$purchaseRaw), 2, '.', ''),
            'selling_price'  => number_format(max(0.0, (float)$sellingRaw), 2, '.', ''),
            'stock_quantity' => max(0, (int)$stockRaw),
            'minimum_stock'  => max(0, (int)$minStockRaw),
            'product_image'  => $cleanImage,
        ],
    ];
}

function createProduct(array $input): array
{
    $validated = validateProductPayload($input);
    if (!empty($validated['errors'])) {
        return ['ok' => false, 'message' => implode(' ', $validated['errors'])];
    }

    $d = $validated['data'];
    $pdo = getDB();

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare(
            'INSERT INTO products
                (product_name, category, brand, description, purchase_price, selling_price, stock_quantity, minimum_stock, product_image)
             VALUES
                (:product_name, :category, :brand, :description, :purchase_price, :selling_price, :stock_quantity, :minimum_stock, :product_image)'
        );
        $stmt->execute([
            ':product_name'   => $d['product_name'],
            ':category'       => $d['category'],
            ':brand'          => $d['brand'],
            ':description'    => $d['description'],
            ':purchase_price' => $d['purchase_price'],
            ':selling_price'  => $d['selling_price'],
            ':stock_quantity' => $d['stock_quantity'],
            ':minimum_stock'  => $d['minimum_stock'],
            ':product_image'  => $d['product_image'],
        ]);

        $productId = (int)$pdo->lastInsertId();
        $user = currentUser();

        if ($d['stock_quantity'] > 0) {
            $mov = $pdo->prepare(
                'INSERT INTO stock_movements (product_id, user_id, movement_type, quantity, remarks)
                 VALUES (:product_id, :user_id, :movement_type, :quantity, :remarks)'
            );
            $mov->execute([
                ':product_id'    => $productId,
                ':user_id'       => $user['id'] ?? null,
                ':movement_type' => 'Stock In',
                ':quantity'      => $d['stock_quantity'],
                ':remarks'       => 'Initial opening stock upon product creation',
            ]);
        }

        $pdo->commit();
        return ['ok' => true, 'message' => 'Product "' . $d['product_name'] . '" added to inventory.'];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('Create product error: ' . $e->getMessage());
        return ['ok' => false, 'message' => 'Failed to save product due to a database error.'];
    }
}

function updateProduct(int $id, array $input): array
{
    if ($id <= 0) {
        return ['ok' => false, 'message' => 'Invalid product ID.'];
    }

    $validated = validateProductPayload($input);
    if (!empty($validated['errors'])) {
        return ['ok' => false, 'message' => implode(' ', $validated['errors'])];
    }

    $d = $validated['data'];
    $pdo = getDB();

    try {
        $stmt = $pdo->prepare(
            'UPDATE products SET
                product_name = :product_name,
                category = :category,
                brand = :brand,
                description = :description,
                purchase_price = :purchase_price,
                selling_price = :selling_price,
                stock_quantity = :stock_quantity,
                minimum_stock = :minimum_stock,
                product_image = :product_image
             WHERE id = :id'
        );
        $stmt->execute([
            ':product_name'   => $d['product_name'],
            ':category'       => $d['category'],
            ':brand'          => $d['brand'],
            ':description'    => $d['description'],
            ':purchase_price' => $d['purchase_price'],
            ':selling_price'  => $d['selling_price'],
            ':stock_quantity' => $d['stock_quantity'],
            ':minimum_stock'  => $d['minimum_stock'],
            ':product_image'  => $d['product_image'],
            ':id'             => $id,
        ]);

        if ($stmt->rowCount() === 0) {
            $check = $pdo->prepare('SELECT id FROM products WHERE id = :id');
            $check->execute([':id' => $id]);
            if (!$check->fetch()) {
                return ['ok' => false, 'message' => 'Product not found.'];
            }
        }

        return ['ok' => true, 'message' => 'Product "' . $d['product_name'] . '" updated successfully.'];
    } catch (Throwable $e) {
        error_log('Update product error: ' . $e->getMessage());
        return ['ok' => false, 'message' => 'Failed to update product due to a database error.'];
    }
}

function deleteProduct(int $id): array
{
    if (!isAdmin()) {
        return ['ok' => false, 'message' => 'Only administrators can delete products.'];
    }
    if ($id <= 0) {
        return ['ok' => false, 'message' => 'Invalid product ID.'];
    }

    $pdo = getDB();
    try {
        $stmt = $pdo->prepare('DELETE FROM products WHERE id = :id');
        $stmt->execute([':id' => $id]);
        if ($stmt->rowCount() === 0) {
            return ['ok' => false, 'message' => 'Product not found or already deleted.'];
        }
        return ['ok' => true, 'message' => 'Product deleted permanently from inventory.'];
    } catch (Throwable $e) {
        error_log('Delete product error: ' . $e->getMessage());
        return ['ok' => false, 'message' => 'Unable to delete product due to a database error.'];
    }
}

function createUserAccount(array $input): array
{
    requireAdmin();

    $fullName = trim((string)($input['full_name'] ?? ''));
    $username = strtolower(trim((string)($input['username'] ?? '')));
    $password = (string)($input['password'] ?? '');
    $role     = (string)($input['role'] ?? 'user');

    $errors = [];
    if ($fullName === '' || mb_strlen($fullName) > 120) {
        $errors[] = 'Full name is required (maximum 120 characters).';
    }
    if ($username === '' || !preg_match('/^[a-z0-9_]{3,40}$/', $username)) {
        $errors[] = 'Username must be 3-40 characters using lowercase letters, numbers, or underscores.';
    }
    if (strlen($password) < 6) {
        $errors[] = 'Password must be at least 6 characters long.';
    }
    if (!in_array($role, ['admin', 'user'], true)) {
        $errors[] = 'Role must be either Admin or User.';
    }

    if (!empty($errors)) {
        return ['ok' => false, 'message' => implode(' ', $errors)];
    }

    $pdo = getDB();
    $dup = $pdo->prepare('SELECT id FROM users WHERE username = :username LIMIT 1');
    $dup->execute([':username' => $username]);
    if ($dup->fetch()) {
        return ['ok' => false, 'message' => 'Username "' . $username . '" is already taken.'];
    }

    try {
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare(
            'INSERT INTO users (full_name, username, password, role)
             VALUES (:full_name, :username, :password, :role)'
        );
        $stmt->execute([
            ':full_name' => $fullName,
            ':username'  => $username,
            ':password'  => $hash,
            ':role'      => $role,
        ]);
        return ['ok' => true, 'message' => 'User account "' . $username . '" created successfully.'];
    } catch (Throwable $e) {
        error_log('Create user error: ' . $e->getMessage());
        return ['ok' => false, 'message' => 'Failed to create user account.'];
    }
}

function updateUserAccount(int $targetId, array $input): array
{
    requireAdmin();

    if ($targetId <= 0) {
        return ['ok' => false, 'message' => 'Invalid user ID.'];
    }

    $fullName = trim((string)($input['full_name'] ?? ''));
    $username = strtolower(trim((string)($input['username'] ?? '')));
    $password = (string)($input['password'] ?? '');
    $role     = (string)($input['role'] ?? 'user');

    $errors = [];
    if ($fullName === '' || mb_strlen($fullName) > 120) {
        $errors[] = 'Full name is required (maximum 120 characters).';
    }
    if ($username === '' || !preg_match('/^[a-z0-9_]{3,40}$/', $username)) {
        $errors[] = 'Username must be 3-40 characters using lowercase letters, numbers, or underscores.';
    }
    if ($password !== '' && strlen($password) < 6) {
        $errors[] = 'New password must be at least 6 characters long.';
    }
    if (!in_array($role, ['admin', 'user'], true)) {
        $errors[] = 'Role must be either Admin or User.';
    }

    if (!empty($errors)) {
        return ['ok' => false, 'message' => implode(' ', $errors)];
    }

    $pdo = getDB();
    $existingStmt = $pdo->prepare('SELECT id, username, role FROM users WHERE id = :id LIMIT 1');
    $existingStmt->execute([':id' => $targetId]);
    $existing = $existingStmt->fetch();

    if (!$existing) {
        return ['ok' => false, 'message' => 'User account not found.'];
    }

    $dupStmt = $pdo->prepare('SELECT id FROM users WHERE username = :username AND id <> :id LIMIT 1');
    $dupStmt->execute([':username' => $username, ':id' => $targetId]);
    if ($dupStmt->fetch()) {
        return ['ok' => false, 'message' => 'Another user already uses the username "' . $username . '".'];
    }

    try {
        if ($password !== '') {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare(
                'UPDATE users SET full_name = :full_name, username = :username, password = :password, role = :role WHERE id = :id'
            );
            $stmt->execute([
                ':full_name' => $fullName,
                ':username'  => $username,
                ':password'  => $hash,
                ':role'      => $role,
                ':id'        => $targetId,
            ]);
        } else {
            $stmt = $pdo->prepare(
                'UPDATE users SET full_name = :full_name, username = :username, role = :role WHERE id = :id'
            );
            $stmt->execute([
                ':full_name' => $fullName,
                ':username'  => $username,
                ':role'      => $role,
                ':id'        => $targetId,
            ]);
        }

        $actor = currentUser();
        if ($actor && (int)$actor['id'] === $targetId) {
            $_SESSION['user']['full_name'] = $fullName;
            $_SESSION['user']['username']  = $username;
            $_SESSION['user']['role']      = $role;
        }

        return ['ok' => true, 'message' => 'User "' . $username . '" updated successfully.'];
    } catch (Throwable $e) {
        error_log('Update user error: ' . $e->getMessage());
        return ['ok' => false, 'message' => 'Failed to update user account.'];
    }
}

function deleteUserAccount(int $targetId): array
{
    requireAdmin();

    $actor = currentUser();
    if ($targetId <= 0) {
        return ['ok' => false, 'message' => 'Invalid user ID.'];
    }
    if ($actor && (int)$actor['id'] === $targetId) {
        return ['ok' => false, 'message' => 'You cannot delete your own currently logged-in administrator account.'];
    }

    $pdo = getDB();
    try {
        $stmt = $pdo->prepare('DELETE FROM users WHERE id = :id');
        $stmt->execute([':id' => $targetId]);
        if ($stmt->rowCount() === 0) {
            return ['ok' => false, 'message' => 'User account not found.'];
        }
        return ['ok' => true, 'message' => 'User account removed successfully.'];
    } catch (Throwable $e) {
        error_log('Delete user error: ' . $e->getMessage());
        return ['ok' => false, 'message' => 'Unable to delete user account due to a database error.'];
    }
}

/* ============================================================================
   10. STOCK MOVEMENT LOGIC
   ============================================================================ */
function recordStockMovement(array $input): array
{
    $productId    = filter_var($input['product_id'] ?? '', FILTER_VALIDATE_INT);
    $movementType = trim((string)($input['movement_type'] ?? ''));
    $quantity     = filter_var($input['quantity'] ?? '', FILTER_VALIDATE_INT);
    $remarks      = trim((string)($input['remarks'] ?? ''));

    if ($productId === false || $productId <= 0) {
        return ['ok' => false, 'message' => 'Please select a valid badminton product.'];
    }
    if (!in_array($movementType, ['Stock In', 'Stock Out'], true)) {
        return ['ok' => false, 'message' => 'Movement type must be Stock In or Stock Out.'];
    }
    if ($quantity === false || $quantity <= 0) {
        return ['ok' => false, 'message' => 'Quantity must be greater than zero.'];
    }
    if (mb_strlen($remarks) > 255) {
        return ['ok' => false, 'message' => 'Remarks cannot exceed 255 characters.'];
    }

    $pdo = getDB();
    try {
        $pdo->beginTransaction();

        $lockStmt = $pdo->prepare(
            'SELECT id, product_name, stock_quantity FROM products WHERE id = :id FOR UPDATE'
        );
        $lockStmt->execute([':id' => $productId]);
        $product = $lockStmt->fetch();

        if (!$product) {
            $pdo->rollBack();
            return ['ok' => false, 'message' => 'Selected product does not exist.'];
        }

        $currentStock = (int)$product['stock_quantity'];
        if ($movementType === 'Stock In') {
            $newStock = $currentStock + $quantity;
        } else {
            if ($quantity > $currentStock) {
                $pdo->rollBack();
                return [
                    'ok'      => false,
                    'message' => sprintf(
                        'Cannot record Stock Out of %d units for "%s". Available stock is only %d units.',
                        $quantity,
                        $product['product_name'],
                        $currentStock
                    ),
                ];
            }
            $newStock = $currentStock - $quantity;
        }

        if ($newStock < 0) {
            $pdo->rollBack();
            return ['ok' => false, 'message' => 'Stock quantity cannot become negative.'];
        }

        $updStock = $pdo->prepare('UPDATE products SET stock_quantity = :stock WHERE id = :id');
        $updStock->execute([
            ':stock' => $newStock,
            ':id'    => $productId,
        ]);

        $actor = currentUser();
        $insMov = $pdo->prepare(
            'INSERT INTO stock_movements (product_id, user_id, movement_type, quantity, remarks)
             VALUES (:product_id, :user_id, :movement_type, :quantity, :remarks)'
        );
        $insMov->execute([
            ':product_id'    => $productId,
            ':user_id'       => $actor['id'] ?? null,
            ':movement_type' => $movementType,
            ':quantity'      => $quantity,
            ':remarks'       => $remarks !== '' ? $remarks : null,
        ]);

        $pdo->commit();

        return [
            'ok'      => true,
            'message' => sprintf(
                '%s (%d units) recorded for "%s". Current stock: %d units.',
                $movementType,
                $quantity,
                $product['product_name'],
                $newStock
            ),
        ];
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log('Stock movement error: ' . $e->getMessage());
        return ['ok' => false, 'message' => 'Failed to record stock movement due to a database error.'];
    }
}

/* ============================================================================
   8B. POST REQUEST HANDLER
   ============================================================================ */
$requestedPage = strtolower(trim((string)($_GET['page'] ?? 'dashboard')));
$allowedPages  = ['login', 'dashboard', 'inventory', 'stock', 'reports', 'users'];
if (!in_array($requestedPage, $allowedPages, true)) {
    $requestedPage = 'dashboard';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');

    if ($action === 'login') {
        if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
            setFlash('danger', 'Security token mismatch. Please refresh and try again.');
            redirectTo('login');
        }
        $username = (string)($_POST['username'] ?? '');
        $password = (string)($_POST['password'] ?? '');

        if (attemptLogin($username, $password)) {
            $user = currentUser();
            setFlash('success', 'Selamat datang, ' . ($user['full_name'] ?? 'Player') . '! Ready to manage badminton stock.');
            redirectTo('dashboard');
        } else {
            setFlash('danger', 'Invalid username or password. Please check your credentials and try again.');
            redirectTo('login');
        }
    }

    if ($action === 'logout') {
        if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
            setFlash('warning', 'Session token expired. You have been signed out safely.');
        } else {
            setFlash('info', 'You have been logged out cleanly.');
        }
        $savedFlash = $_SESSION['flash'] ?? null;
        logoutUser();
        if ($savedFlash !== null) {
            startSecureSession();
            $_SESSION['flash'] = $savedFlash;
        }
        redirectTo('login');
    }

    requireAuth();

    if (!verifyCsrfToken($_POST['csrf_token'] ?? null)) {
        setFlash('danger', 'Invalid or expired CSRF token. Action blocked for your security.');
        redirectTo($requestedPage === 'login' ? 'dashboard' : $requestedPage);
    }

    switch ($action) {
        case 'create_product':
            $res = createProduct($_POST);
            setFlash($res['ok'] ? 'success' : 'danger', $res['message']);
            redirectTo('inventory');

        case 'update_product':
            $pid = (int)($_POST['product_id'] ?? 0);
            $res = updateProduct($pid, $_POST);
            setFlash($res['ok'] ? 'success' : 'danger', $res['message']);
            redirectTo('inventory');

        case 'delete_product':
            if (!isAdmin()) {
                http_response_code(403);
                setFlash('danger', 'Only administrators are allowed to delete products.');
                redirectTo('inventory');
            }
            $pid = (int)($_POST['product_id'] ?? 0);
            $res = deleteProduct($pid);
            setFlash($res['ok'] ? 'success' : 'danger', $res['message']);
            redirectTo('inventory');

        case 'record_movement':
            $res = recordStockMovement($_POST);
            $returnPage = in_array($_POST['return_page'] ?? '', ['stock', 'inventory', 'dashboard'], true)
                ? (string)$_POST['return_page']
                : 'stock';
            setFlash($res['ok'] ? 'success' : 'danger', $res['message']);
            redirectTo($returnPage);

        case 'create_user':
            requireAdmin();
            $res = createUserAccount($_POST);
            setFlash($res['ok'] ? 'success' : 'danger', $res['message']);
            redirectTo('users');

        case 'update_user':
            requireAdmin();
            $uid = (int)($_POST['user_id'] ?? 0);
            $res = updateUserAccount($uid, $_POST);
            setFlash($res['ok'] ? 'success' : 'danger', $res['message']);
            redirectTo('users');

        case 'delete_user':
            requireAdmin();
            $uid = (int)($_POST['user_id'] ?? 0);
            $res = deleteUserAccount($uid);
            setFlash($res['ok'] ? 'success' : 'danger', $res['message']);
            redirectTo('users');

        default:
            setFlash('warning', 'Unrecognized form action.');
            redirectTo('dashboard');
    }
}

/* ============================================================================
   PAGE ACCESS CONTROL & 11. DASHBOARD / DATA QUERIES
   ============================================================================ */
if ($requestedPage === 'login') {
    if (isAuthenticated()) {
        redirectTo('dashboard');
    }
} else {
    requireAuth();
    if ($requestedPage === 'users' && !isAdmin()) {
        http_response_code(403);
        setFlash('danger', 'User Management is restricted to administrators only.');
        redirectTo('dashboard');
    }
}

function fetchDashboardMetrics(): array
{
    $pdo = getDB();

    $summary = $pdo->query(
        'SELECT
            COUNT(*) AS total_products,
            COALESCE(SUM(stock_quantity), 0) AS total_units,
            SUM(CASE WHEN stock_quantity = 0 THEN 1 ELSE 0 END) AS out_of_stock,
            SUM(CASE WHEN stock_quantity > 0 AND stock_quantity <= minimum_stock THEN 1 ELSE 0 END) AS low_stock,
            COALESCE(SUM(purchase_price * stock_quantity), 0.00) AS total_inventory_value
         FROM products'
    )->fetch() ?: [];

    $catRows = $pdo->query(
        'SELECT
            category,
            COUNT(*) AS product_count,
            COALESCE(SUM(stock_quantity), 0) AS total_units,
            COALESCE(SUM(purchase_price * stock_quantity), 0.00) AS category_value
         FROM products
         GROUP BY category'
    )->fetchAll();

    $categoriesMap = [
        'Racket'      => ['product_count' => 0, 'total_units' => 0, 'category_value' => 0.0],
        'String'      => ['product_count' => 0, 'total_units' => 0, 'category_value' => 0.0],
        'Shuttlecock' => ['product_count' => 0, 'total_units' => 0, 'category_value' => 0.0],
    ];
    foreach ($catRows as $row) {
        $c = (string)$row['category'];
        if (isset($categoriesMap[$c])) {
            $categoriesMap[$c] = [
                'product_count'  => (int)$row['product_count'],
                'total_units'    => (int)$row['total_units'],
                'category_value' => (float)$row['category_value'],
            ];
        }
    }

    $levelRows = $pdo->query(
        'SELECT product_name, category, stock_quantity, minimum_stock
         FROM products
         ORDER BY stock_quantity ASC, product_name ASC
         LIMIT 10'
    )->fetchAll();

    $recentMovements = $pdo->query(
        'SELECT
            sm.id,
            sm.movement_type,
            sm.quantity,
            sm.remarks,
            sm.created_at,
            p.product_name,
            p.category,
            COALESCE(u.full_name, u.username, "System") AS actor_name
         FROM stock_movements sm
         INNER JOIN products p ON p.id = sm.product_id
         LEFT JOIN users u ON u.id = sm.user_id
         ORDER BY sm.created_at DESC, sm.id DESC
         LIMIT 8'
    )->fetchAll();

    return [
        'total_products'        => (int)($summary['total_products'] ?? 0),
        'total_units'           => (int)($summary['total_units'] ?? 0),
        'total_categories'      => 3,
        'low_stock'             => (int)($summary['low_stock'] ?? 0),
        'out_of_stock'          => (int)($summary['out_of_stock'] ?? 0),
        'total_inventory_value' => (float)($summary['total_inventory_value'] ?? 0.0),
        'categories_map'        => $categoriesMap,
        'level_rows'            => $levelRows,
        'recent_movements'      => $recentMovements,
    ];
}

function fetchFilteredProducts(string $search, string $category, string $status): array
{
    $pdo = getDB();
    $sql = 'SELECT * FROM products WHERE 1=1';
    $params = [];

    if ($search !== '') {
        $sql .= ' AND (product_name LIKE :q_name OR brand LIKE :q_brand OR description LIKE :q_desc)';
        $like = '%' . $search . '%';
        $params[':q_name']  = $like;
        $params[':q_brand'] = $like;
        $params[':q_desc']  = $like;
    }

    if (in_array($category, ['Racket', 'String', 'Shuttlecock'], true)) {
        $sql .= ' AND category = :category';
        $params[':category'] = $category;
    }

    if ($status === 'Out of Stock') {
        $sql .= ' AND stock_quantity <= 0';
    } elseif ($status === 'Low Stock') {
        $sql .= ' AND stock_quantity > 0 AND stock_quantity <= minimum_stock';
    } elseif ($status === 'In Stock') {
        $sql .= ' AND stock_quantity > minimum_stock';
    }

    $sql .= ' ORDER BY updated_at DESC, id DESC';

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    $rows = $stmt->fetchAll();

    foreach ($rows as &$r) {
        $r['stock_status'] = computeStockStatus((int)$r['stock_quantity'], (int)$r['minimum_stock']);
    }
    unset($r);

    return $rows;
}

function fetchAllProductsSimple(): array
{
    $stmt = getDB()->query('SELECT id, product_name, category, brand, stock_quantity, minimum_stock FROM products ORDER BY product_name ASC');
    return $stmt->fetchAll();
}

function fetchStockMovements(string $typeFilter = '', string $search = ''): array
{
    $pdo = getDB();
    $sql = 'SELECT
                sm.id,
                sm.product_id,
                sm.user_id,
                sm.movement_type,
                sm.quantity,
                sm.remarks,
                sm.created_at,
                p.product_name,
                p.category,
                p.stock_quantity AS current_stock,
                COALESCE(u.full_name, u.username, "System") AS actor_name
            FROM stock_movements sm
            INNER JOIN products p ON p.id = sm.product_id
            LEFT JOIN users u ON u.id = sm.user_id
            WHERE 1=1';
    $params = [];

    if (in_array($typeFilter, ['Stock In', 'Stock Out'], true)) {
        $sql .= ' AND sm.movement_type = :mtype';
        $params[':mtype'] = $typeFilter;
    }

    if ($search !== '') {
        $sql .= ' AND (p.product_name LIKE :q_prod OR sm.remarks LIKE :q_rem OR u.full_name LIKE :q_user)';
        $like = '%' . $search . '%';
        $params[':q_prod'] = $like;
        $params[':q_rem']  = $like;
        $params[':q_user'] = $like;
    }

    $sql .= ' ORDER BY sm.created_at DESC, sm.id DESC LIMIT 100';

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function fetchAllUsers(): array
{
    $stmt = getDB()->query('SELECT id, full_name, username, role, created_at FROM users ORDER BY id ASC');
    return $stmt->fetchAll();
}

$flash = pullFlash();
$user  = currentUser();

$filterSearch   = trim((string)($_GET['q'] ?? ''));
$filterCategory = trim((string)($_GET['category'] ?? ''));
$filterStatus   = trim((string)($_GET['status'] ?? ''));
$filterMovement = trim((string)($_GET['movement_type'] ?? ''));

$dashboardData = null;
$productsList  = [];
$simpleProducts = [];
$movementsList = [];
$usersList     = [];

if ($requestedPage === 'dashboard') {
    $dashboardData = fetchDashboardMetrics();
} elseif ($requestedPage === 'inventory' || $requestedPage === 'reports') {
    $productsList = fetchFilteredProducts($filterSearch, $filterCategory, $filterStatus);
} elseif ($requestedPage === 'stock') {
    $simpleProducts = fetchAllProductsSimple();
    $movementsList  = fetchStockMovements($filterMovement, $filterSearch);
} elseif ($requestedPage === 'users' && isAdmin()) {
    $usersList = fetchAllUsers();
}

$pageTitles = [
    'login'     => 'Sign In - Kampung Court Badminton Inventory',
    'dashboard' => 'Dashboard',
    'inventory' => 'Inventory Management',
    'stock'     => 'Stock Movement',
    'reports'   => 'Inventory Reports',
    'users'     => 'User Management',
];
$currentPageTitle = $pageTitles[$requestedPage] ?? 'Badminton Inventory';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= e($currentPageTitle) ?> | Badminton Inventory Management System</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fredoka:wght@500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">

    <!-- ========================================================================
         20. CSS - PLAYFUL MALAYSIAN VILLAGE & BADMINTON COURT THEME
         ======================================================================== -->
    <style>
        :root {
            --sky-blue: #87CEEB;
            --light-blue: #EAF7FF;
            --soft-sky-tint: #D7F0FD;
            --sun-yellow: #FFD93D;
            --warm-yellow: #FFF3B0;
            --meadow-green: #6BCB77;
            --deep-green: #389E52;
            --coral-accent: #FF7B54;
            --card-white: #FFFFFF;
            --ink-dark: #2C3E50;
            --ink-muted: #5C7085;
            --border-soft: #D6EAF8;
            --shadow-card: 0 10px 28px rgba(44, 62, 80, 0.07);
            --shadow-hover: 0 14px 34px rgba(44, 62, 80, 0.12);
            --radius-lg: 20px;
            --radius-md: 14px;
            --radius-sm: 10px;
            --sidebar-w: 265px;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif;
            color: var(--ink-dark);
            background:
                radial-gradient(circle at 12% 8%, rgba(255, 217, 61, 0.28) 0%, transparent 26%),
                radial-gradient(circle at 88% 12%, rgba(135, 206, 235, 0.38) 0%, transparent 32%),
                linear-gradient(180deg, var(--light-blue) 0%, #F5FBFF 55%, #EBF8EE 100%);
            min-height: 100vh;
            overflow-x: hidden;
        }

        h1, h2, h3, h4, h5, .brand-font {
            font-family: 'Fredoka', 'Plus Jakarta Sans', sans-serif;
            letter-spacing: 0.2px;
        }

        /* Decorative village & shuttlecock backdrop accents */
        .village-bg-shape {
            position: fixed;
            pointer-events: none;
            z-index: 0;
            opacity: 0.35;
        }
        .village-sun {
            top: -36px;
            right: -36px;
            width: 150px;
            height: 150px;
            border-radius: 50%;
            background: radial-gradient(circle, var(--sun-yellow) 35%, rgba(255, 217, 61, 0) 72%);
            animation: floatSlow 7s ease-in-out infinite;
        }
        .village-hill {
            bottom: -45px;
            right: -40px;
            width: 340px;
            height: 140px;
            border-radius: 100% 100% 0 0 / 100% 100% 0 0;
            background: linear-gradient(180deg, rgba(107, 203, 119, 0.28), rgba(56, 158, 82, 0.14));
        }

        @keyframes floatSlow {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(8px); }
        }

        /* Login Screen */
        .login-shell {
            position: relative;
            z-index: 1;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
        }

        .login-card {
            width: 100%;
            max-width: 440px;
            background: var(--card-white);
            border: 3px solid var(--sky-blue);
            border-radius: 26px;
            box-shadow: 0 18px 42px rgba(44, 62, 80, 0.12);
            overflow: hidden;
        }

        .login-banner {
            background: linear-gradient(135deg, var(--sky-blue) 0%, #63BBE3 60%, var(--meadow-green) 140%);
            padding: 28px 28px 24px;
            color: #fff;
            position: relative;
            border-bottom: 4px solid var(--sun-yellow);
        }

        .mascot-badge {
            width: 58px;
            height: 58px;
            border-radius: 18px;
            background: var(--sun-yellow);
            color: var(--ink-dark);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 1.65rem;
            box-shadow: 0 6px 0 rgba(44, 62, 80, 0.16);
            border: 2px solid #fff;
        }

        /* App Shell Layout */
        .app-wrapper {
            position: relative;
            z-index: 1;
            display: flex;
            min-height: 100vh;
        }

        /* 13. SIDEBAR */
        .sidebar {
            width: var(--sidebar-w);
            flex-shrink: 0;
            background: var(--card-white);
            border-right: 3px solid var(--soft-sky-tint);
            box-shadow: 6px 0 24px rgba(44, 62, 80, 0.05);
            display: flex;
            flex-direction: column;
            position: sticky;
            top: 0;
            height: 100vh;
            z-index: 1030;
            transition: transform 0.25s ease;
        }

        .sidebar-brand {
            padding: 20px 18px;
            background: linear-gradient(135deg, var(--light-blue), #fff);
            border-bottom: 2px dashed var(--sky-blue);
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .sidebar-logo {
            width: 46px;
            height: 46px;
            border-radius: 14px;
            background: var(--sun-yellow);
            color: var(--ink-dark);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
            border: 2px solid var(--ink-dark);
            box-shadow: 0 3px 0 var(--ink-dark);
            flex-shrink: 0;
        }

        .nav-menu {
            padding: 16px 14px;
            flex: 1;
            overflow-y: auto;
        }

        .nav-section-label {
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            color: var(--ink-muted);
            padding: 8px 12px 6px;
        }

        .side-link {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 11px 14px;
            margin-bottom: 6px;
            border-radius: var(--radius-md);
            color: var(--ink-dark);
            text-decoration: none;
            font-weight: 600;
            font-size: 0.94rem;
            transition: all 0.18s ease;
            border: 2px solid transparent;
        }

        .side-link i {
            width: 22px;
            text-align: center;
            font-size: 1.02rem;
            color: var(--deep-green);
        }

        .side-link:hover {
            background: var(--light-blue);
            border-color: var(--sky-blue);
            transform: translateX(3px);
        }

        .side-link.active {
            background: linear-gradient(90deg, var(--sun-yellow) 0%, #FFE875 100%);
            color: var(--ink-dark);
            border-color: var(--ink-dark);
            box-shadow: 0 3px 0 var(--ink-dark);
        }

        .side-link.active i {
            color: var(--ink-dark);
        }

        .sidebar-footer {
            padding: 14px;
            border-top: 2px solid var(--light-blue);
            background: #FAFDFF;
        }

        /* Main Content Area */
        .main-panel {
            flex: 1;
            min-width: 0;
            display: flex;
            flex-direction: column;
        }

        /* Top Bar */
        .topbar {
            background: rgba(255, 255, 255, 0.92);
            backdrop-filter: blur(8px);
            border-bottom: 2px solid var(--border-soft);
            padding: 14px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            position: sticky;
            top: 0;
            z-index: 1020;
        }

        .content-container {
            padding: 24px;
            max-width: 1440px;
            width: 100%;
            margin: 0 auto;
        }

        /* Friendly Cards & Badges */
        .kampung-card {
            background: var(--card-white);
            border: 2px solid var(--border-soft);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-card);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .kampung-card:hover {
            box-shadow: var(--shadow-hover);
        }

        .stat-tile {
            background: var(--card-white);
            border-radius: var(--radius-lg);
            padding: 20px;
            border: 2px solid var(--border-soft);
            box-shadow: var(--shadow-card);
            position: relative;
            overflow: hidden;
            height: 100%;
            transition: transform 0.2s ease;
        }

        .stat-tile:hover {
            transform: translateY(-3px);
        }

        .stat-icon {
            width: 50px;
            height: 50px;
            border-radius: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.3rem;
            border: 2px solid rgba(44, 62, 80, 0.12);
        }

        .role-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .role-pill.admin {
            background: var(--sun-yellow);
            color: var(--ink-dark);
            border: 1.5px solid var(--ink-dark);
        }

        .role-pill.user {
            background: #DCFCE7;
            color: #166534;
            border: 1.5px solid #86EFAC;
        }

        .btn-kampung-primary {
            background: var(--meadow-green);
            color: #fff;
            font-weight: 700;
            border: 2px solid var(--deep-green);
            border-radius: var(--radius-sm);
            box-shadow: 0 3px 0 var(--deep-green);
            transition: all 0.15s ease;
        }

        .btn-kampung-primary:hover {
            background: #58B964;
            color: #fff;
            transform: translateY(-1px);
        }

        .btn-kampung-sun {
            background: var(--sun-yellow);
            color: var(--ink-dark);
            font-weight: 700;
            border: 2px solid var(--ink-dark);
            border-radius: var(--radius-sm);
            box-shadow: 0 3px 0 var(--ink-dark);
        }

        .btn-kampung-sun:hover {
            background: #FFCF1A;
            color: var(--ink-dark);
        }

        .table thead th {
            background: var(--light-blue);
            color: var(--ink-dark);
            font-weight: 700;
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.4px;
            border-bottom: 2px solid var(--sky-blue);
            white-space: nowrap;
        }

        .table tbody tr {
            vertical-align: middle;
        }

        .product-thumb {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            object-fit: cover;
            border: 2px solid var(--border-soft);
            background: var(--light-blue);
        }

        .product-thumb-placeholder {
            width: 48px;
            height: 48px;
            border-radius: 12px;
            background: var(--light-blue);
            border: 2px solid var(--border-soft);
            display: inline-flex;
            align-items: center;
            justify-content: center;
            color: var(--deep-green);
            font-size: 1.15rem;
        }

        .chart-box {
            position: relative;
            height: 300px;
            width: 100%;
        }

        /* Mobile Drawer */
        .sidebar-backdrop {
            display: none;
            position: fixed;
            inset: 0;
            background: rgba(44, 62, 80, 0.45);
            z-index: 1025;
        }

        @media (max-width: 991.98px) {
            .sidebar {
                position: fixed;
                left: 0;
                top: 0;
                transform: translateX(-100%);
            }
            .sidebar.show {
                transform: translateX(0);
            }
            .sidebar-backdrop.show {
                display: block;
            }
            .content-container {
                padding: 16px;
            }
        }

        /* Print Styles for Reports */
        @media print {
            .sidebar,
            .sidebar-backdrop,
            .topbar,
            .no-print,
            .village-bg-shape,
            .alert {
                display: none !important;
            }
            body {
                background: #fff !important;
                color: #000 !important;
            }
            .app-wrapper,
            .main-panel,
            .content-container {
                display: block !important;
                padding: 0 !important;
                margin: 0 !important;
                max-width: 100% !important;
            }
            .kampung-card {
                box-shadow: none !important;
                border: 1px solid #ccc !important;
            }
        }
    </style>
</head>
<body>
<div class="village-bg-shape village-sun"></div>
<div class="village-bg-shape village-hill"></div>

<?php if ($requestedPage === 'login'): ?>
    <!-- ========================================================================
         LOGIN VIEW
         ======================================================================== -->
    <div class="login-shell">
        <div class="login-card">
            <div class="login-banner">
                <div class="d-flex align-items-center gap-3">
                    <div class="mascot-badge">
                        <i class="fa-solid fa-shuttlecock"></i>
                    </div>
                    <div>
                        <span class="badge bg-white text-dark fw-bold mb-1 rounded-pill px-3">
                            <i class="fa-solid fa-sun text-warning me-1"></i> Kampung Court Edition
                        </span>
                        <h1 class="h4 mb-0 fw-bold">Badminton Inventory</h1>
                        <small class="opacity-90">Rackets • Strings • Shuttlecocks</small>
                    </div>
                </div>
            </div>

            <div class="p-4 p-sm-4">
                <?php if ($flash): ?>
                    <div class="alert alert-<?= e($flash['type']) ?> alert-dismissible fade show rounded-3" role="alert">
                        <?= e($flash['message']) ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>

                <p class="text-muted small mb-3">
                    Sign in with your staff or administrator account. Public self-registration is disabled; admins manage user accounts.
                </p>

                <form method="post" action="index.php?page=login" novalidate>
                    <?= csrfInput() ?>
                    <input type="hidden" name="action" value="login">

                    <div class="mb-3">
                        <label for="loginUsername" class="form-label fw-semibold">Username</label>
                        <div class="input-group">
                            <span class="input-group-text bg-light"><i class="fa-solid fa-user text-muted"></i></span>
                            <input type="text" class="form-control" id="loginUsername" name="username" placeholder="Enter username" required autofocus>
                        </div>
                    </div>

                    <div class="mb-4">
                        <label for="loginPassword" class="form-label fw-semibold">Password</label>
                        <div class="input-group">
                            <span class="input-group-text bg-light"><i class="fa-solid fa-lock text-muted"></i></span>
                            <input type="password" class="form-control" id="loginPassword" name="password" placeholder="Enter password" required>
                        </div>
                    </div>

                    <button type="submit" class="btn btn-kampung-primary w-100 py-2">
                        <i class="fa-solid fa-right-to-bracket me-2"></i>Sign In to Court
                    </button>
                </form>

                <div class="mt-4 p-3 rounded-3" style="background: var(--light-blue); border: 1.5px dashed var(--sky-blue);">
                    <div class="small fw-bold mb-1"><i class="fa-solid fa-circle-info text-primary me-1"></i>Initial Setup Reminder</div>
                    <div class="small text-muted">
                        Run the SQL setup script in phpMyAdmin to create <code>badminton_inventory</code> and seed your initial <code>admin</code> account.
                    </div>
                </div>
            </div>
        </div>
    </div>

<?php else: ?>
    <!-- ========================================================================
         12. HTML LAYOUT & 13. SIDEBAR
         ======================================================================== -->
    <div class="sidebar-backdrop" id="sidebarBackdrop" onclick="toggleSidebar(false)"></div>

    <div class="app-wrapper">
        <aside class="sidebar" id="mainSidebar">
            <div class="sidebar-brand">
                <div class="sidebar-logo">
                    <i class="fa-solid fa-feather-pointed"></i>
                </div>
                <div>
                    <div class="brand-font fw-bold lh-1 fs-6">TangkisStock</div>
                    <small class="text-muted fw-medium">Badminton Shop POS</small>
                </div>
            </div>

            <nav class="nav-menu">
                <div class="nav-section-label">Main Menu</div>

                <a href="index.php?page=dashboard" class="side-link <?= $requestedPage === 'dashboard' ? 'active' : '' ?>">
                    <i class="fa-solid fa-gauge-high"></i>
                    <span>Dashboard</span>
                </a>

                <a href="index.php?page=inventory" class="side-link <?= $requestedPage === 'inventory' ? 'active' : '' ?>">
                    <i class="fa-solid fa-boxes-stacked"></i>
                    <span>Inventory</span>
                </a>

                <a href="index.php?page=stock" class="side-link <?= $requestedPage === 'stock' ? 'active' : '' ?>">
                    <i class="fa-solid fa-arrows-left-right"></i>
                    <span>Stock Movement</span>
                </a>

                <a href="index.php?page=reports" class="side-link <?= $requestedPage === 'reports' ? 'active' : '' ?>">
                    <i class="fa-solid fa-file-lines"></i>
                    <span>Reports</span>
                </a>

                <?php if (isAdmin()): ?>
                    <div class="nav-section-label mt-3">Administration</div>
                    <a href="index.php?page=users" class="side-link <?= $requestedPage === 'users' ? 'active' : '' ?>">
                        <i class="fa-solid fa-users-gear"></i>
                        <span>User Management</span>
                    </a>
                <?php endif; ?>
            </nav>

            <div class="sidebar-footer">
                <div class="mb-2 px-2">
                    <div class="fw-bold small text-truncate"><?= e($user['full_name'] ?? '') ?></div>
                    <div class="d-flex align-items-center justify-content-between mt-1">
                        <span class="text-muted small">@<?= e($user['username'] ?? '') ?></span>
                        <span class="role-pill <?= e($user['role'] ?? 'user') ?>">
                            <?= e(strtoupper((string)($user['role'] ?? 'user'))) ?>
                        </span>
                    </div>
                </div>
                <form method="post" action="index.php?page=dashboard" class="m-0">
                    <?= csrfInput() ?>
                    <input type="hidden" name="action" value="logout">
                    <button type="submit" class="btn btn-outline-danger btn-sm w-100 fw-semibold rounded-3">
                        <i class="fa-solid fa-right-from-bracket me-1"></i>Logout
                    </button>
                </form>
            </div>
        </aside>

        <div class="main-panel">
            <!-- Top Navigation Bar -->
            <header class="topbar">
                <div class="d-flex align-items-center gap-3">
                    <button type="button" class="btn btn-kampung-sun d-lg-none py-1 px-2" onclick="toggleSidebar(true)" aria-label="Open menu">
                        <i class="fa-solid fa-bars"></i>
                    </button>
                    <div>
                        <h2 class="h5 mb-0 fw-bold"><?= e($currentPageTitle) ?></h2>
                        <small class="text-muted d-none d-sm-inline">Badminton Inventory Management System • Rackets, Strings &amp; Shuttlecocks</small>
                    </div>
                </div>

                <div class="d-flex align-items-center gap-2 no-print">
                    <?php if ($requestedPage === 'inventory'): ?>
                        <button type="button" class="btn btn-kampung-primary btn-sm px-3 py-2" data-bs-toggle="modal" data-bs-target="#addProductModal">
                            <i class="fa-solid fa-plus me-1"></i>Add Product
                        </button>
                    <?php endif; ?>
                    <span class="badge rounded-pill text-dark px-3 py-2 d-none d-md-inline-flex align-items-center gap-1" style="background: var(--warm-yellow); border: 1.5px solid var(--sun-yellow);">
                        <i class="fa-solid fa-circle-check text-success"></i>
                        <span><?= e(ucfirst((string)($user['role'] ?? 'user'))) ?> Session</span>
                    </span>
                </div>
            </header>

            <main class="content-container">
                <?php if ($flash): ?>
                    <div class="alert alert-<?= e($flash['type']) ?> alert-dismissible fade show rounded-3 shadow-sm mb-4" role="alert">
                        <i class="fa-solid fa-bell me-2"></i><?= e($flash['message']) ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                    </div>
                <?php endif; ?>

                <?php if ($requestedPage === 'dashboard'): ?>
                    <!-- ================================================================
                         14. DASHBOARD
                         ================================================================ -->
                    <?php
                        $m = $dashboardData;
                        $catMap = $m['categories_map'];
                    ?>
                    <div class="row g-3 g-md-4 mb-4">
                        <div class="col-12 col-sm-6 col-xl-4">
                            <div class="stat-tile">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <div class="text-muted small fw-semibold">Total Products</div>
                                        <div class="h2 fw-bold mt-1 mb-0"><?= e((string)$m['total_products']) ?></div>
                                    </div>
                                    <div class="stat-icon" style="background: var(--light-blue); color: #0284C7;">
                                        <i class="fa-solid fa-boxes-stacked"></i>
                                    </div>
                                </div>
                                <div class="small text-muted mt-2">Active SKUs across store</div>
                            </div>
                        </div>

                        <div class="col-12 col-sm-6 col-xl-4">
                            <div class="stat-tile">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <div class="text-muted small fw-semibold">Total Stock Units</div>
                                        <div class="h2 fw-bold mt-1 mb-0"><?= e(number_format($m['total_units'])) ?></div>
                                    </div>
                                    <div class="stat-icon" style="background: #DCFCE7; color: var(--deep-green);">
                                        <i class="fa-solid fa-cubes"></i>
                                    </div>
                                </div>
                                <div class="small text-muted mt-2">Combined units on hand</div>
                            </div>
                        </div>

                        <div class="col-12 col-sm-6 col-xl-4">
                            <div class="stat-tile">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <div class="text-muted small fw-semibold">Total Categories</div>
                                        <div class="h2 fw-bold mt-1 mb-0"><?= e((string)$m['total_categories']) ?></div>
                                    </div>
                                    <div class="stat-icon" style="background: var(--warm-yellow); color: #B45309;">
                                        <i class="fa-solid fa-tags"></i>
                                    </div>
                                </div>
                                <div class="small text-muted mt-2">Racket, String, Shuttlecock</div>
                            </div>
                        </div>

                        <div class="col-12 col-sm-6 col-xl-4">
                            <div class="stat-tile">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <div class="text-muted small fw-semibold">Low Stock Products</div>
                                        <div class="h2 fw-bold mt-1 mb-0 text-warning-emphasis"><?= e((string)$m['low_stock']) ?></div>
                                    </div>
                                    <div class="stat-icon" style="background: #FEF9C3; color: #CA8A04;">
                                        <i class="fa-solid fa-triangle-exclamation"></i>
                                    </div>
                                </div>
                                <div class="small text-muted mt-2">At or below minimum alert</div>
                            </div>
                        </div>

                        <div class="col-12 col-sm-6 col-xl-4">
                            <div class="stat-tile">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <div class="text-muted small fw-semibold">Out of Stock Products</div>
                                        <div class="h2 fw-bold mt-1 mb-0 text-danger"><?= e((string)$m['out_of_stock']) ?></div>
                                    </div>
                                    <div class="stat-icon" style="background: #FEE2E2; color: #DC2626;">
                                        <i class="fa-solid fa-ban"></i>
                                    </div>
                                </div>
                                <div class="small text-muted mt-2">Zero units available</div>
                            </div>
                        </div>

                        <div class="col-12 col-sm-6 col-xl-4">
                            <div class="stat-tile">
                                <div class="d-flex justify-content-between align-items-start">
                                    <div>
                                        <div class="text-muted small fw-semibold">Total Inventory Value</div>
                                        <div class="h2 fw-bold mt-1 mb-0 text-success">RM <?= e(number_format($m['total_inventory_value'], 2)) ?></div>
                                    </div>
                                    <div class="stat-icon" style="background: #E0F2FE; color: #0369A1;">
                                        <i class="fa-solid fa-sack-dollar"></i>
                                    </div>
                                </div>
                                <div class="small text-muted mt-2">Valued at purchase price</div>
                            </div>
                        </div>
                    </div>

                    <!-- Charts Row -->
                    <div class="row g-4 mb-4">
                        <div class="col-12 col-lg-6">
                            <div class="kampung-card p-4 h-100">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <div>
                                        <h3 class="h6 fw-bold mb-0"><i class="fa-solid fa-chart-pie text-primary me-2"></i>Stock by Category</h3>
                                        <small class="text-muted">Total units distributed across categories</small>
                                    </div>
                                </div>
                                <div class="chart-box">
                                    <canvas id="stockByCategoryChart"></canvas>
                                </div>
                            </div>
                        </div>

                        <div class="col-12 col-lg-6">
                            <div class="kampung-card p-4 h-100">
                                <div class="d-flex justify-content-between align-items-center mb-3">
                                    <div>
                                        <h3 class="h6 fw-bold mb-0"><i class="fa-solid fa-chart-column text-success me-2"></i>Inventory Stock Levels</h3>
                                        <small class="text-muted">Current stock vs. minimum stock alert</small>
                                    </div>
                                </div>
                                <div class="chart-box">
                                    <canvas id="inventoryLevelsChart"></canvas>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- Recent Stock Movements -->
                    <div class="kampung-card p-4">
                        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
                            <div>
                                <h3 class="h6 fw-bold mb-0"><i class="fa-solid fa-clock-rotate-left text-warning me-2"></i>Recent Stock Movements</h3>
                                <small class="text-muted">Latest Stock In and Stock Out transactions</small>
                            </div>
                            <a href="index.php?page=stock" class="btn btn-sm btn-kampung-sun px-3">
                                <i class="fa-solid fa-arrows-left-right me-1"></i>Record Movement
                            </a>
                        </div>

                        <div class="table-responsive">
                            <table class="table table-hover align-middle mb-0">
                                <thead>
                                    <tr>
                                        <th>Date &amp; Time</th>
                                        <th>Product</th>
                                        <th>Category</th>
                                        <th>Type</th>
                                        <th>Qty</th>
                                        <th>Remarks</th>
                                        <th>By</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($m['recent_movements'])): ?>
                                        <tr>
                                            <td colspan="7" class="text-center text-muted py-4">No stock movements recorded yet.</td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($m['recent_movements'] as $mov): ?>
                                            <?php $isIn = $mov['movement_type'] === 'Stock In'; ?>
                                            <tr>
                                                <td class="small text-muted text-nowrap"><?= e($mov['created_at']) ?></td>
                                                <td class="fw-semibold"><?= e($mov['product_name']) ?></td>
                                                <td><span class="badge bg-light text-dark border"><?= e($mov['category']) ?></span></td>
                                                <td>
                                                    <span class="badge <?= $isIn ? 'bg-success-subtle text-success border border-success-subtle' : 'bg-danger-subtle text-danger border border-danger-subtle' ?>">
                                                        <i class="fa-solid <?= $isIn ? 'fa-arrow-down' : 'fa-arrow-up' ?> me-1"></i><?= e($mov['movement_type']) ?>
                                                    </span>
                                                </td>
                                                <td class="fw-bold <?= $isIn ? 'text-success' : 'text-danger' ?>">
                                                    <?= $isIn ? '+' : '-' ?><?= e((string)$mov['quantity']) ?>
                                                </td>
                                                <td class="small"><?= e($mov['remarks'] ?: '—') ?></td>
                                                <td class="small text-nowrap"><?= e($mov['actor_name']) ?></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>

                <?php elseif ($requestedPage === 'inventory'): ?>
                    <!-- ================================================================
                         15. INVENTORY PAGE
                         ================================================================ -->
                    <div class="kampung-card p-3 p-md-4 mb-4">
                        <form method="get" action="index.php" class="row g-3 align-items-end">
                            <input type="hidden" name="page" value="inventory">

                            <div class="col-12 col-md-5">
                                <label for="invSearch" class="form-label small fw-bold mb-1">Search Products</label>
                                <div class="input-group">
                                    <span class="input-group-text bg-white"><i class="fa-solid fa-magnifying-glass text-muted"></i></span>
                                    <input type="text" class="form-control" id="invSearch" name="q" value="<?= e($filterSearch) ?>" placeholder="Search name, brand, or notes...">
                                </div>
                            </div>

                            <div class="col-12 col-sm-6 col-md-3">
                                <label for="invCategory" class="form-label small fw-bold mb-1">Category</label>
                                <select class="form-select" id="invCategory" name="category">
                                    <option value="">All Categories</option>
                                    <?php foreach (['Racket', 'String', 'Shuttlecock'] as $cat): ?>
                                        <option value="<?= e($cat) ?>" <?= $filterCategory === $cat ? 'selected' : '' ?>><?= e($cat) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="col-12 col-sm-6 col-md-2">
                                <label for="invStatus" class="form-label small fw-bold mb-1">Stock Status</label>
                                <select class="form-select" id="invStatus" name="status">
                                    <option value="">All Status</option>
                                    <?php foreach (['In Stock', 'Low Stock', 'Out of Stock'] as $st): ?>
                                        <option value="<?= e($st) ?>" <?= $filterStatus === $st ? 'selected' : '' ?>><?= e($st) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="col-12 col-md-2 d-flex gap-2">
                                <button type="submit" class="btn btn-kampung-sun flex-grow-1">
                                    <i class="fa-solid fa-filter me-1"></i>Filter
                                </button>
                                <a href="index.php?page=inventory" class="btn btn-outline-secondary" title="Reset filters">
                                    <i class="fa-solid fa-rotate-left"></i>
                                </a>
                            </div>
                        </form>
                    </div>

                    <div class="kampung-card p-3 p-md-4">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <div>
                                <h3 class="h6 fw-bold mb-0">Badminton Product Catalog (<?= e((string)count($productsList)) ?>)</h3>
                                <small class="text-muted">Manage rackets, strings, and shuttlecocks</small>
                            </div>
                            <button type="button" class="btn btn-kampung-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addProductModal">
                                <i class="fa-solid fa-plus me-1"></i>New Product
                            </button>
                        </div>

                        <div class="table-responsive">
                            <table class="table table-hover align-middle mb-0">
                                <thead>
                                    <tr>
                                        <th>Item</th>
                                        <th>Category</th>
                                        <th>Brand</th>
                                        <th>Purchase (RM)</th>
                                        <th>Selling (RM)</th>
                                        <th>Stock</th>
                                        <th>Min Alert</th>
                                        <th>Status</th>
                                        <th class="text-end">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($productsList)): ?>
                                        <tr>
                                            <td colspan="9" class="text-center text-muted py-5">
                                                <i class="fa-solid fa-box-open fa-2x mb-2 d-block opacity-50"></i>
                                                No badminton products match your current filter.
                                            </td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($productsList as $p): ?>
                                            <?php
                                                $statusLabel = (string)$p['stock_status'];
                                                $badgeClass  = stockStatusBadgeClass($statusLabel);
                                                $productJson = htmlspecialchars(json_encode($p, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP), ENT_QUOTES, 'UTF-8');
                                            ?>
                                            <tr>
                                                <td>
                                                    <div class="d-flex align-items-center gap-3">
                                                        <?php if (!empty($p['product_image'])): ?>
                                                            <img src="<?= e($p['product_image']) ?>" alt="<?= e($p['product_name']) ?>" class="product-thumb" onerror="this.style.display='none';">
                                                        <?php else: ?>
                                                            <div class="product-thumb-placeholder">
                                                                <i class="fa-solid <?= $p['category'] === 'Racket' ? 'fa-table-tennis-paddle-ball' : ($p['category'] === 'String' ? 'fa-grip-lines' : 'fa-feather') ?>"></i>
                                                            </div>
                                                        <?php endif; ?>
                                                        <div>
                                                            <div class="fw-bold"><?= e($p['product_name']) ?></div>
                                                            <?php if (!empty($p['description'])): ?>
                                                                <div class="small text-muted text-truncate" style="max-width: 220px;"><?= e($p['description']) ?></div>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                </td>
                                                <td><span class="badge bg-light text-dark border"><?= e($p['category']) ?></span></td>
                                                <td class="small fw-medium"><?= e($p['brand'] ?: '—') ?></td>
                                                <td class="small">RM <?= e(number_format((float)$p['purchase_price'], 2)) ?></td>
                                                <td class="small fw-bold text-success">RM <?= e(number_format((float)$p['selling_price'], 2)) ?></td>
                                                <td class="fw-bold"><?= e((string)$p['stock_quantity']) ?></td>
                                                <td class="small text-muted"><?= e((string)$p['minimum_stock']) ?></td>
                                                <td><span class="badge rounded-pill px-2 py-1 <?= e($badgeClass) ?>"><?= e($statusLabel) ?></span></td>
                                                <td class="text-end text-nowrap">
                                                    <button type="button" class="btn btn-sm btn-outline-primary" title="View Details" onclick='openViewProductModal(<?= $productJson ?>)'>
                                                        <i class="fa-solid fa-eye"></i>
                                                    </button>
                                                    <button type="button" class="btn btn-sm btn-outline-success" title="Adjust Stock" onclick='openQuickStockModal(<?= $productJson ?>)'>
                                                        <i class="fa-solid fa-arrows-left-right"></i>
                                                    </button>
                                                    <button type="button" class="btn btn-sm btn-outline-warning text-dark" title="Edit Product" onclick='openEditProductModal(<?= $productJson ?>)'>
                                                        <i class="fa-solid fa-pen"></i>
                                                    </button>
                                                    <?php if (isAdmin()): ?>
                                                        <button type="button" class="btn btn-sm btn-outline-danger" title="Delete Product" onclick="openDeleteProductModal(<?= (int)$p['id'] ?>, '<?= e(addslashes($p['product_name'])) ?>')">
                                                            <i class="fa-solid fa-trash"></i>
                                                        </button>
                                                    <?php endif; ?>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>

                <?php elseif ($requestedPage === 'stock'): ?>
                    <!-- ================================================================
                         16. STOCK MOVEMENT PAGE
                         ================================================================ -->
                    <div class="row g-4">
                        <div class="col-12 col-lg-4">
                            <div class="kampung-card p-4">
                                <h3 class="h6 fw-bold mb-1"><i class="fa-solid fa-dolly text-success me-2"></i>Record Stock Movement</h3>
                                <p class="text-muted small mb-3">Stock In adds units; Stock Out deducts available stock safely inside a transaction.</p>

                                <form method="post" action="index.php?page=stock" novalidate>
                                    <?= csrfInput() ?>
                                    <input type="hidden" name="action" value="record_movement">
                                    <input type="hidden" name="return_page" value="stock">

                                    <div class="mb-3">
                                        <label for="movProduct" class="form-label small fw-bold">Product <span class="text-danger">*</span></label>
                                        <select class="form-select" id="movProduct" name="product_id" required>
                                            <option value="">-- Choose Badminton Item --</option>
                                            <?php foreach ($simpleProducts as $sp): ?>
                                                <option value="<?= (int)$sp['id'] ?>">
                                                    <?= e($sp['product_name']) ?> (<?= e($sp['category']) ?> • Stock: <?= (int)$sp['stock_quantity'] ?>)
                                                </option>
                                            <?php endforeach; ?>
                                        </select>
                                    </div>

                                    <div class="mb-3">
                                        <label for="movType" class="form-label small fw-bold">Movement Type <span class="text-danger">*</span></label>
                                        <select class="form-select" id="movType" name="movement_type" required>
                                            <option value="Stock In">Stock In (Receive / Restock)</option>
                                            <option value="Stock Out">Stock Out (Sale / Issue / Damage)</option>
                                        </select>
                                    </div>

                                    <div class="mb-3">
                                        <label for="movQty" class="form-label small fw-bold">Quantity <span class="text-danger">*</span></label>
                                        <input type="number" class="form-control" id="movQty" name="quantity" min="1" step="1" placeholder="e.g. 10" required>
                                    </div>

                                    <div class="mb-4">
                                        <label for="movRemarks" class="form-label small fw-bold">Remarks</label>
                                        <input type="text" class="form-control" id="movRemarks" name="remarks" maxlength="255" placeholder="e.g. Supplier delivery or walk-in sale">
                                    </div>

                                    <button type="submit" class="btn btn-kampung-primary w-100 py-2">
                                        <i class="fa-solid fa-check-circle me-1"></i>Submit Stock Movement
                                    </button>
                                </form>
                            </div>
                        </div>

                        <div class="col-12 col-lg-8">
                            <div class="kampung-card p-4">
                                <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
                                    <div>
                                        <h3 class="h6 fw-bold mb-0"><i class="fa-solid fa-list-check text-primary me-2"></i>Stock Movement History</h3>
                                        <small class="text-muted">Audited log of all inventory adjustments</small>
                                    </div>
                                    <form method="get" action="index.php" class="d-flex flex-wrap gap-2">
                                        <input type="hidden" name="page" value="stock">
                                        <select name="movement_type" class="form-select form-select-sm" style="width: auto;">
                                            <option value="">All Types</option>
                                            <option value="Stock In" <?= $filterMovement === 'Stock In' ? 'selected' : '' ?>>Stock In</option>
                                            <option value="Stock Out" <?= $filterMovement === 'Stock Out' ? 'selected' : '' ?>>Stock Out</option>
                                        </select>
                                        <input type="text" name="q" value="<?= e($filterSearch) ?>" class="form-control form-control-sm" style="width: 170px;" placeholder="Search product/remarks">
                                        <button type="submit" class="btn btn-sm btn-kampung-sun">Filter</button>
                                    </form>
                                </div>

                                <div class="table-responsive">
                                    <table class="table table-hover align-middle mb-0">
                                        <thead>
                                            <tr>
                                                <th>Timestamp</th>
                                                <th>Product</th>
                                                <th>Type</th>
                                                <th>Qty</th>
                                                <th>Current Stock</th>
                                                <th>Remarks</th>
                                                <th>Staff</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <?php if (empty($movementsList)): ?>
                                                <tr>
                                                    <td colspan="7" class="text-center text-muted py-4">No stock movement records found.</td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($movementsList as $mv): ?>
                                                    <?php $isIn = $mv['movement_type'] === 'Stock In'; ?>
                                                    <tr>
                                                        <td class="small text-muted text-nowrap"><?= e($mv['created_at']) ?></td>
                                                        <td>
                                                            <div class="fw-semibold"><?= e($mv['product_name']) ?></div>
                                                            <small class="text-muted"><?= e($mv['category']) ?></small>
                                                        </td>
                                                        <td>
                                                            <span class="badge <?= $isIn ? 'bg-success-subtle text-success border border-success-subtle' : 'bg-danger-subtle text-danger border border-danger-subtle' ?>">
                                                                <?= e($mv['movement_type']) ?>
                                                            </span>
                                                        </td>
                                                        <td class="fw-bold <?= $isIn ? 'text-success' : 'text-danger' ?>">
                                                            <?= $isIn ? '+' : '-' ?><?= e((string)$mv['quantity']) ?>
                                                        </td>
                                                        <td class="fw-bold"><?= e((string)$mv['current_stock']) ?></td>
                                                        <td class="small"><?= e($mv['remarks'] ?: '—') ?></td>
                                                        <td class="small text-nowrap"><?= e($mv['actor_name']) ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($requestedPage === 'reports'): ?>
                    <!-- ================================================================
                         17. REPORTS PAGE
                         ================================================================ -->
                    <div class="kampung-card p-3 p-md-4 mb-4 no-print">
                        <form method="get" action="index.php" class="row g-3 align-items-end">
                            <input type="hidden" name="page" value="reports">

                            <div class="col-12 col-md-4">
                                <label for="repSearch" class="form-label small fw-bold mb-1">Search Report</label>
                                <input type="text" class="form-control" id="repSearch" name="q" value="<?= e($filterSearch) ?>" placeholder="Product name or brand...">
                            </div>

                            <div class="col-12 col-sm-6 col-md-3">
                                <label for="repCategory" class="form-label small fw-bold mb-1">Category</label>
                                <select class="form-select" id="repCategory" name="category">
                                    <option value="">All Categories</option>
                                    <?php foreach (['Racket', 'String', 'Shuttlecock'] as $cat): ?>
                                        <option value="<?= e($cat) ?>" <?= $filterCategory === $cat ? 'selected' : '' ?>><?= e($cat) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="col-12 col-sm-6 col-md-3">
                                <label for="repStatus" class="form-label small fw-bold mb-1">Stock Status</label>
                                <select class="form-select" id="repStatus" name="status">
                                    <option value="">All Status</option>
                                    <?php foreach (['In Stock', 'Low Stock', 'Out of Stock'] as $st): ?>
                                        <option value="<?= e($st) ?>" <?= $filterStatus === $st ? 'selected' : '' ?>><?= e($st) ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>

                            <div class="col-12 col-md-2 d-flex gap-2">
                                <button type="submit" class="btn btn-kampung-sun flex-grow-1">Apply</button>
                                <button type="button" class="btn btn-kampung-primary" onclick="window.print()" title="Print Report">
                                    <i class="fa-solid fa-print"></i>
                                </button>
                            </div>
                        </form>
                    </div>

                    <div class="kampung-card p-4">
                        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
                            <div>
                                <h3 class="h5 fw-bold mb-0">Inventory Valuation &amp; Stock Status Report</h3>
                                <small class="text-muted">Generated on <?= e(date('Y-m-d H:i')) ?> • <?= e((string)count($productsList)) ?> item(s) listed</small>
                            </div>
                            <button type="button" class="btn btn-outline-dark btn-sm no-print" onclick="window.print()">
                                <i class="fa-solid fa-print me-1"></i>Print Report
                            </button>
                        </div>

                        <div class="table-responsive">
                            <table class="table table-bordered align-middle mb-0">
                                <thead>
                                    <tr>
                                        <th>Product Name</th>
                                        <th>Category</th>
                                        <th>Brand</th>
                                        <th class="text-end">Purchase (RM)</th>
                                        <th class="text-end">Selling (RM)</th>
                                        <th class="text-end">Current Stock</th>
                                        <th class="text-end">Min Stock</th>
                                        <th>Stock Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($productsList)): ?>
                                        <tr>
                                            <td colspan="8" class="text-center text-muted py-4">No inventory records match the selected report filters.</td>
                                        </tr>
                                    <?php else: ?>
                                        <?php foreach ($productsList as $row): ?>
                                            <?php $st = (string)$row['stock_status']; ?>
                                            <tr>
                                                <td class="fw-semibold"><?= e($row['product_name']) ?></td>
                                                <td><?= e($row['category']) ?></td>
                                                <td><?= e($row['brand'] ?: '—') ?></td>
                                                <td class="text-end"><?= e(number_format((float)$row['purchase_price'], 2)) ?></td>
                                                <td class="text-end"><?= e(number_format((float)$row['selling_price'], 2)) ?></td>
                                                <td class="text-end fw-bold"><?= e((string)$row['stock_quantity']) ?></td>
                                                <td class="text-end"><?= e((string)$row['minimum_stock']) ?></td>
                                                <td>
                                                    <span class="badge rounded-pill px-2 py-1 <?= e(stockStatusBadgeClass($st)) ?>"><?= e($st) ?></span>
                                                </td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>

                <?php elseif ($requestedPage === 'users' && isAdmin()): ?>
                    <!-- ================================================================
                         18. USER MANAGEMENT PAGE (ADMIN ONLY)
                         ================================================================ -->
                    <div class="kampung-card p-4">
                        <div class="d-flex flex-wrap justify-content-between align-items-center gap-2 mb-3">
                            <div>
                                <h3 class="h6 fw-bold mb-0"><i class="fa-solid fa-users-gear text-primary me-2"></i>Registered System Users</h3>
                                <small class="text-muted">Create accounts, update roles, and manage staff access. You cannot delete your own active session.</small>
                            </div>
                            <button type="button" class="btn btn-kampung-primary btn-sm" data-bs-toggle="modal" data-bs-target="#addUserModal">
                                <i class="fa-solid fa-user-plus me-1"></i>Add New User
                            </button>
                        </div>

                        <div class="table-responsive">
                            <table class="table table-hover align-middle mb-0">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Full Name</th>
                                        <th>Username</th>
                                        <th>Role</th>
                                        <th>Created At</th>
                                        <th class="text-end">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($usersList as $u): ?>
                                        <?php
                                            $isSelf = (int)$u['id'] === (int)($user['id'] ?? 0);
                                            $uJson  = htmlspecialchars(json_encode($u, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP), ENT_QUOTES, 'UTF-8');
                                        ?>
                                        <tr>
                                            <td>#<?= (int)$u['id'] ?></td>
                                            <td class="fw-semibold">
                                                <?= e($u['full_name']) ?>
                                                <?php if ($isSelf): ?>
                                                    <span class="badge bg-info-subtle text-info-emphasis ms-1">You</span>
                                                <?php endif; ?>
                                            </td>
                                            <td><code><?= e($u['username']) ?></code></td>
                                            <td>
                                                <span class="role-pill <?= e($u['role']) ?>">
                                                    <?= e(strtoupper((string)$u['role'])) ?>
                                                </span>
                                            </td>
                                            <td class="small text-muted"><?= e($u['created_at']) ?></td>
                                            <td class="text-end text-nowrap">
                                                <button type="button" class="btn btn-sm btn-outline-warning text-dark" onclick='openEditUserModal(<?= $uJson ?>)'>
                                                    <i class="fa-solid fa-user-pen me-1"></i>Edit
                                                </button>
                                                <?php if (!$isSelf): ?>
                                                    <button type="button" class="btn btn-sm btn-outline-danger" onclick="openDeleteUserModal(<?= (int)$u['id'] ?>, '<?= e(addslashes($u['username'])) ?>')">
                                                        <i class="fa-solid fa-user-minus me-1"></i>Delete
                                                    </button>
                                                <?php else: ?>
                                                    <button type="button" class="btn btn-sm btn-outline-secondary" disabled title="Cannot delete your own active account">
                                                        <i class="fa-solid fa-lock"></i>
                                                    </button>
                                                <?php endif; ?>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                <?php endif; ?>
            </main>
        </div>
    </div>

    <!-- ========================================================================
         19. MODAL FORMS
         ======================================================================== -->

    <!-- Add Product Modal -->
    <div class="modal fade" id="addProductModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content rounded-4 border-0 shadow">
                <form method="post" action="index.php?page=inventory" novalidate>
                    <?= csrfInput() ?>
                    <input type="hidden" name="action" value="create_product">
                    <div class="modal-header" style="background: var(--light-blue);">
                        <h5 class="modal-title fw-bold"><i class="fa-solid fa-plus-circle text-success me-2"></i>Add Badminton Product</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body p-4">
                        <div class="row g-3">
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Product Name <span class="text-danger">*</span></label>
                                <input type="text" name="product_name" class="form-control" required maxlength="150" placeholder="e.g. Astrox 88D Pro">
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Category <span class="text-danger">*</span></label>
                                <select name="category" class="form-select" required>
                                    <option value="Racket">Racket</option>
                                    <option value="String">String</option>
                                    <option value="Shuttlecock">Shuttlecock</option>
                                </select>
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Brand</label>
                                <input type="text" name="brand" class="form-control" maxlength="100" placeholder="e.g. Yonex, Victor, Li-Ning">
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Product Image URL (Optional)</label>
                                <input type="url" name="product_image" class="form-control" maxlength="500" placeholder="https://example.com/racket.jpg">
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Purchase Price (RM) <span class="text-danger">*</span></label>
                                <input type="number" name="purchase_price" class="form-control" step="0.01" min="0" value="0.00" required>
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Selling Price (RM) <span class="text-danger">*</span></label>
                                <input type="number" name="selling_price" class="form-control" step="0.01" min="0" value="0.00" required>
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Stock Quantity <span class="text-danger">*</span></label>
                                <input type="number" name="stock_quantity" class="form-control" step="1" min="0" value="0" required>
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Minimum Stock Alert <span class="text-danger">*</span></label>
                                <input type="number" name="minimum_stock" class="form-control" step="1" min="0" value="5" required>
                            </div>
                            <div class="col-12">
                                <label class="form-label small fw-bold">Description</label>
                                <textarea name="description" class="form-control" rows="2" placeholder="Tension spec, weight/grip, speed grade, or notes..."></textarea>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer bg-light">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-kampung-primary px-4">Save Product</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- Edit Product Modal -->
    <div class="modal fade" id="editProductModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-lg modal-dialog-centered">
            <div class="modal-content rounded-4 border-0 shadow">
                <form method="post" action="index.php?page=inventory" novalidate>
                    <?= csrfInput() ?>
                    <input type="hidden" name="action" value="update_product">
                    <input type="hidden" name="product_id" id="editProdId">
                    <div class="modal-header" style="background: var(--warm-yellow);">
                        <h5 class="modal-title fw-bold"><i class="fa-solid fa-pen-to-square me-2"></i>Edit Badminton Product</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body p-4">
                        <div class="row g-3">
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Product Name <span class="text-danger">*</span></label>
                                <input type="text" name="product_name" id="editProdName" class="form-control" required maxlength="150">
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Category <span class="text-danger">*</span></label>
                                <select name="category" id="editProdCategory" class="form-select" required>
                                    <option value="Racket">Racket</option>
                                    <option value="String">String</option>
                                    <option value="Shuttlecock">Shuttlecock</option>
                                </select>
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Brand</label>
                                <input type="text" name="brand" id="editProdBrand" class="form-control" maxlength="100">
                            </div>
                            <div class="col-12 col-md-6">
                                <label class="form-label small fw-bold">Product Image URL (Optional)</label>
                                <input type="url" name="product_image" id="editProdImage" class="form-control" maxlength="500">
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Purchase Price (RM) <span class="text-danger">*</span></label>
                                <input type="number" name="purchase_price" id="editProdPurchase" class="form-control" step="0.01" min="0" required>
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Selling Price (RM) <span class="text-danger">*</span></label>
                                <input type="number" name="selling_price" id="editProdSelling" class="form-control" step="0.01" min="0" required>
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Stock Quantity <span class="text-danger">*</span></label>
                                <input type="number" name="stock_quantity" id="editProdStock" class="form-control" step="1" min="0" required>
                            </div>
                            <div class="col-6 col-md-3">
                                <label class="form-label small fw-bold">Minimum Stock Alert <span class="text-danger">*</span></label>
                                <input type="number" name="minimum_stock" id="editProdMinStock" class="form-control" step="1" min="0" required>
                            </div>
                            <div class="col-12">
                                <label class="form-label small fw-bold">Description</label>
                                <textarea name="description" id="editProdDesc" class="form-control" rows="2"></textarea>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer bg-light">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-kampung-sun px-4">Update Product</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <!-- View Product Details Modal -->
    <div class="modal fade" id="viewProductModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content rounded-4 border-0 shadow">
                <div class="modal-header" style="background: var(--light-blue);">
                    <h5 class="modal-title fw-bold"><i class="fa-solid fa-circle-info text-primary me-2"></i>Product Details</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body p-4">
                    <div class="text-center mb-3" id="viewProdImgWrap"></div>
                    <h4 class="h5 fw-bold mb-1" id="viewProdName"></h4>
                    <div class="mb-3">
                        <span class="badge bg-light text-dark border me-1" id="viewProdCategory"></span>
                        <span class="badge bg-info-subtle text-dark" id="viewProdBrand"></span>
                        <span class="badge rounded-pill ms-1" id="viewProdStatus"></span>
                    </div>
                    <p class="small text-muted" id="viewProdDesc"></p>
                    <div class="row g-2 text-center mt-2">
                        <div class="col-6">
                            <div class="p-2 rounded-3 bg-light border">
                                <div class="small text-muted">Purchase Price</div>
                                <div class="fw-bold" id="viewProdPurchase"></div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="p-2 rounded-3 bg-light border">
                                <div class="small text-muted">Selling Price</div>
                                <div class="fw-bold text-success" id="viewProdSelling"></div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="p-2 rounded-3 bg-light border">
                                <div class="small text-muted">Current Stock</div>
                                <div class="fw-bold" id="viewProdStock"></div>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="p-2 rounded-3 bg-light border">
                                <div class="small text-muted">Minimum Stock</div>
                                <div class="fw-bold" id="viewProdMinStock"></div>
                            </div>
                        </div>
                    </div>
                </div>
                <div class="modal-footer bg-light">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Quick Stock Movement Modal from Inventory -->
    <div class="modal fade" id="quickStockModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content rounded-4 border-0 shadow">
                <form method="post" action="index.php?page=inventory" novalidate>
                    <?= csrfInput() ?>
                    <input type="hidden" name="action" value="record_movement">
                    <input type="hidden" name="return_page" value="inventory">
                    <input type="hidden" name="product_id" id="quickStockProdId">
                    <div class="modal-header" style="background: var(--light-blue);">
                        <h5 class="modal-title fw-bold"><i class="fa-solid fa-arrows-left-right text-success me-2"></i>Update Stock Quantity</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body p-4">
                        <div class="p-3 rounded-3 mb-3" style="background: var(--light-blue);">
                            <div class="fw-bold" id="quickStockProdName"></div>
                            <div class="small text-muted">Current Stock: <strong id="quickStockCurrent"></strong> units</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label small fw-bold">Movement Type</label>
                            <select name="movement_type" class="form-select" required>
                                <option value="Stock In">Stock In (+)</option>
                                <option value="Stock Out">Stock Out (-)</option>
                            </select>
                        </div>
                        <div class="mb-3">
                            <label class="form-label small fw-bold">Quantity</label>
                            <input type="number" name="quantity" class="form-control" min="1" step="1" required>
                        </div>
                        <div class="mb-2">
                            <label class="form-label small fw-bold">Remarks</label>
                            <input type="text" name="remarks" class="form-control" maxlength="255" placeholder="Optional note">
                        </div>
                    </div>
                    <div class="modal-footer bg-light">
                        <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-kampung-primary px-4">Apply Movement</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <?php if (isAdmin()): ?>
        <!-- Delete Product Confirmation Modal (Admin Only) -->
        <div class="modal fade" id="deleteProductModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content rounded-4 border-0 shadow">
                    <form method="post" action="index.php?page=inventory">
                        <?= csrfInput() ?>
                        <input type="hidden" name="action" value="delete_product">
                        <input type="hidden" name="product_id" id="delProdId">
                        <div class="modal-header bg-danger text-white">
                            <h5 class="modal-title fw-bold"><i class="fa-solid fa-trash me-2"></i>Confirm Product Deletion</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-4">
                            <p class="mb-0">Are you sure you want to permanently delete <strong id="delProdName"></strong>? This also removes its movement history.</p>
                        </div>
                        <div class="modal-footer bg-light">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-danger fw-bold">Yes, Delete Product</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Add User Modal (Admin Only) -->
        <div class="modal fade" id="addUserModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content rounded-4 border-0 shadow">
                    <form method="post" action="index.php?page=users" novalidate>
                        <?= csrfInput() ?>
                        <input type="hidden" name="action" value="create_user">
                        <div class="modal-header" style="background: var(--light-blue);">
                            <h5 class="modal-title fw-bold"><i class="fa-solid fa-user-plus text-success me-2"></i>Create User Account</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-4">
                            <div class="mb-3">
                                <label class="form-label small fw-bold">Full Name <span class="text-danger">*</span></label>
                                <input type="text" name="full_name" class="form-control" maxlength="120" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label small fw-bold">Username <span class="text-danger">*</span></label>
                                <input type="text" name="username" class="form-control" maxlength="40" pattern="[a-z0-9_]{3,40}" required>
                                <div class="form-text">Lowercase letters, numbers, or underscores (3-40 chars).</div>
                            </div>
                            <div class="mb-3">
                                <label class="form-label small fw-bold">Password <span class="text-danger">*</span></label>
                                <input type="password" name="password" class="form-control" minlength="6" required>
                            </div>
                            <div class="mb-2">
                                <label class="form-label small fw-bold">Role <span class="text-danger">*</span></label>
                                <select name="role" class="form-select" required>
                                    <option value="user">User (Staff)</option>
                                    <option value="admin">Admin (Administrator)</option>
                                </select>
                            </div>
                        </div>
                        <div class="modal-footer bg-light">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-kampung-primary px-4">Create User</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Edit User Modal (Admin Only) -->
        <div class="modal fade" id="editUserModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content rounded-4 border-0 shadow">
                    <form method="post" action="index.php?page=users" novalidate>
                        <?= csrfInput() ?>
                        <input type="hidden" name="action" value="update_user">
                        <input type="hidden" name="user_id" id="editUserId">
                        <div class="modal-header" style="background: var(--warm-yellow);">
                            <h5 class="modal-title fw-bold"><i class="fa-solid fa-user-pen me-2"></i>Edit User Account</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-4">
                            <div class="mb-3">
                                <label class="form-label small fw-bold">Full Name <span class="text-danger">*</span></label>
                                <input type="text" name="full_name" id="editUserFullName" class="form-control" maxlength="120" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label small fw-bold">Username <span class="text-danger">*</span></label>
                                <input type="text" name="username" id="editUserUsername" class="form-control" maxlength="40" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label small fw-bold">New Password (Optional)</label>
                                <input type="password" name="password" class="form-control" minlength="6" placeholder="Leave blank to keep current password">
                            </div>
                            <div class="mb-2">
                                <label class="form-label small fw-bold">Role <span class="text-danger">*</span></label>
                                <select name="role" id="editUserRole" class="form-select" required>
                                    <option value="user">User (Staff)</option>
                                    <option value="admin">Admin (Administrator)</option>
                                </select>
                            </div>
                        </div>
                        <div class="modal-footer bg-light">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-kampung-sun px-4">Save Changes</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>

        <!-- Delete User Modal (Admin Only) -->
        <div class="modal fade" id="deleteUserModal" tabindex="-1" aria-hidden="true">
            <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content rounded-4 border-0 shadow">
                    <form method="post" action="index.php?page=users">
                        <?= csrfInput() ?>
                        <input type="hidden" name="action" value="delete_user">
                        <input type="hidden" name="user_id" id="delUserId">
                        <div class="modal-header bg-danger text-white">
                            <h5 class="modal-title fw-bold"><i class="fa-solid fa-user-minus me-2"></i>Delete User Account</h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body p-4">
                            <p class="mb-0">Remove account <strong id="delUserName"></strong>? This action cannot be undone.</p>
                        </div>
                        <div class="modal-footer bg-light">
                            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
                            <button type="submit" class="btn btn-danger fw-bold">Delete Account</button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    <?php endif; ?>
<?php endif; ?>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<?php if ($requestedPage === 'dashboard'): ?>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
<?php endif; ?>

<!-- ========================================================================
     21. JAVASCRIPT
     ======================================================================== -->
<script>
    function toggleSidebar(show) {
        const sidebar = document.getElementById('mainSidebar');
        const backdrop = document.getElementById('sidebarBackdrop');
        if (!sidebar || !backdrop) return;
        sidebar.classList.toggle('show', Boolean(show));
        backdrop.classList.toggle('show', Boolean(show));
    }

    function openEditProductModal(p) {
        document.getElementById('editProdId').value = p.id;
        document.getElementById('editProdName').value = p.product_name || '';
        document.getElementById('editProdCategory').value = p.category || 'Racket';
        document.getElementById('editProdBrand').value = p.brand || '';
        document.getElementById('editProdImage').value = p.product_image || '';
        document.getElementById('editProdPurchase').value = p.purchase_price || '0.00';
        document.getElementById('editProdSelling').value = p.selling_price || '0.00';
        document.getElementById('editProdStock').value = p.stock_quantity ?? 0;
        document.getElementById('editProdMinStock').value = p.minimum_stock ?? 5;
        document.getElementById('editProdDesc').value = p.description || '';
        new bootstrap.Modal(document.getElementById('editProductModal')).show();
    }

    function openViewProductModal(p) {
        document.getElementById('viewProdName').textContent = p.product_name || '';
        document.getElementById('viewProdCategory').textContent = p.category || '';
        document.getElementById('viewProdBrand').textContent = p.brand || 'No Brand';
        document.getElementById('viewProdDesc').textContent = p.description || 'No description provided.';
        document.getElementById('viewProdPurchase').textContent = 'RM ' + Number(p.purchase_price || 0).toFixed(2);
        document.getElementById('viewProdSelling').textContent = 'RM ' + Number(p.selling_price || 0).toFixed(2);
        document.getElementById('viewProdStock').textContent = (p.stock_quantity ?? 0) + ' units';
        document.getElementById('viewProdMinStock').textContent = (p.minimum_stock ?? 0) + ' units';

        const statusBadge = document.getElementById('viewProdStatus');
        const st = p.stock_status || 'In Stock';
        statusBadge.textContent = st;
        statusBadge.className = 'badge rounded-pill ms-1 ' + (
            st === 'Out of Stock' ? 'bg-danger-subtle text-danger' :
            st === 'Low Stock' ? 'bg-warning-subtle text-dark' :
            'bg-success-subtle text-success'
        );

        const imgWrap = document.getElementById('viewProdImgWrap');
        if (p.product_image) {
            imgWrap.innerHTML = '<img src="' + String(p.product_image).replace(/"/g, '&quot;') + '" alt="" class="img-fluid rounded-3 border" style="max-height:170px;object-fit:cover;">';
        } else {
            imgWrap.innerHTML = '';
        }

        new bootstrap.Modal(document.getElementById('viewProductModal')).show();
    }

    function openQuickStockModal(p) {
        document.getElementById('quickStockProdId').value = p.id;
        document.getElementById('quickStockProdName').textContent = p.product_name || '';
        document.getElementById('quickStockCurrent').textContent = p.stock_quantity ?? 0;
        new bootstrap.Modal(document.getElementById('quickStockModal')).show();
    }

    function openDeleteProductModal(id, name) {
        const elId = document.getElementById('delProdId');
        const elName = document.getElementById('delProdName');
        const modalEl = document.getElementById('deleteProductModal');
        if (elId && elName && modalEl) {
            elId.value = id;
            elName.textContent = name;
            new bootstrap.Modal(modalEl).show();
        }
    }

    function openEditUserModal(u) {
        const modalEl = document.getElementById('editUserModal');
        if (!modalEl) return;
        document.getElementById('editUserId').value = u.id;
        document.getElementById('editUserFullName').value = u.full_name || '';
        document.getElementById('editUserUsername').value = u.username || '';
        document.getElementById('editUserRole').value = u.role || 'user';
        new bootstrap.Modal(modalEl).show();
    }

    function openDeleteUserModal(id, username) {
        const elId = document.getElementById('delUserId');
        const elName = document.getElementById('delUserName');
        const modalEl = document.getElementById('deleteUserModal');
        if (elId && elName && modalEl) {
            elId.value = id;
            elName.textContent = '@' + username;
            new bootstrap.Modal(modalEl).show();
        }
    }

    <?php if ($requestedPage === 'dashboard' && is_array($dashboardData)): ?>
        (function () {
            const catCtx = document.getElementById('stockByCategoryChart');
            if (catCtx && typeof Chart !== 'undefined') {
                new Chart(catCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Racket', 'String', 'Shuttlecock'],
                        datasets: [{
                            data: [
                                <?= (int)$dashboardData['categories_map']['Racket']['total_units'] ?>,
                                <?= (int)$dashboardData['categories_map']['String']['total_units'] ?>,
                                <?= (int)$dashboardData['categories_map']['Shuttlecock']['total_units'] ?>
                            ],
                            backgroundColor: ['#87CEEB', '#FFD93D', '#6BCB77'],
                            borderColor: '#FFFFFF',
                            borderWidth: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });
            }

            const lvlCtx = document.getElementById('inventoryLevelsChart');
            if (lvlCtx && typeof Chart !== 'undefined') {
                <?php
                    $lvlLabels = array_map(static fn($r) => (string)$r['product_name'], $dashboardData['level_rows']);
                    $lvlStock  = array_map(static fn($r) => (int)$r['stock_quantity'], $dashboardData['level_rows']);
                    $lvlMin    = array_map(static fn($r) => (int)$r['minimum_stock'], $dashboardData['level_rows']);
                ?>
                new Chart(lvlCtx, {
                    type: 'bar',
                    data: {
                        labels: <?= json_encode($lvlLabels, JSON_HEX_TAG) ?>,
                        datasets: [
                            {
                                label: 'Current Stock',
                                data: <?= json_encode($lvlStock, JSON_HEX_TAG) ?>,
                                backgroundColor: '#6BCB77',
                                borderRadius: 6
                            },
                            {
                                label: 'Minimum Alert',
                                data: <?= json_encode($lvlMin, JSON_HEX_TAG) ?>,
                                backgroundColor: '#FFD93D',
                                borderRadius: 6
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: { beginAtZero: true, ticks: { precision: 0 } }
                        },
                        plugins: {
                            legend: { position: 'bottom' }
                        }
                    }
                });
            }
        })();
    <?php endif; ?>
</script>
</body>
</html>