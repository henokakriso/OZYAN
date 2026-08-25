<?php
/**
 * Ozayn Router
 * Simple router to serve frontend and API
 */

$requestUri = $_SERVER['REQUEST_URI'];
$path = parse_url($requestUri, PHP_URL_PATH);

// Remove trailing slash
$path = rtrim($path, '/');

// Route API requests
if (strpos($path, '/ozayn/backend/api') === 0) {
    require __DIR__ . '/ozayn/backend/api/index.php';
    exit();
}

// Route frontend requests - redirect /ozayn to /ozayn/ so relative URLs work
if ($path === '/ozayn' && (!isset($_SERVER['REQUEST_URI']) || substr($_SERVER['REQUEST_URI'], -1) !== '/')) {
    header('Location: /ozayn/');
    http_response_code(301);
    exit();
}
if ($path === '/ozayn' || $path === '/ozayn/') {
    require __DIR__ . '/ozayn/frontend/index.html';
    exit();
}

if ($path === '/ozayn/config') {
    require __DIR__ . '/ozayn/frontend/config.html';
    exit();
}

if ($path === '/ozayn/3d') {
    require __DIR__ . '/ozayn/frontend/3d.html';
    exit();
}

if ($path === '/ozayn/dashboard') {
    require __DIR__ . '/ozayn/frontend/dashboard.html';
    exit();
}

// Serve static files from ozayn/frontend/
if (strpos($path, '/ozayn/') === 0) {
    $relativePath = substr($path, strlen('/ozayn/'));

    // Security: block access to sensitive app data and config over HTTP,
    // even when using the built-in PHP dev server (php -S). These contain
    // the SQLite DB (password hashes + session IDs), API keys, logs and backups.
    $blockedPrefixes = [
        'database/', 'backend/config/', 'logs/', 'backups/', 'data/', 'install.php'
    ];
    foreach ($blockedPrefixes as $prefix) {
        if (strpos($relativePath, $prefix) === 0) {
            http_response_code(403);
            echo json_encode(['error' => 'Forbidden']);
            exit();
        }
    }

    $filePath = __DIR__ . '/ozayn/frontend/' . $relativePath;
    
    // Security: prevent directory traversal
    $realPath = realpath($filePath);
    $baseDir = realpath(__DIR__ . '/ozayn/frontend');
    
    if ($realPath && strpos($realPath, $baseDir) === 0 && file_exists($realPath)) {
        // Set content type
        $ext = pathinfo($realPath, PATHINFO_EXTENSION);
        $mimeTypes = [
            'html' => 'text/html',
            'css' => 'text/css',
            'js' => 'application/javascript',
            'json' => 'application/json',
            'png' => 'image/png',
            'jpg' => 'image/jpeg',
            'gif' => 'image/gif',
            'svg' => 'image/svg+xml',
            'ico' => 'image/x-icon'
        ];
        
        if (isset($mimeTypes[$ext])) {
            header('Content-Type: ' . $mimeTypes[$ext]);
        }
        
        readfile($realPath);
        exit();
    }
}

// 404 for everything else
http_response_code(404);
echo json_encode(['error' => 'Not found']);
