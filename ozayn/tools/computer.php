<?php
/**
 * Ozayn Computer Control Tools
 * File operations, application launching, system commands
 */

class ComputerTools {

    /**
     * Root directory that all file operations are confined to.
     * Prevents arbitrary file read/write/delete outside the app data dir.
     */
    private $baseDir;

    public function __construct() {
        $base = getenv('OZAYN_DATA_DIR');
        if ($base) {
            $this->baseDir = rtrim($base, '/\\') . DIRECTORY_SEPARATOR;
        } else {
            // Default: a "files" directory inside the project root, kept out of the web root.
            $this->baseDir = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'data' . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR;
        }
        if (!is_dir($this->baseDir)) {
            @mkdir($this->baseDir, 0755, true);
        }
    }

    /**
     * Resolve $path to an absolute path confined within the base directory.
     * Works on both Linux and Windows. Returns null if the path escapes the sandbox.
     */
    private function resolveSafePath($path) {
        // Remove null bytes
        $path = str_replace("\0", '', (string) $path);

        // Normalize slashes for consistent handling across OSes
        $path = str_replace('\\', '/', $path);
        $base = str_replace('\\', '/', $this->baseDir);

        // Expand ~ to the base directory home
        if (strpos($path, '~') === 0) {
            $path = rtrim($base, '/') . '/' . ltrim(substr($path, 1), '/');
        }

        // Relative paths are relative to the base directory.
        // An absolute path is one that starts with "/" or a drive letter "C:".
        $isAbsolute = ($path[0] ?? '') === '/'
            || preg_match('#^[A-Za-z]:/#', $path);

        if (!$isAbsolute) {
            $path = rtrim($base, '/') . '/' . ltrim($path, '/');
        }

        $path = str_replace('\\', '/', $path);

        // Normalize and verify it stays inside the base directory.
        // realpath() fails for not-yet-existing files, so fall back to the parent dir.
        $real = realpath($path);
        if ($real === false) {
            $parent = realpath(dirname($path));
            if ($parent === false) {
                return null;
            }
            $candidate = rtrim($parent, '/') . '/' . basename($path);
        } else {
            $candidate = $real;
        }

        $baseReal = realpath($base);
        if ($baseReal === false) {
            $baseReal = $base;
        }
        $baseReal = rtrim(str_replace('\\', '/', $baseReal), '/');
        $candidate = rtrim(str_replace('\\', '/', $candidate), '/');

        // Case-insensitive prefix check is required on Windows
        $match = strncasecmp($candidate, $baseReal, strlen($baseReal)) === 0
            && ($candidate === $baseReal || $candidate[strlen($baseReal)] === '/');

        if (!$match) {
            return null;
        }

        $result = $real === false ? $candidate : $real;
        return str_replace('/', DIRECTORY_SEPARATOR, $result);
    }

    /**
     * List files in directory
     */
    public function listFiles($path = '.', $recursive = false) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        if (!is_dir($path)) {
            return ['error' => "Directory not found: {$path}"];
        }

        $items = [];
        
        if ($recursive) {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            foreach ($iterator as $item) {
                $items[] = $this->getFileInfo($item);
            }
        } else {
            foreach (new DirectoryIterator($path) as $item) {
                if (!$item->isDot()) {
                    $items[] = $this->getFileInfo($item);
                }
            }
        }

        return [
            'path' => $path,
            'items' => $items,
            'count' => count($items)
        ];
    }

    /**
     * Read file contents
     */
    public function readFile($path, $maxSize = 1048576) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        if (!file_exists($path)) {
            return ['error' => "File not found: {$path}"];
        }

        if (!is_readable($path)) {
            return ['error' => "File not readable: {$path}"];
        }

        $size = filesize($path);
        
        if ($size > $maxSize) {
            // Read in chunks for large files
            $handle = fopen($path, 'r');
            $content = fread($handle, $maxSize);
            fclose($handle);
            return [
                'path' => $path,
                'content' => $content,
                'truncated' => true,
                'size' => $size,
                'max_size' => $maxSize
            ];
        }

        return [
            'path' => $path,
            'content' => file_get_contents($path),
            'truncated' => false,
            'size' => $size
        ];
    }

    /**
     * Write file contents
     */
    public function writeFile($path, $content, $append = false) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        // Create directory if not exists
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $mode = $append ? 'a' : 'w';
        $handle = fopen($path, $mode);
        
        if (!$handle) {
            return ['error' => "Cannot write to file: {$path}"];
        }

        fwrite($handle, $content);
        fclose($handle);

        return [
            'success' => true,
            'path' => $path,
            'bytes_written' => strlen($content),
            'mode' => $append ? 'append' : 'write'
        ];
    }

    /**
     * Create directory
     */
    public function createDirectory($path) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        if (is_dir($path)) {
            return ['error' => "Directory already exists: {$path}"];
        }

        if (mkdir($path, 0755, true)) {
            return ['success' => true, 'path' => $path];
        }

        return ['error' => "Failed to create directory: {$path}"];
    }

    /**
     * Delete file or directory
     */
    public function delete($path) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        if (!file_exists($path)) {
            return ['error' => "Path not found: {$path}"];
        }

        // Safety check - prevent deleting critical directories
        $protected = ['/', '/home', '/etc', '/var', '/usr', '/bin', '/sbin'];
        $realPath = realpath($path);
        
        foreach ($protected as $p) {
            if ($realPath === $p || strpos($realPath, $p . '/') === 0) {
                return ['error' => "Cannot delete protected path: {$path}"];
            }
        }

        if (is_dir($path)) {
            $this->deleteDirectoryRecursive($path);
        } else {
            unlink($path);
        }

        return ['success' => true, 'path' => $path];
    }

    /**
     * Copy file
     */
    public function copyFile($source, $destination) {
        $source = $this->resolveSafePath($source);
        $destination = $this->resolveSafePath($destination);
        
        if (!file_exists($source)) {
            return ['error' => "Source not found: {$source}"];
        }

        $destDir = dirname($destination);
        if (!is_dir($destDir)) {
            mkdir($destDir, 0755, true);
        }

        if (copy($source, $destination)) {
            return [
                'success' => true,
                'source' => $source,
                'destination' => $destination
            ];
        }

        return ['error' => "Failed to copy file"];
    }

    /**
     * Move/rename file
     */
    public function moveFile($source, $destination) {
        $source = $this->resolveSafePath($source);
        $destination = $this->resolveSafePath($destination);
        
        if (!file_exists($source)) {
            return ['error' => "Source not found: {$source}"];
        }

        if (rename($source, $destination)) {
            return [
                'success' => true,
                'source' => $source,
                'destination' => $destination
            ];
        }

        return ['error' => "Failed to move file"];
    }

    /**
     * Search files by name pattern
     */
    public function searchFiles($path, $pattern, $maxResults = 50) {
        $path = $this->resolveSafePath($path);
        
        if (!is_dir($path)) {
            return ['error' => "Directory not found: {$path}"];
        }

        $results = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $item) {
            if (count($results) >= $maxResults) break;
            
            if (fnmatch($pattern, $item->getFilename(), FNM_CASEFOLD)) {
                $results[] = [
                    'path' => $item->getPathname(),
                    'name' => $item->getFilename(),
                    'size' => $item->getSize(),
                    'modified' => date('Y-m-d H:i:s', $item->getMTime())
                ];
            }
        }

        return [
            'path' => $path,
            'pattern' => $pattern,
            'results' => $results,
            'count' => count($results)
        ];
    }

    /**
     * Search file contents
     */
    public function grep($path, $pattern, $maxResults = 50) {
        $path = $this->resolveSafePath($path);
        
        if (!file_exists($path)) {
            return ['error' => "Path not found: {$path}"];
        }

        $results = [];
        
        if (is_file($path)) {
            $lines = file($path);
            foreach ($lines as $lineNum => $line) {
                if (preg_match($pattern, $line)) {
                    $results[] = [
                        'file' => $path,
                        'line' => $lineNum + 1,
                        'content' => trim($line)
                    ];
                    if (count($results) >= $maxResults) break;
                }
            }
        } else {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS)
            );
            
            foreach ($iterator as $item) {
                if ($item->isFile() && $item->isReadable()) {
                    $lines = file($item->getPathname());
                    foreach ($lines as $lineNum => $line) {
                        if (preg_match($pattern, $line)) {
                            $results[] = [
                                'file' => $item->getPathname(),
                                'line' => $lineNum + 1,
                                'content' => trim($line)
                            ];
                            if (count($results) >= $maxResults) break 2;
                        }
                    }
                }
            }
        }

        return [
            'pattern' => $pattern,
            'results' => $results,
            'count' => count($results)
        ];
    }

    /**
     * Get file information
     */
    public function getFileInfo($item) {
        return [
            'name' => $item->getFilename(),
            'path' => $item->getPathname(),
            'type' => $item->isDir() ? 'directory' : 'file',
            'size' => $item->getSize(),
            'modified' => date('Y-m-d H:i:s', $item->getMTime()),
            'permissions' => substr(sprintf('%o', $item->getPerms()), -4)
        ];
    }

    /**
     * Run shell command (restricted, no shell, no interpreters)
     */
    public function runCommand($command, $timeout = 30) {
        $isWindows = stripos(PHP_OS, 'WIN') === 0;

        // Only safe, read-only system-info commands. No interpreters (php/python/node/git)
        // so the sandbox cannot be used to execute arbitrary code.
        $allowed = ['ls', 'pwd', 'whoami', 'date', 'uptime', 'df', 'du', 'free',
                    'cat', 'head', 'tail', 'wc', 'grep', 'which', 'echo', 'uname',
                    'dir', 'ver', 'type', 'hostname', 'tasklist', 'systeminfo'];

        // Never permit code interpreters / shells.
        $forbidden = ['php', 'php.exe', 'python', 'python.exe', 'python3', 'py',
                      'node', 'node.exe', 'git', 'git.exe', 'cmd', 'cmd.exe',
                      'powershell', 'powershell.exe', 'sh', 'bash', 'wscript', 'cscript'];
        $cmdLower = strtolower(trim($command));

        $cmdParts = preg_split('/\s+/', $cmdLower);
        if (empty($cmdParts)) {
            return ['error' => 'Empty command'];
        }
        $baseCmd = strtolower(basename($cmdParts[0]));

        if (in_array($baseCmd, $forbidden, true)) {
            return ['error' => "Command not allowed: {$baseCmd}"];
        }
        if (!in_array($baseCmd, $allowed, true)) {
            return ['error' => "Command not allowed: {$baseCmd}"];
        }

        // Resolve the real executable path via the OS so we run a known binary,
        // and execute with proc_open (no shell) so metacharacters are inert.
        $exe = $this->findExecutable($baseCmd, $isWindows);
        if ($exe === null) {
            return ['error' => "Command not found: {$baseCmd}"];
        }

        $argv = [$exe];
        for ($i = 1; $i < count($cmdParts); $i++) {
            $argv[] = $cmdParts[$i];
        }

        $proc = proc_open(
            $argv,
            [
                0 => ['pipe', 'r'],
                1 => ['pipe', 'w'],
                2 => ['pipe', 'w'],
            ],
            $pipes
        );

        if (!is_resource($proc)) {
            return ['error' => 'Failed to start command'];
        }

        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $returnCode = proc_close($proc);

        $result = trim($stdout . "\n" . $stderr);

        return [
            'command' => implode(' ', $argv),
            'output' => $result,
            'return_code' => $returnCode,
            'success' => $returnCode === 0
        ];
    }

    /**
     * Locate an allowed executable without invoking a shell.
     * On Windows uses where.exe; on Unix uses which. Returns null if not found.
     */
    private function findExecutable($cmd, $isWindows) {
        if ($isWindows) {
            $out = [];
            $rc = 0;
            exec('where ' . escapeshellarg($cmd) . ' 2>nul', $out, $rc);
            if ($rc !== 0 || empty($out)) {
                return null;
            }
            return $out[0];
        }
        $out = [];
        $rc = 0;
        exec('command -v ' . escapeshellarg($cmd) . ' 2>/dev/null', $out, $rc);
        if ($rc !== 0 || empty($out)) {
            return null;
        }
        return $out[0];
    }

    /**
     * Get current directory
     */
    public function getCurrentDirectory() {
        return ['path' => getcwd()];
    }

    /**
     * Change directory (returns new path, doesn't actually change)
     */
    public function resolvePath($path) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        if (is_dir($path)) {
            return ['path' => realpath($path)];
        }

        return ['error' => "Directory not found: {$path}"];
    }

    /**
     * Get file stats
     */
    public function stat($path) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        if (!file_exists($path)) {
            return ['error' => "File not found: {$path}"];
        }

        $stat = stat($path);
        
        return [
            'path' => $path,
            'size' => $stat['size'],
            'accessed' => date('Y-m-d H:i:s', $stat['atime']),
            'modified' => date('Y-m-d H:i:s', $stat['mtime']),
            'changed' => date('Y-m-d H:i:s', $stat['ctime']),
            'permissions' => substr(sprintf('%o', $stat['mode']), -4),
            'is_file' => is_file($path),
            'is_dir' => is_dir($path),
            'readable' => is_readable($path),
            'writable' => is_writable($path)
        ];
    }

    /**
     * Watch file for changes
     */
    public function watchFile($path, $callback = null) {
        $path = $this->resolveSafePath($path);
        if ($path === null) {
            return ['error' => 'Access denied: path is outside the allowed directory'];
        }

        if (!file_exists($path)) {
            return ['error' => "File not found: {$path}"];
        }

        $lastModified = filemtime($path);
        
        return [
            'path' => $path,
            'last_modified' => date('Y-m-d H:i:s', $lastModified),
            'message' => 'Use polling to check for changes'
        ];
    }

    /**
     * Recursively delete directory
     */
    private function deleteDirectoryRecursive($path) {
        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        
        foreach ($items as $item) {
            if ($item->isDir()) {
                rmdir($item->getRealPath());
            } else {
                unlink($item->getRealPath());
            }
        }
        
        rmdir($path);
    }
}
