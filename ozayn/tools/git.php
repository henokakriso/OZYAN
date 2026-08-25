<?php
/**
 * Ozayn Git Integration
 * Git operations for version control
 */

class GitIntegration {

    private $repoPath;

    public function __construct($repoPath = null) {
        $this->repoPath = $repoPath ?? getcwd();
    }

    public function isGitRepo() {
        return is_dir($this->repoPath . '/.git');
    }

    public function getStatus() {
        if (!$this->isGitRepo()) {
            return ['error' => 'Not a git repository'];
        }
        $output = $this->exec(['status', '--porcelain']);
        $lines = array_filter(explode("\n", $output));
        $changes = ['modified' => [], 'added' => [], 'deleted' => [], 'untracked' => []];
        foreach ($lines as $line) {
            $status = substr($line, 0, 2);
            $file = trim(substr($line, 3));
            if (strpos($status, 'M') !== false) $changes['modified'][] = $file;
            elseif (strpos($status, 'A') !== false) $changes['added'][] = $file;
            elseif (strpos($status, 'D') !== false) $changes['deleted'][] = $file;
            elseif (strpos($status, '?') !== false) $changes['untracked'][] = $file;
        }
        return $changes;
    }

    public function getLog($limit = 20) {
        $limit = (int) $limit;
        $output = $this->exec(['log', '--oneline', "-{$limit}", '--pretty=format:%H|%an|%ae|%ai|%s']);
        $commits = [];
        foreach (explode("\n", $output) as $line) {
            $line = trim($line, "'");
            if (empty($line)) continue;
            $parts = explode('|', $line, 5);
            if (count($parts) >= 5) {
                $commits[] = [
                    'hash' => $parts[0],
                    'author' => $parts[1],
                    'email' => $parts[2],
                    'date' => $parts[3],
                    'message' => $parts[4]
                ];
            }
        }
        return $commits;
    }

    public function getBranches() {
        $output = $this->exec(['branch', '-a']);
        $branches = ['current' => '', 'local' => [], 'remote' => []];
        foreach (explode("\n", $output) as $line) {
            $line = trim($line);
            if (empty($line)) continue;
            $branch = preg_replace('/^[* ]+/', '', $line);
            if (strpos($line, '*') !== false) {
                $branches['current'] = $branch;
                $branches['local'][] = $branch;
            } elseif (strpos($branch, 'remotes/') !== false) {
                $branches['remote'][] = str_replace('remotes/origin/', '', $branch);
            } else {
                $branches['local'][] = $branch;
            }
        }
        return $branches;
    }

    public function diff($file = null) {
        $args = ['diff'];
        if ($file !== null) {
            $args[] = '--';
            $args[] = $file;
        } else {
            $args[] = '--stat';
        }
        return $this->exec($args);
    }

    public function diffStaged($file = null) {
        $args = ['diff', '--cached'];
        if ($file !== null) {
            $args[] = '--';
            $args[] = $file;
        } else {
            $args[] = '--stat';
        }
        return $this->exec($args);
    }

    public function add($files = '.') {
        $args = ['add'];
        if ($files === '.' || $files === '*') {
            $args[] = '.';
        } else {
            foreach (explode(' ', $files) as $f) {
                $f = trim($f);
                if ($f !== '') {
                    $args[] = $f;
                }
            }
        }
        $this->exec($args);
        return ['success' => true];
    }

    public function commit($message, $files = null) {
        $args = ['commit', '-m', $message];
        if ($files) {
            $args = array_merge(['add'], explode(' ', $files));
            $this->exec($args);
            $args = ['commit', '-m', $message];
        }
        $output = $this->exec($args);
        return ['success' => true, 'output' => $output];
    }

    public function push($remote = 'origin', $branch = null) {
        if (!$branch) {
            $branch = $this->getCurrentBranch();
        }
        $output = $this->exec(['push', $remote, $branch]);
        return ['success' => true, 'output' => $output];
    }

    public function pull($remote = 'origin', $branch = null) {
        if (!$branch) {
            $branch = $this->getCurrentBranch();
        }
        $output = $this->exec(['pull', $remote, $branch]);
        return ['success' => true, 'output' => $output];
    }

    public function stash($message = null) {
        $args = ['stash', 'push'];
        if ($message) {
            $args[] = '-m';
            $args[] = $message;
        }
        $output = $this->exec($args);
        return ['success' => true, 'output' => $output];
    }

    public function stashPop() {
        $output = $this->exec(['stash', 'pop']);
        return ['success' => true, 'output' => $output];
    }

    public function createBranch($name) {
        $output = $this->exec(['checkout', '-b', $name]);
        return ['success' => true, 'output' => $output];
    }

    public function switchBranch($name) {
        $output = $this->exec(['checkout', $name]);
        return ['success' => strpos($output, 'error') === false, 'output' => $output];
    }

    public function getCurrentBranch() {
        return trim($this->exec(['branch', '--show-current']));
    }

    public function getFileHistory($file, $limit = 10) {
        $limit = (int) $limit;
        $output = $this->exec([
            'log', '--oneline', "-{$limit}", '--format=%H|%ai|%s', '--', $file
        ]);
        $history = [];
        foreach (explode("\n", $output) as $line) {
            if (empty($line)) continue;
            $parts = explode('|', $line, 3);
            if (count($parts) >= 3) {
                $history[] = ['hash' => $parts[0], 'date' => $parts[1], 'message' => $parts[2]];
            }
        }
        return $history;
    }

    public function getRemoteUrl($remote = 'origin') {
        return trim($this->exec(['remote', 'get-url', $remote]));
    }

    /**
     * Validate git arguments. Only a small, known-safe set is permitted; anything
     * that could invoke shell features or unexpected options is rejected.
     */
    private function validateArgs(array $args) {
        $allowedFlags = [
            'status', 'log', 'branch', 'diff', 'add', 'commit', 'push', 'pull',
            'stash', 'checkout', 'remote', 'pop', 'push', '-b', '-m',
            '--porcelain', '--oneline', '--cached', '--stat', '--show-current',
            '-a', '-all', 'get-url', '.'
        ];
        foreach ($args as $arg) {
            if ($arg === '--') {
                continue;
            }
            if (in_array($arg, $allowedFlags, true)) {
                continue;
            }
            // Numeric -N limit (e.g. -10) is allowed
            if (preg_match('/^-[0-9]+$/', $arg)) {
                continue;
            }
            // A path argument after the safe separator, or a plain branch/remote name
            if (preg_match('/^[A-Za-z0-9_.\/-]+$/', $arg)) {
                continue;
            }
            return false;
        }
        return true;
    }

    private function exec(array $args) {
        if (!$this->validateArgs($args)) {
            return 'error: invalid or unsupported git argument';
        }
        $argv = array_merge(['git', '-C', $this->repoPath], $args);

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
            return '';
        }
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($proc);

        return trim($stdout . "\n" . $stderr);
    }
}
