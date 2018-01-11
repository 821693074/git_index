<?php
/**
 * 此页面用来实现git的clone、pull、push等基本操作
 */

include __DIR__ . '/../../autoload.php';
use hapn\util\Logger;
use hapn\util\Conf;
use hapn\db\Db;
use firegit\app\mod\git\Reposite;

set_time_limit(600);

//初始化配置文件和数据库
Conf::load([CONF_ROOT . '/hapn.conf.php']);
Db::init(Conf::get('db.conf'));
// 初始化日志
$logFile = 'cgi';
$logLevel = Conf::get('hapn.log.level', Logger::INT_LOG_LEVEL_DEBUG);
$roll = Conf::get('hapn.log.roll', Logger::NONE_ROLLING);
Logger::init(LOG_ROOT, $logFile, [], $logLevel, $roll);

//全局变量
$username = $_SERVER['PHP_AUTH_USER'] ?? '';
$pwd = $_SERVER['PHP_AUTH_PW'] ?? '';
$uri = $_SERVER['REQUEST_URI'] ?? '';

$info = parse_url($uri);
$path = $info['path'];
$arr = explode('/', trim($path, '/'));
$git['group'] = array_shift($arr);
$git['name'] = array_shift($arr);
if (substr($git['name'], -4) == '.git') {
    $git['name'] = substr($git['name'], 0, -4);
}
$path = sprintf('%s/%s/%s.git', GIT_REPO, $git['group'], $git['name']);
Logger::trace('gitDir:' . $path);
$action = implode('/', $arr);
Logger::trace('action:' . $action);

//校验项目权限
if (empty($git['group']) || empty($git['name'])) {
    header('HTTP/1.1 404 Not Found');
    exit();
}
$mReposite = new Reposite();
$repoInfo = $mReposite->getRepoByGroupName($git['group'], $git['name']); //项目信息
if (empty($repoInfo)) {
    header('HTTP/1.1 404 Not Found');
    exit();
}

//file_put_contents(LOG_ROOT.'index.log', $action, FILE_APPEND);
switch ($action) {
    case 'info/refs':
        $service = $_GET['service'];    //下一步操作
        if ($service == 'git-upload-pack' && $repoInfo['anony_access'] == 0) {
            checkUser($username, $pwd);
            $role = $mReposite->getTeamUserRole($repoInfo['repo_id'], $username); //用户的项目权限
            if (!isset($role['repo_role']) || $role['repo_role'] < Reposite::GROUP_ROLE_READER) {
                header('HTTP/1.1 403 Forbidden');
                exit();
            }
        } else if ($service == 'git-receive-pack') {
            checkUser($username, $pwd);
            $role = $mReposite->getTeamUserRole($repoInfo['repo_id'], $username); //用户的项目权限
            if (!isset($role['repo_role']) || $role['repo_role'] <= Reposite::GROUP_ROLE_READER) {
                header('HTTP/1.1 403 Forbidden');
                exit();
            }
        }
        header('Content-type: application/x-' . $service . '-advertisement');
        $cmd = sprintf('git %s --stateless-rpc --advertise-refs %s', substr($service, 4), $path);
        Logger::trace('cmd:' . $cmd);
        exec($cmd, $outputs);
        $serverAdvert = sprintf('# service=%s', $service);
        $length = strlen($serverAdvert) + 4;
        echo sprintf('%04x%s0000', $length, $serverAdvert);
        echo implode(PHP_EOL, $outputs);
        Logger::trace(implode(PHP_EOL, $outputs));
        unset($outputs);
        break;
    case 'git-upload-pack':
    case 'git-receive-pack':
        if ($action == 'git-upload-pack' && $repoInfo['anony_access'] == 0) {
            checkUser($username, $pwd);
            $role = $mReposite->getTeamUserRole($repoInfo['repo_id'], $username); //用户的项目权限
            if (!isset($role['repo_role']) || $role['repo_role'] < Reposite::GROUP_ROLE_READER) {
                header('HTTP/1.1 403 Forbidden');
                exit();
            }
        } else if ($action == 'git-receive-pack') {
            checkUser($username, $pwd);
            $role = $mReposite->getTeamUserRole($repoInfo['repo_id'], $username); //用户的项目权限
            if (!isset($role['repo_role']) || $role['repo_role'] <= Reposite::GROUP_ROLE_READER) {
                header('HTTP/1.1 403 Forbidden');
                exit();
            }
        }
        $input = file_get_contents('php://input');
        header(sprintf('Content-type: application/x-%s-result', $action));
        $input = gzBody($input);
        $cmd = sprintf('git %s --stateless-rpc %s', substr($action, 4), $path);
        $descs = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];
        Logger::trace('cmd:' . $cmd);
        $process = proc_open($cmd, $descs, $pipes, null, ['REQUEST_METHOD' => 'GET', 'AUTH_USER' => $username]);
        if (is_resource($process)) {
            fwrite($pipes[0], $input);
            fclose($pipes[0]);
            while (!feof($pipes[1])) {
                $data = fread($pipes[1], 16*1024);
                echo $data;
                ob_flush();
            }
            Logger::trace(stream_get_contents($pipes[2]));
            fclose($pipes[1]);
            fclose($pipes[2]);
            $return_value = proc_close($process);
        }
        if ($action == 'git-receive-pack') {
            $cmd = sprintf('git --git-dir %s update-server-info', $path);
            Logger::trace('cmd:' . $cmd);
            exec($cmd);
        }
        break;
}

function checkUser($username, $pwd)
{
    //使用输入了用户名、密码
    if (empty($username) || empty($pwd)) {
        header("WWW-Authenticate: Basic realm=\"GIT LOGIN\"");
        header('HTTP/1.1 401 Unauthorize');
        exit();
    }

    //验证帐号密码
    $grant = new firegit\app\mod\user\Grant();
    $login = $grant->login($username, $pwd);
    if ($login['status'] != 1) {
        header("WWW-Authenticate: Basic realm=\"GIT LOGIN\"");
        header('HTTP/1.1 401 Unauthorize');
        exit();
    }
}

// gzip解压内容
function gzBody($gzData)
{
    $encoding = $_SERVER['HTTP_CONTENT_ENCODING'] ?? '';
    $gzip = ($encoding == 'gzip' || $encoding == 'x-gzip');
    if (!$gzip) {
        return $gzData;
    }
    $i = 10;
    $flg = ord(substr($gzData, 3, 1));
    if ($flg > 0) {
        if ($flg & 4) {
            list($xlen) = unpack('v', substr($gzData, $i, 2));
            $i = $i + 2 + $xlen;
        }
        if ($flg & 8) {
            $i = strpos($gzData, "\0", $i) + 1;
        }
        if ($flg & 16) {
            $i = strpos($gzData, "\0", $i) + 1;
        }
        if ($flg & 2) {
            $i = $i + 2;
        }
    }
    return gzinflate(substr($gzData, $i, -8));
}
