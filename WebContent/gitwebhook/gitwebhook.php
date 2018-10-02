<?php

# Enable Error Reporting and Display:
error_reporting(E_ERROR | E_WARNING | E_PARSE | E_NOTICE);
ini_set('display_errors', 1);

require(__DIR__ . '/secret.php');

function validateSignature($gitHubSignatureHeader, $payload, $secret) {
    list ($algo, $gitHubSignature) = explode("=", $gitHubSignatureHeader);
    if ($algo !== 'sha1') {
        // See https://developer.github.com/webhooks/securing/
        return false;
    }
    $payloadHash = hash_hmac($algo, $payload, $secret);
    return ($payloadHash == $gitHubSignature);
    // return hash_equals($payloadHash, $gitHubSignature);
}

function logIt($txt) {
    $mydate = date('l jS \of F Y h:i:s A');
    $my_file = 'log.txt';
    $handle = fopen($my_file, 'a') or die('Cannot open file:  '.$my_file);
    fwrite($handle, $mydate . " > " . $txt . "\n");
    fclose($handle);
}

// Make sure that it is a POST request.
if (strcasecmp($_SERVER['REQUEST_METHOD'], 'POST') != 0) {
    logIt('Request method must be POST!');
    die();
}

// Make sure that the content type of the POST
// request has been set to application/json.
$contentType = isset($_SERVER["CONTENT_TYPE"]) ?
    trim($_SERVER["CONTENT_TYPE"]) : '';

if (strcasecmp($contentType, 'application/json') != 0) {
    logIt('Content type must be: application/json');
    die();
}

// Receive the RAW post data.
$content = trim(file_get_contents("php://input"));

$gitHubSignatureHeader = @$_SERVER['HTTP_X_HUB_SIGNATURE'];
if (!validateSignature($gitHubSignatureHeader, $content, $secret)) {
    logIt("Invalid signature: " . $gitHubSignatureHeader);
    die();
}

// Attempt to decode the incoming RAW post data from JSON.
$decoded = json_decode($content, true);

// If json_decode failed, the JSON is invalid.
if (!is_array($decoded)) {
    logIt('Received content contained invalid JSON!');
    die();
}

// Process the JSON.

$prefix = 'https://github.com/nodeGame/nodegame-website/raw/master/';

$updated = array();
// There might be more than 1 commit from last push.
$commits = $decoded["commits"];
$web_dir = realpath(__DIR__ . '/..') . '/';
foreach ($commits as $commit_data) {
    $mod_files = $commit_data["modified"];
    // file_put_contents("./mod_files" . $counter, var_export($mod_files, true));
    foreach ($mod_files as $f) {
        // Ignore changes to gitwebhook directory (must update manually).
        // if (strpos($f, 'gitwebhook') !== false) continue;
        // Ignore files already copied.
        // if ($updated[$f]) continue;
        // Ignore changes outside WebContent.
        // if (strpos($f, 'WebContent/') !== 0) continue;
        $filePath = $web_dir . substr($f, 11);
        // Copy file.
        // file_put_contents("./mod_files", $filePath);
        $fileContent = file_get_contents($prefix . $f);
        if ($fileContent == FALSE) {
            logIt('Error fetching file: ' . $f);
        }
        else {
            $res = file_put_contents($filePath, $fileContent);
            if ($res) {
                // Mark updated.
                $updated[$f] = $f;
            }
            else {
                logIt('Error writing file: ' . $f);
            }
        }

        // file_put_contents($filePath, fopen($prefix . $f, 'r'));
        // Mark updated.
        // $updated[$f] = TRUE;
    }
}

// Save last payload.
$my_file = 'lastPayload.txt';
$handle = fopen($my_file, 'w') or die('Cannot open file:  '.$my_file);
fwrite($handle, var_export($decoded, true));
fclose($handle);
logIt("OK. Files updated (" . count($updated) . "): " . implode(" ", $updated));
