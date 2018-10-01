<?php

require(__DIR__ . '/secret.php');

function validateSignature($payload) {
  $gitHubSignatureHeader = @$_SERVER['HTTP_X_HUB_SIGNATURE'];
  list ($algo, $gitHubSignature) = explode("=", $gitHubSignatureHeader);
  if ($algo !== 'sha1') {
    // See https://developer.github.com/webhooks/securing/
    return false;
  }
  $payloadHash = hash_hmac($algo, $payload, $secret);
  return hash_equals($payloadHash, $gitHubSignature);
}

function logIt($txt, $success = FALSE) {
  $mydate = date('l jS \of F Y h:i:s A'); 
  $my_file = 'log.txt';
  $handle = fopen($my_file, 'a') or die('Cannot open file:  '.$my_file);
  fwrite($handle, $mydate . " > " . $txt . "\n");
  fclose($handle);
  if (!success) {
    die($txt);
  }
}

// Make sure that it is a POST request.
if (strcasecmp($_SERVER['REQUEST_METHOD'], 'POST') != 0) {
    logIt('Request method must be POST!');
}
 
// Make sure that the content type of the POST
// request has been set to application/json.
$contentType = isset($_SERVER["CONTENT_TYPE"]) ?
                 trim($_SERVER["CONTENT_TYPE"]) : '';
                 
if (strcasecmp($contentType, 'application/json') != 0) {
    logIt('Content type must be: application/json');
}
 
// Receive the RAW post data.
$content = trim(file_get_contents("php://input"));

if (!validateSignature($content)) {
  logIt("Invalid signature: " . @$_SERVER['HTTP_X_HUB_SIGNATURE']);
}
 
// Attempt to decode the incoming RAW post data from JSON.
$decoded = json_decode($content, true);
 
// If json_decode failed, the JSON is invalid.
if (!is_array($decoded)) {
    logIt('Received content contained invalid JSON!');
}

// Process the JSON.

$my_file = 'file.txt';
$handle = fopen($my_file, 'w') or die('Cannot open file:  '.$my_file);
fwrite($handle, $content);
fclose($handle);
logIt("OK", TRUE);


