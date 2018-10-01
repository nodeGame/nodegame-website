<?php

require(__DIR__ . '/secret.php');

function validateSignature($gitHubSignatureHeader, $payload) {
  list ($algo, $gitHubSignature) = explode("=", $gitHubSignatureHeader);
  if ($algo !== 'sha1') {
    // See https://developer.github.com/webhooks/securing/
    return false;
  }
  $payloadHash = hash_hmac($algo, $payload, $secret);
  return hash_equals($payloadHash, $gitHubSignature);
}

$str = "OK";

// Make sure that it is a POST request.
if (strcasecmp($_SERVER['REQUEST_METHOD'], 'POST') != 0) {
    $str = 'Request method must be POST!';
}
 
// Make sure that the content type of the POST
// request has been set to application/json.
$contentType = isset($_SERVER["CONTENT_TYPE"]) ?
                 trim($_SERVER["CONTENT_TYPE"]) : '';
                 
if (strcasecmp($contentType, 'application/json') != 0) {
    $str = 'Content type must be: application/json';
}
 
// Receive the RAW post data.
$content = trim(file_get_contents("php://input"));
 
// Attempt to decode the incoming RAW post data from JSON.
$decoded = json_decode($content, true);
 
// If json_decode failed, the JSON is invalid.
if (!is_array($decoded)) {
    $str = 'Received content contained invalid JSON!';
}

if (!validateSignature($decoded)) {
  $str = "Invalid signature";
}

// Process the JSON.
$mydate = date('l jS \of F Y h:i:s A'); 
$my_file = 'log.txt';
$handle = fopen($my_file, 'a') or die('Cannot open file:  '.$my_file);
fwrite($handle, $mydate . " > " . $str . "\n");
fclose($handle);

if ($str == "OK" ) {
  $my_file = 'file.txt';
  $handle = fopen($my_file, 'w') or die('Cannot open file:  '.$my_file);
  fwrite($handle, $content);
  fclose($handle);
}
