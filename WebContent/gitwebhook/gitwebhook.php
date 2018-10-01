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

$gitHubSignatureHeader = @$_SERVER['HTTP_X_HUB_SIGNATURE'];
if (!validateSignature($gitHubSignatureHeader, $content)) {
  logIt("Invalid signature: " . $gitHubSignatureHeader);
}
 
// Attempt to decode the incoming RAW post data from JSON.
$decoded = json_decode($content, true);

// If json_decode failed, the JSON is invalid.
if (!is_array($decoded)) {
    logIt('Received content contained invalid JSON!');
}

// Process the JSON.

$prefix = 'https://github.com/nodeGame/nodegame-website/blob/master/';

$updated = array();
// There might be more than 1 commit from last push.
$commits = $decoded->commits;

foreach ($commits as $commit_data) {
    $mod_files = $commit_data->modified;
    foreach ($mod_files as $f) {
      // Ignore changes to gitwebhook directory (must update manually).
      if (strpos($f, 'gitwebhook') !== false) continue;
      // Ignore changes outside WebContent.
      if (strpos($f, 'WebContent/') !== 0) continue;
      // Ignore files already copied.
      if ($updated[$f]) continue;
      // Copy file.
      // file_put_contents("./file_" . count($updated), fopen($prefix . $f), 'r'));
      // Mark updated.
      $updated[$f] = TRUE;
   }
}     

// Save last payload.
$my_file = 'lastPayload.txt';
$handle = fopen($my_file, 'w') or die('Cannot open file:  '.$my_file);
fwrite($handle, var_export($decoded, true));
fclose($handle);
logIt("OK. Files updated: " . count($updated), TRUE);


