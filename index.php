// You need to set these three to the values for your own application
define('CONSUMER_KEY', 'abc123');
define('CONSUMER_SECRET', '1234');
define('LOGIN_BASE_URL', 'https://test.salesforce.com');

//Json Header
$h = array(
	"alg" => "RS256"	
);

$jsonH = json_encode(($h));	
$header = base64_encode($jsonH); 

//Create JSon Claim/Payload
$c = array(
	"iss" => CONSUMER_KEY, 
	"sub" => "myemail@email.com", 
	"aud" => LOGIN_BASE_URL, 
	"exp" => "1333685628"
);

$jsonC = (json_encode($c));	
$payload = base64_encode($jsonC);

//Sign the resulting string using SHA256 with RSA
$s = hash_hmac('sha256', $header.'.'.$payload, CONSUMER_SECRET);
$secret = base64_encode($s);


$token = $header . '.' . $payload . '.' . $secret;

$token_url = LOGIN_BASE_URL.'/services/oauth2/token';

$post_fields = array(
	'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
	'assertion' => $token
);

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $token_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
curl_setopt($ch, CURLOPT_POST, TRUE);
curl_setopt($ch, CURLOPT_POSTFIELDS, $post_fields);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

// Make the API call, and then extract the information from the response
    $token_request_body = curl_exec($ch) 
        or die("Call to get token from code failed: '$token_url' - ".print_r($post_fields, true));
