<?php
    // Report all errors (ignore Notices)
    error_reporting(E_ALL & ~E_NOTICE);
    ini_set('display_errors', 1);
    session_start();
 
    // Define our State class
    class State 
    {
        public $passthroughState1;  // Arbitary state we want to pass to the Authentication request
        public $passthroughState2;  // Arbitary state we want to pass to the Authentication request
 
        public $code;               // Authentication code received from Salesforce
        public $token;              // Session token
        public $refreshToken;       // Refresh token
        public $instanceURL;        // Salesforce Instance URL
        public $userId;             // Current User Id
        public $redirect_uri;             // Current User Id
         
        public $codeVerifier;       // 128 bytes of random data used to secure the request
 
        public $error;              // Error code
        public $errorDescription;   // Error description
 
        /**
         * Constructor - Takes 2 pieces of optional state we want to preserve through the request
         */
        function __construct($state1 = "", $state2 = "")
        {
            // Initialise arbitary state
            $this->passthroughState1 = $state1;
            $this->passthroughState2 = $state2;
 
            // Initialise remaining state
            $this->code = "";
            $this->token = "";
            $this->refreshToken = "";
            $this->instanceURL = "";
            $this->userId = "";
            $this->redirect_uri = getCallBackURL();
             
            $this->error = "";
            $this->errorDescription = "";
 
            // Generate 128 bytes of random data
            $this->codeVerifier = bin2hex(openssl_random_pseudo_bytes(128));
        }
 
        /**
         * Helper function to populate state following a call back from Salesforce
         */
        function loadStateFromRequest()
        {
            $stateString = "";
 
            // If we've arrived via a GET request, we can assume it's a callback from Salesforce OAUTH
            // so attempt to load the state from the parameters in the request
            if ($_SERVER["REQUEST_METHOD"] == "GET") 
            {
                $this->code = $this->sanitizeInput($_GET["code"]);
                $this->error = $this->sanitizeInput($_GET["error"]);
                $this->errorDescription = $this->sanitizeInput($_GET["error_description"]);
                $stateString = $this->sanitizeInput($_GET["state"]);
 
                // If we have a state string, then deserialize this into state as it's been passed
                // to the salesforce request and back
                if ($stateString)
                {
                    $this->deserializeStateString($stateString);
                }
            }
        }
 
        /**
         * Helper function to sanitize any input and prevent injection attacks
         */
        function sanitizeInput($data) 
        {
            $data = trim($data);
            $data = stripslashes($data);
            $data = htmlspecialchars($data);
            return $data;
        }
 
        /**
         * Helper function to serialize our arbitary state we want to send accross the request
         */
        function serializeStateString()
        {
            $stateArray = array("passthroughState1" => $this->passthroughState1, 
                                "passthroughState2" => $this->passthroughState2
                                );
 
            return rawurlencode(base64_encode(serialize($stateArray)));
        }
 
        /**
         * Helper function to deserialize our arbitary state passed back in the callback
         */
        function deserializeStateString($stateString)
        {
            $stateArray = unserialize(base64_decode(rawurldecode($stateString)));
 
            $this->passthroughState1 = $stateArray["passthroughState1"];
            $this->passthroughState2 = $stateArray["passthroughState2"];
        }
 
        /**
         * Helper function to generate the code challenge for the code verifier
         */
        function generateCodeChallenge()
        {
            $hash = pack('H*', hash("SHA256", $this->generateCodeVerifier()));
 
            return $this->base64url_encode($hash);
        }
 
        /**
         * Helper function to generate the code verifier
         */
        function generateCodeVerifier()
        {
            return $this->base64url_encode(pack('H*', $this->codeVerifier));
        }
 
        /**
         * Helper function to Base64URL encode as per https://tools.ietf.org/html/rfc4648#section-5
         */
        function base64url_encode($string)
        {
            return strtr(rtrim(base64_encode($string), '='), '+/', '-_');
        }
 
        /**
         * Helper function to display the current state values
         */
        function debugState($message = NULL)
        {
            if ($message != NULL)
            {
                echo "<pre>$message</pre>";
            }
 
            echo "<pre>passthroughState1 = $this->passthroughState1</pre>";
            echo "<pre>passthroughState2 = $this->passthroughState2</pre>";
            echo "<pre>code = $this->code</pre>";
            echo "<pre>token = $this->token</pre>";
            echo "<pre>refreshToken = $this->refreshToken</pre>";
            echo "<pre>instanceURL = $this->instanceURL</pre>";
            echo "<pre>redirectURI = $this->redirect_uri</pre>";
            echo "<pre>userId = $this->userId</pre>";
            echo "<pre>error = $this->error</pre>";
            echo "<pre>errorDescription = $this->errorDescription</pre>";
            echo "<pre>codeVerifier = $this->codeVerifier</pre>";
        }
    }
 
    // If we have not yet initialised state, are resetting or are Authenticating then Initialise State
    // and store in a session variable.
    if ($_SESSION['state'] == NULL || $_POST["reset"] || $_POST["authenticate"])
    {
        $_SESSION['state'] = new State('ippy', 'dippy');
    }
 
    $state = $_SESSION['state'];
 
    // Attempt to load the state from the page request
    $state->loadStateFromRequest();
 
    // if an error is present, render the error
    if ($state->error != NULL)
    {
        renderError();      
    }
 
    // Determine the form action
    if ($_POST["authenticate"]) // Authenticate button clicked
    {
        doOAUTH();  
    }
    else if ($_POST["login_via_code"])  // Login via Authentication Code button clicked
    {
        if (!loginViaAuthenticationCode())
        {
            renderError();
            return;
        }
 
        renderPage();
    }
    else if ($_POST["login_via_refresh_token"]) // Login via Refresh Token button clicked
    {
        if (!loginViaRefreshToken())
        {
            renderError();
            return;
        }
 
        renderPage();
    }
    else if ($_POST["get_user"])    // Get User button clicked
    {
        // Get the user data from Salesforce
        $userDataHTML = getUserData();
 
        // Render the page passing in the user data
        renderPage($userDataHTML);
    }
    else    // Otherwise render the page
    {
        renderPage();
    }
 
    // Render the Page
    function renderPage($userDataHTML = NULL)
    {
        $state = $_SESSION['state'];
 
        echo "<!DOCTYPE html>";
?>
        <html>
            <head>
                <title>SFDC - OAuth 2.0 Web Server Authentication Flow</title>
                <meta charset="UTF-8">
            </head>
 
            <body>
                <h1>SFDC - OAuth 2.0 Web Server Authentication Flow</h1>
<?php
                // Show the current state values
                $state->debugState();
 
                // If we have some user data to display then do so
                if ($userDataHTML)
                {
                    echo $userDataHTML;
                }
?>
                <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">
                    <input type="submit" name="reset" value="Reset" />
                    <input type="submit" name="authenticate" value="Authenticate" /> 
                    <input type="submit" name="login_via_code" value="Login via JWT Code" />
                   <!-- <input type="submit" name="login_via_refresh_token" value="Login via Refresh Token" />-->
                    <input type="submit" name="get_user" value="Get User" />
                </form>
 
            </body>
        </html>
<?php
    }
 
    /**
     * Redirect page to Salesforce to authenticate
     */
    function doOAUTH()
    {
        $state = $_SESSION['state'];
 
        // Set the Authentication URL
        // Note we pass in the code challenge
        //Cambiando HREF para Communitites:
        //$href = "https://login.salesforce.com/services/oauth2/authorize?response_type=code" . 
        //        "&client_id=" . getClientId() . 
        //        "&redirect_uri=" . getCallBackURL() . 
        //        "&scope=api refresh_token" . 
        //        "&prompt=consent" . 
        //        "&code_challenge=" . $state->generateCodeChallenge() .
        //        "&state=" . $state->serializeStateString();
        //
        $href = "https://sdodemo-main-15b0fc33c9c.force.com/Carrefour/services/oauth2/authorize?response_type=code" . 
                "&client_id=" . getClientId() . 
                "&redirect_uri=" . getCallBackURL() . 
                "&scope=api refresh_token" . 
                "&prompt=consent" . 
                "&code_challenge=" . $state->generateCodeChallenge() .
                "&state=" . $state->serializeStateString();
        // Wipe out arbitary state values to demonstrate passing additional state to salesforce and back
        $state->passthroughState1 = NULL;
        $state->passthroughState2 = NULL;
 
        // Perform the redirect
        header("location: $href");
    }

 
    /**
     * Login via an Authentication Code
     */
    function loginViaAuthenticationCode()
    {
        $state = $_SESSION['state'];
 
        // Create the Field array to pass to the post request
        // Note we pass in the code verifier and the authentication code
        //$fields = array('grant_type' => 'authorization_code', 
        //                'client_id' => getClientId(),
        //                'client_secret' => getClientSecret(),
        //                'redirect_uri' => getCallBackURL(),
        //                'code_verifier' => $state->generateCodeVerifier(),
        //                'code' => $state->code,
        //                );
         
        // perform the login to Salesforce
        return doLogin($fields, false);
    }
 
    /**
     * Login via a Refresh Token
     */
  /*  function loginViaRefreshToken()
    {
        $state = $_SESSION['state'];
 
        // Create the Field array to pass to the post request
        // Note we pass in the refresh token
        $fields = array('grant_type' => 'refresh_token', 
                        'client_id' => getClientId(),
                        'client_secret' => getClientSecret(),
                        'redirect_uri' => getCallBackURL(),
                        'refresh_token' => $state->refreshToken,
                        );
 
        // perform the login to Salesforce
        return doLogin($fields, true);
    }
 */
    /**
     * Login to Salesforce to get a Session Token using CURL
     */
    function doLogin($fields, $isViaRefreshToken)
    {
        $state = $_SESSION['state'];
 
        // Set the POST url to call
        // Probando para comunidades:
        //$postURL = 'https://login.salesforce.com/services/oauth2/token';
        $postURL = 'https://sdodemo-main-15b0fc33c9c.force.com/Carrefour/services/oauth2/token';
        // Header options
        $headerOpts = array('Content-type: application/x-www-form-urlencoded');
 
        // Create the params for the POST request from the supplied fields  
       define('LOGIN_BASE_URL', 'https://sdodemo-main-15b0fc33c9c.force.com/Carrefour');
    /**
     * Añadido para la autenticación con JWT
     */
        //Json Header
        $h = array(
            "alg" => "RS256"    
        );

        $jsonH = json_encode(($h)); 
        $header = base64_encode($jsonH); 

        //Create JSon Claim/Payload
        $c = array(
            "iss" => getClientId(), 
            "sub" => "juanperez.salesforce2@gmail.com", 
            "aud" => getClientSecret(), 
            "exp" => strval(time() + (5 * 60))
        );

        $jsonC = (json_encode($c)); 
        $payload = base64_encode($jsonC);

        //Sign the resulting string using SHA256 with RSA
        //$s = hash_hmac('sha256', $header.'.'.$payload, getClientSecret());
        //$secret = base64_encode($s);

        //########################


// LOAD YOUR PRIVATE KEY FROM A FILE - BE CAREFUL TO PROTECT IT USING
// FILE PERMISSIONS!
    $private_key = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,AA38898124E5A7ED

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
-----END RSA PRIVATE KEY-----
EOD;

        // This is where openssl_sign will put the signature
        $s = "";

        // SHA256 in this context is actually RSA with SHA256
        $algo = "SHA256";

        // Sign the header and payload
        openssl_sign($header.'.'.$payload, $s, $private_key, $algo);

        // Base64 encode the result
        $secret = base64_encode($s);


        //#############################

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

         $resultArray = json_decode($token_request_body, true);
        
        echo $token_request_body;
        // Extract the user Id
        if ($resultArray["id"] != null)
        {
            $trailingSlashPos = strrpos($resultArray["id"], '/');
 
            $state->userId = substr($resultArray["id"], $trailingSlashPos + 1);
        }
 
        // verify the signature
        $baseString = $resultArray["id"] . $resultArray["issued_at"];
        $signature = base64_encode(hash_hmac('SHA256', $baseString, getClientSecret(), true));
 
        if ($signature != $resultArray["signature"])
        {
            $state->error = 'Invalid Signature';
            $state->errorDescription = 'Failed to verify OAUTH signature.';
 
            return false;
        }
 
        // Debug that we've logged in via the appropriate method
        echo "<pre>Logged in " . ($isViaRefreshToken ? "via refresh token" : "via authorisation code") . "</pre>";
 
        return true;
    }
 
    /**
     * Get User Data from Salesforce using CURL
     */
    function getUserData()
    {
        $state = $_SESSION['state'];
 
        // Set our GET request URL
        $getURL = $state->instanceURL . '/services/data/v20.0/sobjects/User/' . $state->userId . '?fields=Name,Email,ContactId,contact.name,contact.number_of_friends__c,contact.Facebook_picture__c';
 
        // Header options
        $headerOpts = array('Authorization: Bearer ' . $state->token);
 
        // Open connection
        $ch = curl_init();
 
        // Set the url and header options
        curl_setopt($ch, CURLOPT_URL, $getURL);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headerOpts);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
 
        // Execute GET
        $result = curl_exec($ch);
 
        // Close connection
        curl_close($ch);
 
        // Get the results
        $typeString = gettype($result);
        $resultArray = json_decode($result, true);
 
        // Return them as an html String
        $rtnString = '<hr><h2>User Data</h2>';
 
        foreach($resultArray as $key=>$value) 
        { 
            $rtnString .= "<pre>$key=$value</pre>";
        }

        $rtnString .= " " . $result;
 
        return $rtnString;
    }
 
    /**
     * Helper function to render an Error
     */
    function renderError()
    {
        $state = $_SESSION['state'];
 
        echo '<div class="error"><span class="error_msg">' . $state->error . '</span> <span class="error_desc">' . $state->errorDescription . '</span></div>';
    }
 
    /**
     * Get the hard coded Client Id for the Conected Application
     */
    function getClientId()
    {
        return "3MVG9i1HRpGLXp.rWT8Mzhvq8DKCXYYhpZFtVygLxLKO73NSup_szrPEBXgYnSpVBfN.NVcNmV1e4dfhATTrt";
    }
 
    /**
     * Get the hard coded Client Secret for the Conected Application
     */
    function getClientSecret()
    {
        return "560008810877349762";
    }
 
    /**
     * Get the Call back URL (the current php script)
     */
    function getCallBackURL()
    {
        $callbackURL = ($_SERVER['HTTPS'] == NULL || $_SERVER['HTTPS'] == false ? "http://" : "https://") .
            $_SERVER['SERVER_NAME']  . $_SERVER['PHP_SELF'];
 
        return $callbackURL;
    }
?>
