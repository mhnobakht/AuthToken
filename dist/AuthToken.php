<?php declare(strict_types=1); // strict mode

class AuthToken {
    // declare the information
    private static $domain = 'localhost';
    private static $salt   = "54373b6ccb934793475ef0f2ad7580bc6e04bdba";


    // check the session
    public static function checkSession() {
        try {
            if(session_id() == '') {
                if(!isset($_SESSION)){  
                    session_set_cookie_params(0, '/', self::$domain, true, true);
                    ini_set( 'session.cookie_httponly', '1' );
                    @session_regenerate_id(true);  
                    ob_start();  
                    session_start();
                }  
            }
        }catch(Exception $e){
            die("You have error in checkSession() --> ".(string)$e);
        }
    }
    // get client ip address
    public static function getIpAddress() : string {
        try{
            $ipaddress = '';
            if (isset($_SERVER['HTTP_CLIENT_IP']))
                $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
            else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
                $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
            else if(isset($_SERVER['HTTP_X_FORWARDED']))
                $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
            else if(isset($_SERVER['HTTP_X_CLUSTER_CLIENT_IP']))
                $ipaddress = $_SERVER['HTTP_X_CLUSTER_CLIENT_IP'];
            else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
                $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
            else if(isset($_SERVER['HTTP_FORWARDED']))
                $ipaddress = $_SERVER['HTTP_FORWARDED'];
            else if(isset($_SERVER['REMOTE_ADDR']))
                $ipaddress = $_SERVER['REMOTE_ADDR'];
            else
                $ipaddress = 'UNKNOWN';
            return $ipaddress;
        }catch(Exception $e) {
            die("You have error in getIpAddress() --> ".(string)$e);
        }
    }
    // sanitize the inputs
    public static function validation(string $data) : string {
        try{
            $data = trim($data);
            $data = stripslashes($data);
            $data = htmlspecialchars($data);
            $data = filter_var($data, FILTER_SANITIZE_STRING);
            return $data;
        }catch(Exception $e) {
            die("You have error in validation() --> ".(string)$e);
        }
    }
    // Make a Token
    public static function token(string $username=NULL) : string {
        try {
            self::checkSession();
            $ip = self::validation(self::getIpAddress());
            $userAgent = self::validation($_SERVER['HTTP_USER_AGENT']);
            $salt = self::$salt;
            if ($username != NULL) {
                $username = self::validation($username);
            }elseif(isset($_SESSION['username']) && $_SESSION['username'] != NULL && !empty($_SESSION['username'])){
                $username = self::validation($_SESSION['username']);
            } else {
                $username = "Null_Username_Set_By_Default";
            }
            $token = md5($ip.$userAgent.$username.$salt);
            return $token;
        }catch(Exception $e) {
            die("You have error in generate() --> ".(string)$e);
        }
    }
    // generate a token and set it to sessions
    public static function generate(string $username=NULL) {
        try {
            $token = self::token($username);
            $_SESSION['AuthToken_Generated'] = $token;
            session_write_close();
        }catch(Exception $e) {
            die("You have error in generate() --> ".(string)$e);
        }
    } 
    // check the token and return true or false
    public static function check(string $username=NULL) : bool {
        try{
            self::checkSession();
            if(isset($_SESSION['AuthToken_Generated']) && $_SESSION['AuthToken_Generated'] != NULL && !empty($_SESSION['AuthToken_Generated'])){
                $token = self::token($username);
                if($token === $_SESSION['AuthToken_Generated']) {
                    return true;
                }else{
                    return false;
                }
            }else {
                return false;
            }
        }catch(Exception $e) {
            die("You have error in check() --> ".(string)$e);
        }
    }
    // delete the token session
    public static function delete() : void {
        try {
            self::checkSession();
            if(isset($_SESSION['AuthToken_Generated'])) {
                $_SESSION['AuthToken_Generated'] = NULL;
                unset($_SESSION['AuthToken_Generated']);
                session_write_close();
            }
        }catch(Exception $e) {
            die("You have error in delete() --> ".(string)$e);
        }
    }
    
}