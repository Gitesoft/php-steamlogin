<?php


namespace Gitesoft\PhpSteamSessionLogin {

    require_once "lib/Math/BigInteger.php";
    require_once "lib/Crypt/RSA.php";

    class SteamLogin
    {
        const USER_AGENT = "Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.7.12) Gecko/20050915 Firefox/1.0.7";
        const COOKIE_PATH = '../storage/framework/bot_cookies/%d.cookie';

        public $config;

        private $cookiePath = '';

        private $accountdata = [];

        /**
         * SteamLogin constructor.
         * @param $config
         */
        public function __construct(array $config)
        {
            if (
                empty($config['ACCOUNT_USER']) ||
                empty($config['ACCOUNT_PASS']) ||
                empty($config['STEAM_64_ID'])
            )  {
                throw new \Exception('Corrupted Bot Config. Please make sure config contains "ACCOUNT_USER, ACCOUNT_PASS, STEAM_64_ID" keys with correct values.');
            }

            $this->config = $config;
            $this->cookiePath = sprintf(self::COOKIE_PATH, $this->config['STEAM_64_ID']);
        }

        public function isLoggedIn()
        {
            $cookieString = $this->getCookie();
            if (is_null($cookieString)) {
                return false;
            }
            $this->checkIsCookieValid($cookieString);
        }

        /**
         * @todo Implement cookie check method
         * @param $cookieString
         * @return bool
         */
        protected function checkIsCookieValid($cookieString) {
            dd($cookieString);
            return true;
        }

        /**
         * @return null|string
         */
        public function getCookie()
        {
            if (!file_exists($this->cookiePath)) {
                return null;
            }

            return file_get_contents($this->cookiePath);
        }

        /**
         * @param string $authCode
         * @param string $twoFactorCode
         * @return array|mixed
         */
        public function login($authCode = '', $twoFactorCode = '')
        {
            $doLogin = $this->getRSAkey();
            if ( !($doLogin->publickey_mod && $doLogin->publickey_exp && $doLogin->timestamp) ) {
                throw new \Exception('Bad RSA!');
            }

            $rsa = new \Crypt_RSA();
            $key = array('modulus' => new \Math_BigInteger($doLogin->publickey_mod, 16), 'publicExponent' => new \Math_BigInteger($doLogin->publickey_exp, 16));
            $rsa->loadKey($key, CRYPT_RSA_PUBLIC_FORMAT_RAW);
            $rsa->setPublicKey($key);
            $rsa->setEncryptionMode(CRYPT_RSA_ENCRYPTION_PKCS1);
            $enc_password = base64_encode($rsa->encrypt($this->config['ACCOUNT_PASS']));

            $login = $this->request('POST', 'https://steamcommunity.com/login/dologin/', array(
                'password' => $enc_password,
                'username' => $this->config['ACCOUNT_USER'],
                'twofactorcode' => $twoFactorCode,
                'emailauth' => $authCode,
                'loginfriendlyname' => '',
                'capatcha_text' => '',
                'emailsteamid' => ((isset($this->accountdata['steamid'])) ? $this->accountdata['steamid'] : ''),
                'rsatimestamp' => $doLogin->timestamp,
                'remember_login' => 'true',
                'donotcache' => time(),
            ));
            $login = json_decode($login);
            if ($login->success == false) {

                if (isset($login->emailsteamid) && $login->emailauth_needed == true) {
                    if ($authCode == '') {
                        throw new \Exception('Please enter AUTHCODE available in your e-mail inbox (domain: ' . $login->emaildomain . ').');
                    } else {
                        throw new \Exception('You enter bad authcode!');
                    }

                } else if ($login->requires_twofactor == true) {
                    if ($twoFactorCode == '') {
                        throw new \Exception('Please enter twofactorcode (mobile auth).');
                    } else {
                        throw new \Exception('You enter bad twofactorcode!');
                    }
                }

                throw new \Exception("Unsuccessful Login Attempt!");
            }
            preg_match_all('#g_sessionID\\s\=\\s\"(.*?)\"\;#si', $this->view('http://steamcommunity.com/id'), $matches);

            $cookie = file_get_contents($this->cookiePath);

            return array(
                'steamid' => $login->transfer_parameters->steamid,
                'sessionId' => $matches[1][0],
                'cookies' => $this->cookiejarToString($cookie),
            );

        }

        /**
         * @param $url
         * @return mixed
         */
        public function view($url)
        {
            return $this->request('POST', $url);
        }

        /**
         * @param $type
         * @param $url
         * @param array $data
         * @return mixed
         */
        private function request($type, $url, $data = array())
        {
            $c = curl_init();
            curl_setopt($c, CURLOPT_HEADER, false);
            curl_setopt($c, CURLOPT_NOBODY, false);
            curl_setopt($c, CURLOPT_URL, $url);
            curl_setopt($c, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($c, CURLOPT_USERAGENT, self::USER_AGENT);
            curl_setopt($c, CURLOPT_COOKIESESSION, false);
            curl_setopt($c, CURLOPT_COOKIEJAR, $this->cookiePath);
            curl_setopt($c, CURLOPT_COOKIEFILE, $this->cookiePath);
            curl_setopt($c, CURLOPT_POST, 1);
            curl_setopt($c, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($c, CURLOPT_REFERER, $_SERVER['REQUEST_URI']);
            curl_setopt($c, CURLOPT_SSL_VERIFYPEER, 0);
            curl_setopt($c, CURLOPT_FOLLOWLOCATION, 1);
            curl_setopt($c, CURLOPT_CUSTOMREQUEST, strtoupper($type));
            $return = curl_exec($c);
            curl_close($c);
            return $return;
        }

        /**
         * @return mixed
         */
        private function getRSAkey()
        {
            return json_decode($this->request('POST', 'https://steamcommunity.com/login/getrsakey/', array(
                'username' => $this->config['ACCOUNT_USER'],
                'donotcache' => time(),
            )));
        }

        /**
         * @param $string
         * @return string
         */
        private function cookiejarToString($string)
        {
            $cookieString = '';
            $lines = explode("\n", $string);
            foreach ($lines as $line) {
                if (isset($line[0]) && substr_count($line, "\t") == 6) {
                    $tokens = explode("\t", $line);
                    $tokens = array_map('trim', $tokens);
                    $cookieString .= $tokens[5] . '=' . $tokens[6] . '; ';
                }
            }
            return $cookieString;
        }

    }
}