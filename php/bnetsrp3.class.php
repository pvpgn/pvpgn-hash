<?php
// Calculates Warcraft 3 Battle.Net & pvpgn 1.99.x SRP hash (verifier)
// Authors: basman, harpywar
// (it's required php_gmp extension http://www.php.net/manual/en/book.gmp.php)
// 
final class BnetSRP3
{
	const g = '2F';
	const N = 'F8FF1A8B619918032186B68CA092B5557E976C78C73212D91216F6658523C787';
	
	public static function getVerifier($username, $password, $salt = null)
	{
		$salt_bytes = self::hex2bin($salt); 
		
		$gmp_g = gmp_init(self::g, 16);
		$gmp_N = gmp_init(self::N, 16);

		$x = self::hexrev(sha1( $salt_bytes . self::hex2bin(sha1( strtoupper($username) . ':' . strtoupper($password) )) ));
		
		$gmp_x = gmp_init($x, 16);
		$gmp_v = gmp_powm($gmp_g, $gmp_x, $gmp_N);
		
		$verifier = self::hexrev( gmp_strval($gmp_v, 16) );
		return strtoupper($verifier);
	}
	
	// convert hex to binary
	private static function hex2bin($str)
	{
		return pack('H*', $str);
	}

	// reverse hex string
	private static function hexrev($str)
	{
		if ( strlen($str) % 2 !== 0 )
			$str = "0" . $str;

		$new_str = "";
		for ($i = 0; $i < strlen($str); $i += 2)
			$new_str .= strrev( substr($str, $i, 2) );

		return strrev($new_str);
	}
	
	// random 256-bit hex string
	public static function rndsalt()
	{
		$random_salt = "";
		if(function_exists('openssl_random_pseudo_bytes'))
		{
			$strong = false;
			$random_salt = openssl_random_pseudo_bytes(32, $strong);
			if($random_salt !== FALSE && $strong)
			{
				return strtoupper( bin2hex($random_salt) );
			}
		}
		
		$random_salt = hash('sha256', mt_rand(0,100) . mt_rand(0,100) . mt_rand(0,100) . mt_rand(0,100));
		return strtoupper($random_salt);
	}
}