Usage example

```php
<?php
    // initialize class
    require_once("pvpgnhash.class.php");

    $pass = "12345";
    $hash = pvpgn_hash::get_hash($pass);

    // print 460e0af6c1828a93fe887cbe103d6ca6ab97a0e4
    echo $hash;
?>
```

```php
<?php
    // initialize class
    require_once("bnetsrp3.class.php");

    $username = 'username';
    $password = 'password';
    $salt = BnetSRP3::rndsalt(); // random salt
	
	// print something like this: 
	//  841105F99D43ACAC0AB5705E2CA1DD09DEBD806D988A1659BD78CF7394993D8F
    echo BnetSRP3::getVerifier($username, $password, $salt);
?>
```