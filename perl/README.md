Usage example

```perl
#!/usr/bin/perl
do 'pvpgn_hash.pl';

$pass = '12345';
$hash = pvpgn_hash($pass);

# print 460e0af6c1828a93fe887cbe103d6ca6ab97a0e4
print $hash;
```
